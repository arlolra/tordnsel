{-# LANGUAGE PatternGuards, ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Main
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, STM, extended exceptions,
--                             pattern guards, FFI, GHC primitives)
--
-- Implements a DNSBL-style interface providing information about whether a
-- client for a network service is likely connecting through a Tor exit node.
--
-- See <http://tor.eff.org/svn/trunk/doc/contrib/torbl-design.txt> for
-- details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Main (
  -- * Top level functionality
    main
  , torController

  -- * Daemon operations
  , getIDs
  , dropPrivileges
  , changeRootDirectory
  , daemonize

  -- * Helpers
  , liftMb
  , b
  , chroot
  ) where

import Control.Concurrent (forkIO, threadDelay)
import qualified Control.Exception as E
import Control.Monad (when, unless, liftM)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (toLower)
import Data.Dynamic (fromDynamic)
import qualified Data.Map as M
import Data.Map ((!))
import Data.Maybe (isJust)
import System.Environment (getArgs)
import System.IO
  ( openFile, hPutStr, hPutStrLn, hClose, stderr
  , IOMode(WriteMode, ReadWriteMode) )
import Network.BSD (getProtocolNumber, ProtocolNumber)
import Network.Socket
  ( socket, connect, bindSocket, setSocketOption, socketToHandle, SockAddr
  , Family(AF_INET), SocketType(Datagram, Stream), SocketOption(ReuseAddr) )

import System.Exit (ExitCode(ExitSuccess))
import System.Directory (setCurrentDirectory)
import System.Posix.Files (setFileCreationMask)
import System.Posix.IO
  ( openFd, closeFd, stdInput, stdOutput, stdError, OpenMode(ReadWrite)
  , defaultFileFlags, dupTo )
import System.Posix.Process
  (forkProcess, createSession, exitImmediately, getProcessID)
import System.Posix.Signals (installHandler, Handler(Ignore), sigHUP)

import System.Posix.Error (throwErrnoPathIfMinus1_)
import System.Posix.Types (UserID, GroupID)
import System.Posix.User
  ( getEffectiveUserID, UserEntry(userID), GroupEntry(groupID)
  , getUserEntryForName, getGroupEntryForName, setUserID, setGroupID )
import Foreign.C (CString, CInt)

import GHC.Prim (Addr#)

import TorDNSEL.Config
import TorDNSEL.Control
import TorDNSEL.DNS
import TorDNSEL.DNS.Handler
import TorDNSEL.NetworkState
import TorDNSEL.Util

-- | The main entry point for the server. This handles parsing config options,
-- various daemon operations, forking the network state handler and Tor
-- controller, and starting the DNS server.
main :: IO ()
main = do
  config <- fillInConfig =<< parseConfig =<< parseConfigArgs =<< getArgs
  dnsSockAddr     <- parse $ config ! b "dnslistenaddress"#
  controlSockAddr <- parse $ config ! b "torcontroladdress"#
  runAsDaemon     <- parse $ config ! b "runasdaemon"#

  let authZone = toAuthZone $ config ! b "authoritativezone"#
      [user,group,newRoot,pidFile,dataDir,password] = map (`M.lookup` config)
        [ b "user"#, b "group"#, b "changerootdirectory"#, b "pidfile"#
        , b "tordatadirectory"#, b "torcontrolpassword"# ]

  euid <- getEffectiveUserID
  when (any isJust [user, group, newRoot] && euid /= 0) $
    fail "You must be root to drop privileges or chroot."

  authSecret <- fmap encodeBase16 `fmap`
    case (dataDir, password) of
      (Just dir,_)    ->
        Just `fmap` B.readFile (B.unpack dir ++ "/control_auth_cookie")
      (_,Just passwd) -> return (Just passwd)
      _               -> return Nothing

  pidHandle <- flip openFile WriteMode . B.unpack `liftMb` pidFile
  ids <- getIDs user group
  tcp <- getProtocolNumber "tcp"

  sock <- socket AF_INET Datagram =<< getProtocolNumber "udp"
  setSocketOption sock ReuseAddr 1
  bindSocket sock dnsSockAddr

  -- We lose any other running threads when we 'forkProcess', so don't 'forkIO'
  -- before this point.
  (if runAsDaemon then daemonize else id) $ do

    whenJust pidHandle $ \handle -> do
      hPutStr handle . show =<< getProcessID
      hClose handle

    whenJust newRoot $ \dir -> do
      changeRootDirectory dir
      setCurrentDirectory "/"

    dropPrivileges ids

    netState <- newNetworkState
    let controller = torController netState controlSockAddr authSecret tcp
    forkIO . forever . E.catchJust connExceptions controller $ \e -> do
      -- XXX this should be logged
      unless runAsDaemon $
        hPutStrLn stderr (showConnException e)
      threadDelay (5 * 10^6)

    -- start the DNS server
    forever . E.catchJust E.ioErrors
      (runServer sock $ dnsHandler netState authZone) $ \e -> do
        -- XXX this should be logged
        unless runAsDaemon $
          hPutStrLn stderr (show e)
        threadDelay (5 * 10^6)
  where
    connExceptions :: E.Exception -> Maybe E.Exception
    connExceptions e@(E.IOException _)  = Just e
    connExceptions e@(E.DynException _) = Just e
    connExceptions _                    = Nothing

    showConnException :: E.Exception -> String
    showConnException (E.IOException e) = show e
    showConnException (E.DynException e)
      | Just (e' :: TorControlError) <- fromDynamic e
      = "Tor control error: " ++ show e'
    showConnException _ = "bug: unknown exception type"

    toAuthZone :: ByteString -> DomainName
    toAuthZone = DomainName . map Label . reverse . B.split '.' . B.map toLower

-- | Connect to Tor using the controller interface. Initialize our network state
-- with all the routers Tor knows about and register asynchronous events to
-- notify us and update the state when updated router info comes in.
torController
  :: NetworkState -> SockAddr -> Maybe ByteString -> ProtocolNumber -> IO ()
torController netState control authSecret tcp = do
  sock <- socket AF_INET Stream tcp
  connect sock control
  handle <- socketToHandle sock ReadWriteMode
  withConnection handle $ \conn -> do
    authenticate authSecret conn
    let newNS = newNetworkStatus (updateNetworkStatus netState)
        newDesc = newDescriptors (updateDescriptors netState) conn
    registerEventHandlers [newNS, newDesc] conn
    fetchNetworkStatus conn >>= updateNetworkStatus netState
    fetchAllDescriptors conn >>= updateDescriptors netState
    waitForConnection conn

-- | Lookup the UID and GID for a pair of user and group names.
getIDs
  :: Maybe ByteString -> Maybe ByteString -> IO (Maybe UserID, Maybe GroupID)
getIDs user group = do
  userEntry <- getUserEntryForName . B.unpack `liftMb` user
  groupEntry <- getGroupEntryForName . B.unpack `liftMb` group
  return (userID `fmap` userEntry, groupID `fmap` groupEntry)

-- | Drop privileges to the given UID\/GID pair.
dropPrivileges :: (Maybe UserID, Maybe GroupID) -> IO ()
dropPrivileges (uid,gid) = do
  whenJust gid setGroupID
  whenJust uid setUserID

-- | Call chroot(2) using the given directory path. Throws an 'IOError' if the
-- call fails.
changeRootDirectory :: ByteString -> IO ()
changeRootDirectory dir =
  B.useAsCString dir $ \s ->
    throwErrnoPathIfMinus1_ "changeRootDirectory" (B.unpack dir) (chroot s)

-- | Run an IO action as a daemon. This action doesn't return.
daemonize :: IO () -> IO ()
daemonize io = do
  forkProcess $ do
    createSession
    forkProcess $ do
      installHandler sigHUP Ignore Nothing
      setCurrentDirectory "/"
      setFileCreationMask 0
      mapM_ closeFd stdFds
      nullFd <- openFd "/dev/null" ReadWrite Nothing defaultFileFlags
      mapM_ (dupTo nullFd) stdFds
      closeFd nullFd
      io
    exitImmediately ExitSuccess
  exitImmediately ExitSuccess
  where stdFds = [stdInput, stdOutput, stdError]

-- | Lift a 'Maybe' into a monadic action.
liftMb :: Monad m => (a -> m b) -> Maybe a -> m (Maybe b)
liftMb f = maybe (return Nothing) (liftM Just . f)

infixr 8 `liftMb`

-- | An alias for 'B.packAddress'.
b :: Addr# -> ByteString
b = B.packAddress

foreign import ccall unsafe "chroot" chroot :: CString -> IO CInt
