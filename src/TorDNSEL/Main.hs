{-# LANGUAGE PatternGuards, ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-missing-fields #-}

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
-- See <https://tor.eff.org/svn/trunk/doc/contrib/torel-design.txt> for
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
  , checkStateDirectory
  , liftMb
  , b
  , chroot
  ) where

import Control.Concurrent (forkIO, threadDelay, myThreadId)
import qualified Control.Exception as E
import Control.Monad (when, unless, liftM, forM_)
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (toLower)
import Data.Dynamic (fromDynamic)
import qualified Data.Map as M
import Data.Map ((!))
import Data.Maybe (isJust)
import System.Environment (getArgs)
import System.IO
  ( openFile, hPutStr, hPutStrLn, hFlush, hClose, stderr
  , IOMode(WriteMode, ReadWriteMode) )
import Network.BSD (getProtocolNumber, ProtocolNumber)
import Network.Socket
  ( socket, sClose, connect, bindSocket, setSocketOption, socketToHandle
  , SockAddr, Family(AF_INET), SocketType(Datagram, Stream)
  , SocketOption(ReuseAddr) )

import System.Exit (ExitCode(ExitSuccess))
import System.Directory (setCurrentDirectory, createDirectoryIfMissing)
import System.Posix.IO
  ( openFd, closeFd, stdInput, stdOutput, stdError, OpenMode(ReadWrite)
  , defaultFileFlags, dupTo )
import System.Posix.Process
  (forkProcess, createSession, exitImmediately, getProcessID)
import System.Posix.Signals
  (installHandler, Handler(Ignore, Catch), sigHUP, sigPIPE, sigINT, sigTERM)

import System.Posix.Error (throwErrnoPathIfMinus1_)
import System.Posix.Files
  (getFileStatus, fileOwner, fileMode, setFileMode, setOwnerAndGroup)
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
import TorDNSEL.Random
import TorDNSEL.Statistics
import TorDNSEL.Util

-- | The main entry point for the server. This handles parsing config options,
-- various daemon operations, forking the network state handler, Tor controller,
-- and exit test threads, and starting the DNS server.
main :: IO ()
main = do
  conf <- exitLeft . fillInConfig =<< parseConfig =<< exitLeft . parseConfigArgs
                                                  =<< getArgs

  dnsSockAddr     <- conf <! "dnslistenaddress"#
  controlSockAddr <- conf <! "torcontroladdress"#
  runAsDaemon     <- conf <! "runasdaemon"#
  address         <- exitLeft . parse `liftMb` b "address"# `M.lookup` conf

  let [user,group,newRoot,pidFile,dataDir,password] = map (`M.lookup` conf)
        [ b "user"#, b "group"#, b "changerootdirectory"#, b "pidfile"#
        , b "tordatadirectory"#, b "torcontrolpassword"# ]

  euid <- getEffectiveUserID
  when (any isJust [user, group, newRoot] && euid /= 0) $
    failMsg "You must be root to drop privileges or chroot."

  ids <- getIDs user group

  stateDir <- conf <! "statedirectory"#
  checkStateDirectory (fst ids) newRoot stateDir

  tcp <- getProtocolNumber "tcp"

  concTests <- conf <! "concurrentexittests"#
  testConf <- do
    if concTests <= 0 then return Nothing else do

    socksSockAddr <- conf <! "torsocksaddress"#
    (testListenAddr,testListenPorts) <- conf <! "testlistenaddress"#
    (testDestAddr,testDestPorts) <- conf <! "testdestinationaddress"#

    testSockets <- bindListeningSockets tcp testListenAddr testListenPorts

    random <- exitLeft =<< openRandomDevice
    seedPRNG random

    return . Just $ \c -> c
      { etConcTests   = concTests
      , etSocksServer = socksSockAddr
      , etListenSocks = testSockets
      , etTestAddr    = testDestAddr
      , etTestPorts   = testDestPorts
      , etRandom      = random }

  authSecret <- fmap encodeBase16 `fmap`
    case (dataDir, password) of
      (Just dir,_)    ->
        Just `fmap` B.readFile (B.unpack dir ++ "/control_auth_cookie")
      (_,Just passwd) -> return (Just passwd)
      _               -> return Nothing

  pidHandle <- flip openFile WriteMode . B.unpack `liftMb` pidFile

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

    topLevelThread <- myThreadId
    forM_ [sigINT, sigTERM] $ \signal ->
      flip (installHandler signal) Nothing . Catch $ do
        unlinkStatsSocket stateDir
        E.throwTo topLevelThread (E.ExitException ExitSuccess)

    statsHandle <- openStatsListener stateDir

    let authLabels  = toLabels $ conf ! b "authoritativezone"#
        authZone    = DomainName authLabels
        revAuthZone = DomainName $ reverse authLabels
        rName       = DomainName . toLabels $ conf ! b "soarname"#
        myName      = DomainName . toLabels $ conf ! b "domainname"#
        dnsConf = DNSConfig
          { dnsAuthZone = revAuthZone
          , dnsMyName   = myName
          , dnsSOA      = SOA authZone ttl myName rName 0 ttl ttl ttl ttl
          , dnsNS       = NS authZone ttl myName
          , dnsA        = A authZone ttl `fmap` address
          , dnsStats    = incrementResponses statsHandle }

    net <- case testConf of
      Just testConf' -> do
        exitTestChan <- newExitTestChan
        net <- newNetwork $ Just (exitTestChan, stateDir)
        startExitTests . testConf' $ ExitTestConfig
          { etChan    = exitTestChan
          , etNetwork = net
          , etTcp     = tcp }
        return net
      _ ->
        newNetwork Nothing

    let controller = torController net controlSockAddr authSecret tcp
    installHandler sigPIPE Ignore Nothing
    forkIO . forever . E.catchJust connExceptions controller $ \e -> do
      -- XXX this should be logged
      unless runAsDaemon $ do
        hPutStrLn stderr (showConnException e) >> hFlush stderr
      threadDelay (5 * 10^6)

    -- start the DNS server
    forever . E.catchJust E.ioErrors
      (runServer sock (incrementBytes statsHandle) (dnsHandler dnsConf net)) $
        \e -> do
          -- XXX this should be logged
          unless runAsDaemon $
            hPutStrLn stderr (show e) >> hFlush stderr
          threadDelay (5 * 10^6)
  where
    connExceptions e@(E.IOException _)                = Just e
    connExceptions e@(E.DynException e')
      | Just (_ :: TorControlError) <- fromDynamic e' = Just e
    connExceptions _                                  = Nothing

    showConnException (E.IOException e) = show e
    showConnException (E.DynException e)
      | Just (e' :: TorControlError) <- fromDynamic e
      = "Tor control error: " ++ show e'
    showConnException _ = "bug: unknown exception type"

    toLabels = map Label . reverse . dropWhile B.null . reverse .
      B.split '.' . B.map toLower

    conf <! addr = exitLeft . parse $ conf ! b addr

    failMsg = exitLeft . Left

-- | Connect to Tor using the controller interface. Initialize our network state
-- with all the routers Tor knows about and register asynchronous events to
-- notify us and update the state when updated router info comes in.
torController
  :: Network -> SockAddr -> Maybe ByteString -> ProtocolNumber -> IO ()
torController net control authSecret tcp = do
  sock <- E.bracketOnError (socket AF_INET Stream tcp) sClose $ \sock ->
            connect sock control >> return sock
  handle <- socketToHandle sock ReadWriteMode
  withConnection handle $ \conn -> do
    authenticate authSecret conn
    let newNS = newNetworkStatus (updateNetworkStatus net)
        newDesc = newDescriptors (updateDescriptors net) conn
    registerEventHandlers [newNS, newDesc] conn
    fetchNetworkStatus conn >>= updateNetworkStatus net
    fetchAllDescriptors conn >>= updateDescriptors net
    setFetchUselessDescriptors conn
    waitForConnection conn

-- | Set up the state directory with proper ownership and permissions.
checkStateDirectory :: Maybe UserID -> Maybe ByteString -> FilePath -> IO ()
checkStateDirectory uid newRoot stateDir = do
  createDirectoryIfMissing True stateDir'
  desiredUID <- maybe getEffectiveUserID return uid
  st <- getFileStatus stateDir'
  when (fileOwner st /= desiredUID) $
    setOwnerAndGroup stateDir' desiredUID (-1)
  when (fileMode st .&. 0o700 /= 0o700) $
    setFileMode stateDir' (fileMode st .|. 0o700)
  where stateDir' = maybe "" (B.unpack . flip B.snoc '/') newRoot ++ stateDir

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

-- | An alias for packAddress.
b :: Addr# -> ByteString
b = B.packAddress

foreign import ccall unsafe "chroot" chroot :: CString -> IO CInt
