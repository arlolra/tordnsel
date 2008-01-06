{-# LANGUAGE PatternGuards, ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-missing-fields
                -fno-warn-orphans #-}

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
  , exitWith
  , liftMb
  , b
  , chroot
  ) where

import qualified Control.Concurrent as C
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import qualified Control.Exception as E
import Control.Monad (when, unless, liftM, forM, forM_)
import Control.Monad.Fix (fix)
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Dynamic (fromDynamic)
import qualified Data.Map as M
import Data.Maybe (isJust)
import System.Environment (getArgs)
import System.IO
  ( openFile, hPutStr, hPutStrLn, hFlush, hClose, stderr
  , IOMode(WriteMode, ReadWriteMode) )
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
import System.Posix.Resource
  ( ResourceLimits(..), ResourceLimit(..), Resource(ResourceOpenFiles)
  , getResourceLimit, setResourceLimit )
import System.Posix.Types (UserID, GroupID)
import System.Posix.User
  ( getEffectiveUserID, UserEntry(userID), GroupEntry(groupID)
  , getUserEntryForName, getGroupEntryForName, setUserID, setGroupID )
import Foreign.C (CString, CInt, withCString)

import GHC.Prim (Addr##)

import TorDNSEL.Config
import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.TorControl
import TorDNSEL.Directory
import TorDNSEL.DNS
import TorDNSEL.DNS.Handler
import TorDNSEL.NetworkState
import TorDNSEL.Random
import TorDNSEL.Statistics
import TorDNSEL.Util

#include <sys/types.h>

#ifdef OPEN_MAX
import System.IO.Error (isPermissionError)
#endif

-- | Minimum limit on open file descriptors under which we can run.
minFileDesc :: ResourceLimit
minFileDesc = ResourceLimit 128

-- | Maximum limit on open file descriptors we can set with 'setResourceLimit'.
maxFileDesc :: ResourceLimit
maxFileDesc = ResourceLimit 4096

-- | The number of file descriptors the process might need for everything but
-- exit tests.
extraFileDesc :: Integer
extraFileDesc = 96

-- | The main entry point for the server. This handles parsing config options,
-- various daemon operations, forking the network state handler, Tor controller,
-- and exit test threads, and starting the DNS server.
main :: IO ()
main = do
  availableFileDesc <- setMaxOpenFiles minFileDesc maxFileDesc

  conf <- do
    conf <- exitLeft . parseConfigArgs =<< getArgs
    case b "configfile"## `M.lookup` conf of
      Just fp -> do
        file <- E.catchJust E.ioErrors (B.readFile $ B.unpack fp)
          (exitWith . cat "Opening config file failed: ")
        exitLeft $ makeConfig . M.union conf =<< parseConfigFile file
      Nothing -> exitLeft $ makeConfig conf

  euid <- getEffectiveUserID
  when (any (isJust . ($ conf)) [cfUser, cfGroup, cfChangeRootDirectory] &&
        euid /= 0) $
    exitWith ("You must be root to drop privileges or chroot." ++)

  ids <- getIDs (cfUser conf) (cfGroup conf)

  checkStateDirectory (fst ids) (cfChangeRootDirectory conf)
                      (cfStateDirectory conf)

  testConf <- flip liftMb (cfTestConfig conf) $ \testConf -> do
    testSocks <- forM (snd $ tcfTestListenAddress testConf) $ \port ->
      E.catchJust E.ioErrors
        (bindListeningSocket (fst $ tcfTestListenAddress testConf) port)
        (exitWith . cat "Binding listening socket to port " port " failed: ")

    random <- exitLeft =<< openRandomDevice
    seedPRNG random
    return ExitTestConfig
      { etConcTests   = (availableFileDesc - extraFileDesc) `div` 2
      , etSocksServer = cfTorSocksAddress conf
      , etListenSocks = testSocks
      , etTestAddr    = fst $ tcfTestDestinationAddress testConf
      , etTestPorts   = snd $ tcfTestDestinationAddress testConf
      , etRandom      = random }

  authSecret <- fmap encodeBase16 `fmap`
    case (cfTorDataDirectory conf, cfTorControlPassword conf) of
      (Just dir,_) ->
         E.catchJust E.ioErrors
           (Just `fmap` B.readFile (dir ++ "/control_auth_cookie"))
           (exitWith . cat "Opening control auth cookie failed: ")
      (_,Just passwd) -> return (Just passwd)
      _               -> return Nothing

  pidHandle <- E.catchJust E.ioErrors
                 (flip openFile WriteMode `liftMb` cfPIDFile conf)
                 (exitWith . cat "Opening PID file failed: ")

  sock <- E.handleJust E.ioErrors
          (exitWith . cat "Binding DNS socket failed: ") $ do
    sock <- socket AF_INET Datagram udpProtoNum
    setSocketOption sock ReuseAddr 1
    bindSocket sock $ cfDNSListenAddress conf
    return sock

  -- We lose any other running threads when we 'forkProcess', so don't 'forkIO'
  -- before this point.
  (if cfRunAsDaemon conf then daemonize else id) .
    withLinksDo (showException [showLinkException]) $ do

    whenJust pidHandle $ \handle -> do
      hPutStr handle . show =<< getProcessID
      hClose handle

    whenJust (cfChangeRootDirectory conf) $ \dir -> do
      changeRootDirectory dir
      setCurrentDirectory "/"

    dropPrivileges ids

    mainThread <- C.myThreadId
    forM_ [sigINT, sigTERM] $ \signal ->
      flip (installHandler signal) Nothing . Catch $ do
        unlinkStatsSocket $ cfStateDirectory conf
        E.throwTo mainThread (E.ExitException ExitSuccess)

    statsHandle <- openStatsListener $ cfStateDirectory conf

    let DomainName authLabels = cfAuthoritativeZone conf
        dnsConf = DNSConfig
          { dnsAuthZone = DomainName $ reverse authLabels
          , dnsMyName   = cfDomainName conf
          , dnsSOA      = SOA (cfAuthoritativeZone conf) ttl (cfDomainName conf)
                              (cfSOARName conf) 0 ttl ttl ttl ttl
          , dnsNS       = NS (cfAuthoritativeZone conf) ttl (cfDomainName conf)
          , dnsA        = A (cfAuthoritativeZone conf) ttl `fmap` cfAddress conf
          , dnsStats    = incrementResponses statsHandle }

    net <- case testConf of
      Just testConf' -> do
        exitTestChan <- newExitTestChan

        let acceptsPort = flip $ exitPolicyAccepts (etTestAddr testConf')
            allowsExit policy = any (acceptsPort policy) (etTestPorts testConf')

        net <- newNetwork $ Just (exitTestChan,cfStateDirectory conf,allowsExit)
        startExitTests $ testConf'
          { etChan    = exitTestChan
          , etNetwork = net }
        return net
      _ ->
        newNetwork Nothing

    let controller = torController net (cfTorControlAddress conf) authSecret
    installHandler sigPIPE Ignore Nothing
    forkIO $ do
      exitChan <- newChan
      setTrapExit (curry $ writeChan exitChan)
      forever $ do
        E.catchJust connExceptions (controller exitChan) $ \e -> do
          -- XXX this should be logged
          unless (cfRunAsDaemon conf) $
            hPutStrLn stderr (showConnException e) >> hFlush stderr
          C.threadDelay (5 * 10^6)

    -- start the DNS server
    forever . E.catchJust E.ioErrors
      (runServer sock (incrementBytes statsHandle) (dnsHandler dnsConf net)) $
        \e -> do
          -- XXX this should be logged
          unless (cfRunAsDaemon conf) $
            hPutStrLn stderr (show e) >> hFlush stderr
          C.threadDelay (5 * 10^6)
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

-- | Connect to Tor using the controller interface. Initialize our network state
-- with all the routers Tor knows about and register asynchronous events to
-- notify us and update the state when updated router info comes in.
torController :: Network -> SockAddr -> Maybe ByteString
              -> Chan (ThreadId, ExitReason) -> IO ()
torController net control authSecret exitChan = do
  handle <- E.bracketOnError (socket AF_INET Stream tcpProtoNum)
                             sClose $ \sock -> do
    connect sock control
    socketToHandle sock ReadWriteMode

  withConnection handle $ \conn -> do
    authenticate authSecret conn
    let newNS = networkStatusEvent (const $ updateNetworkStatus net)
        newDesc = newDescriptorsEvent (const $ updateDescriptors net) conn
    registerEventHandlers [newNS, newDesc] conn
    getNetworkStatus conn >>= updateNetworkStatus net . fst
    getAllDescriptors conn >>= updateDescriptors net . fst
    setConf fetchUselessDescriptors (Just True) conn

    fix $ \loop -> do
      (tid,reason) <- readChan exitChan
      if tid == connectionThread conn
        then whenJust reason E.throwIO
        else maybe loop (const $ exit reason) reason

-- | Set up the state directory with proper ownership and permissions.
checkStateDirectory :: Maybe UserID -> Maybe FilePath -> FilePath -> IO ()
checkStateDirectory uid newRoot stateDir =
  E.handleJust E.ioErrors
    (exitWith . cat "Preparing state directory failed: ") $ do
      createDirectoryIfMissing True stateDir'
      desiredUID <- maybe getEffectiveUserID return uid
      st <- getFileStatus stateDir'
      when (fileOwner st /= desiredUID) $
        setOwnerAndGroup stateDir' desiredUID (-1)
      when (fileMode st .&. 0o700 /= 0o700) $
        setFileMode stateDir' (fileMode st .|. 0o700)
  where stateDir' = maybe id ((++) . (++ "/")) newRoot stateDir

-- | Ensure that the current limit on open file descriptors is at least
-- @lowerLimit@ and at least the minimum of @cap@ and FD_SETSIZE. Return the
-- new current limit.
setMaxOpenFiles :: ResourceLimit -> ResourceLimit -> IO Integer
setMaxOpenFiles lowerLimit cap = do
  let fdSetSize = ResourceLimit #{const FD_SETSIZE}

  euid <- getEffectiveUserID
  limits <- getResourceLimit ResourceOpenFiles

  when (euid /= 0 && hardLimit limits < lowerLimit) $
    exitWith $ cat "The hard limit on file descriptors is set to "
                   (hardLimit limits) ", but we need at least " lowerLimit '.'
  when (fdSetSize < lowerLimit) $
    exitWith $ cat "FD_SETSIZE is " fdSetSize ", but we need at least "
                   lowerLimit " file descriptors."

  let newLimits limit
        | euid /= 0 = limits { softLimit = limit }
        | otherwise = limits { softLimit = limit, hardLimit = limit }
      minHardLimit | euid /= 0 = min $ hardLimit limits
                   | otherwise = id
      most = minHardLimit $ cap `min` fdSetSize
      unResourceLimit (ResourceLimit n) = n
      unResourceLimit _ = error "unResourceLimit: bug"

  fmap unResourceLimit $ E.catchJust E.ioErrors
    (setResourceLimit ResourceOpenFiles (newLimits most) >> return most) $ \e ->
    do
#ifdef OPEN_MAX
      -- For OS X 10.5. This hasn't been tested.
      let openMax = ResourceLimit #{const OPEN_MAX}
      if not (isPermissionError e) && openMax < most
        then do setResourceLimit ResourceOpenFiles (newLimits openMax)
                return openMax
        else E.throwIO (E.IOException e)
#else
      E.throwIO (E.IOException e)
#endif

instance Ord ResourceLimit where
  ResourceLimitInfinity `compare` ResourceLimitInfinity = EQ
  _ `compare` ResourceLimitInfinity = LT
  ResourceLimitInfinity `compare` _ = GT
  ResourceLimitUnknown `compare` ResourceLimitUnknown = EQ
  _ `compare` ResourceLimitUnknown = LT
  ResourceLimitUnknown `compare` _ = GT
  ResourceLimit n `compare` ResourceLimit n' = n `compare` n'

instance Show ResourceLimit where
  show (ResourceLimit n) = show n
  show ResourceLimitInfinity = "infinity"
  show ResourceLimitUnknown = "unknown"

-- | Lookup the UID and GID for a pair of user and group names.
getIDs :: Maybe String -> Maybe String -> IO (Maybe UserID, Maybe GroupID)
getIDs user group = do
  userEntry <- getUserEntryForName `liftMb` user
  groupEntry <- getGroupEntryForName `liftMb` group
  return (userID `fmap` userEntry, groupID `fmap` groupEntry)

-- | Drop privileges to the given UID\/GID pair.
dropPrivileges :: (Maybe UserID, Maybe GroupID) -> IO ()
dropPrivileges (uid,gid) = do
  whenJust gid setGroupID
  whenJust uid setUserID

-- | Call chroot(2) using the given directory path. Throws an 'IOError' if the
-- call fails.
changeRootDirectory :: FilePath -> IO ()
changeRootDirectory dir =
  withCString dir $ \s ->
    throwErrnoPathIfMinus1_ "changeRootDirectory" dir (chroot s)

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

-- | Print the given string as an error message and exit.
exitWith :: ShowS -> IO a
exitWith = exitLeft . Left

-- | Lift a 'Maybe' into a monadic action.
liftMb :: Monad m => (a -> m b) -> Maybe a -> m (Maybe b)
liftMb f = maybe (return Nothing) (liftM Just . f)

infixr 8 `liftMb`

-- | An alias for packAddress.
b :: Addr## -> ByteString
b = B.packAddress

foreign import ccall unsafe "chroot" chroot :: CString -> IO CInt
