{-# LANGUAGE PatternGuards, BangPatterns, ForeignFunctionInterface, CPP #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-missing-fields
                -fno-warn-orphans #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Main
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             pattern guards, bang patterns, FFI,
--                             GHC primitives)
--
-- Implements a DNSBL-style interface providing information about whether a
-- client for a network service is likely connecting through a Tor exit node.
--
-- See <https://tor.eff.org/svn/trunk/doc/contrib/torel-design.txt> for
-- details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Main (
  -- * Constants
    minFileDesc
  , maxFileDesc
  , extraFileDesc

  -- * Top level functionality
  , StaticState(..)
  , State(..)
  , MainThreadMessage(..)
  , main
  , verifyConfig
  , runMainThread
  , handleMessage
  , mkDNSServerConfig
  , mkExitTestConfig
  , initializeLogger
  , initializeNetworkStateManager
  , reconfigureOrRestartLogger
  , reconfigureListenersAndNetworkStateManager
  , reconfigureDNSListenerAndServer
  , terminateProcess

  -- * Daemon operations
  , getIDs
  , dropPrivileges
  , changeRootDirectory
  , daemonize

  -- * Helpers
  , setMaxOpenFiles
  , checkDirectory
  , checkLogTarget
  , SysExitCode(..)
  , fromSysExitCode
  , bindErrorCode
  , exitLeft
  , exitPrint
  , liftMb
  , b
  ) where

import Prelude hiding (log)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import qualified Control.Exception as E
import Control.Monad (when, liftM, forM, forM_)
import Control.Monad.Fix (fix)
import Control.Monad.State (StateT, runStateT, liftIO, get, put)
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.ByteString (ByteString)
import Data.Char (toLower)
import Data.List (intersperse)
import qualified Data.Map as M
import Data.Map (Map)
import Data.Maybe (isJust, isNothing, fromMaybe)
import qualified Data.Set as S
import Data.Set (Set)
import System.Environment (getArgs)
import System.IO
  ( openFile, hPutStrLn, hFlush, hClose, Handle, stdout, stderr
  , IOMode(WriteMode, ReadWriteMode, AppendMode) )
import System.IO.Error (isPermissionError)
import Network.Socket
  ( Socket, SockAddr(SockAddrInet), sClose, shutdown, ShutdownCmd(ShutdownSend)
  , socketToHandle )

import System.Exit (ExitCode(ExitSuccess, ExitFailure), exitWith)
import System.Directory (setCurrentDirectory, createDirectoryIfMissing)
import System.Posix.IO
  ( openFd, closeFd, stdInput, stdOutput, stdError, OpenMode(ReadWrite)
  , defaultFileFlags, dupTo )
import System.Posix.Process
  (forkProcess, createSession, exitImmediately, getProcessID)
import System.Posix.Signals
  ( installHandler, Signal, Handler(Ignore, Catch)
  , sigHUP, sigPIPE, sigINT, sigTERM )

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
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS
import TorDNSEL.DNS.Server
import TorDNSEL.Log
import TorDNSEL.NetworkState
import TorDNSEL.Random
import TorDNSEL.Statistics
import TorDNSEL.Util

#include <sys/types.h>
#include <unistd.h>
#include <sysexits.h>

--------------------------------------------------------------------------------
-- Constants

-- | Minimum limit on open file descriptors under which we can run.
minFileDesc :: ResourceLimit
minFileDesc = ResourceLimit 128

-- | Maximum limit on open file descriptors we can set with 'setResourceLimit'.
-- This should be relatively low because select(2) is O(n) in the number of open
-- fds. Once GHC begins using kqueue(2) and epoll(7), this limit can be lifted.
maxFileDesc :: ResourceLimit
maxFileDesc = ResourceLimit 4096

-- | Number of file descriptors the process might need for everything but exit
-- tests.
extraFileDesc :: Integer
extraFileDesc = 96

--------------------------------------------------------------------------------
-- Top level functionality

-- | State that is initialized once on startup, then never changed.
data StaticState = StaticState
  { availableFileDesc :: Integer -- ^ Number of file descriptors available.
  , randomHandle      :: Handle  -- ^ Handle to a random number device.
  , statsSocket       :: Socket  -- ^ Listening statistics socket.
  , reconfigSocket    :: Socket  -- ^ Listening reconfigure socket.
  }

-- | Mutable state used by the main thread.
data State = State
  { logger              :: Maybe Logger -- ^ The logger thread, if it's running.
  , reconfigServer      :: Maybe ReconfigServer
                            -- ^ The reconfigure server thread, if it's running.
  , statsServer         :: Maybe StatsServer
                            -- ^ The statistics server thread, if it's running.
  , networkStateManager :: NetworkStateManager
                            -- ^ The network state manager thread.
  , dnsServer           :: DNSServer -- ^ The DNS server thread.
  , exitTestListeners   :: Map SockAddr (Maybe Socket)
                            -- ^ Listening exit test sockets.
  , dnsListener         :: Socket -- ^ The listening DNS socket.
  , deadThreads         :: Set ThreadId
                            -- ^ Dead threads linked to the main thread.
  }

-- | Messages the main thread can receive.
data MainThreadMessage
  -- | Reconfigure the process given an optional config. If the config isn't
  -- given, try to reload our config file. Either way, the log file (if open)
  -- will be closed and re-opened. If the config is given, pass an error message
  -- to the given action if reconfiguring the process fails and we're about to
  -- exit.
  = Reconfigure (Maybe (Config, (Maybe String -> IO ())))
  | Terminate Signal -- ^ Terminate the process with the given Posix signal.
  | Exit ThreadId ExitReason -- ^ An exit signal sent by a linked thread.

-- | The main entry point for the server. This handles parsing config options,
-- various daemon operations, forking the network state handler, Tor controller,
-- exit test threads, and starting the DNS server.
main :: IO ()
main = do
  args <- getArgs
  case args of
    _ | args == ["-h"] || args == ["--help"] ->
          exitUsage stdout ExitSuccess
      | args == ["-v"] || args == ["--version"] ->
          putStrLn ("TorDNSEL " ++ VERSION) >> exitWith ExitSuccess
      | any (\arg -> map toLower arg == "--verify-config") args ->
          verifyConfig args
    ["--reconfigure",runtimeDir] -> do
      sock <- connectToReconfigSocket runtimeDir
        `E.catch` \e -> do
          hCat stderr "Connecting to reconfigure socket failed: " e '\n'
          exitWith $ fromSysExitCode Unavailable
      r <- E.handleJust E.ioErrors (\e -> do
             hCat stderr "An I/O error occurred while reconfiguring: " e '\n'
             exitWith $ fromSysExitCode IOError) $
        E.bracket (socketToHandle sock ReadWriteMode) hClose $ \handle -> do
          L.getContents >>= L.hPut handle
          hFlush handle
          shutdown sock ShutdownSend
          B.hGetContents handle
      B.hPut stderr r
      exitWith . fromSysExitCode $ case () of
       _| B.null r                             -> OK
        | b "Parse error:"## `B.isPrefixOf` r  -> DataError
        | b "Config error:"## `B.isPrefixOf` r -> ConfigError
        | otherwise                            -> ProtocolError
    _ -> return ()

  log Notice "Starting TorDNSEL " VERSION "."
  conf <- do
    conf <- exitLeft Usage $ parseConfigArgs args
    case b "configfile"## `M.lookup` conf of
      Just fp -> do
        file <- E.catchJust E.ioErrors (B.readFile $ B.unpack fp)
          (exitPrint NoInput . cat "Opening config file failed: ")
        exitLeft DataError $ makeConfig . M.union conf =<< parseConfigFile file
      Nothing -> exitLeft Usage $ makeConfig conf

  availFileDesc <- setMaxOpenFiles minFileDesc maxFileDesc
  random <- exitLeft OSFile =<< openRandomDevice
  seedPRNG random
  openSystemLogger "TorDNSEL" SysLogOptions { noDelay = True, logPid = True }
                   Daemon

  euid <- getEffectiveUserID
  when (any (isJust . ($ conf)) [cfUser, cfGroup, cfChangeRootDirectory] &&
        euid /= 0) $
    exitPrint NoPermission ("You must be root to drop privileges or chroot." ++)

  ids <- E.catchJust E.ioErrors
    (getIDs (cfUser conf) (cfGroup conf))
    (exitPrint OSFile . cat "Looking up uid/gid failed: ")

  E.catchJust E.ioErrors
    (checkDirectory (fst ids) (cfChangeRootDirectory conf)
                    (cfStateDirectory conf))
    (exitPrint Can'tCreate . cat "Preparing state directory failed: ")

  E.catchJust E.ioErrors
    (checkDirectory Nothing Nothing (cfRuntimeDirectory conf))
    (exitPrint Can'tCreate . cat "Preparing runtime directory failed: ")

  statsSock <- E.catchJust E.ioErrors
    (bindStatsSocket $ cfRuntimeDirectory conf)
    (exitPrint Can'tCreate . cat "Opening statistics listener failed: ")

  reconfigSock <- E.catchJust E.ioErrors
    (bindReconfigSocket (cfRuntimeDirectory conf) (fst ids))
    (exitPrint Can'tCreate . cat "Opening reconfigure listener failed: ")

  pidHandle <- E.catchJust E.ioErrors
    (flip openFile WriteMode `liftMb` cfPIDFile conf)
    (exitPrint Can'tCreate . cat "Opening PID file failed: ")

  log Notice "Opening DNS listener on " (cfDNSListenAddress conf) '.'
  dnsSock <- E.catchJust E.ioErrors
    (bindUDPSocket $ cfDNSListenAddress conf)
    (\e -> exitPrint (bindErrorCode e) $
             cat "Opening DNS listener on " (cfDNSListenAddress conf)
                 " failed: " e)

  testListeners <- case cfTestConfig conf of
    Nothing -> return M.empty
    Just testConf ->
      fmap M.fromList . forM (snd $ tcfTestListenAddress testConf) $ \port -> do
        let sockAddr = SockAddrInet (fromIntegral port)
                                   (htonl . fst $ tcfTestListenAddress testConf)
        log Notice "Opening exit test listener on " sockAddr '.'
        sock <- E.catchJust E.ioErrors
         (bindListeningTCPSocket sockAddr)
         (\e -> exitPrint (bindErrorCode e) $
                  cat "Opening exit test listener on " sockAddr " failed: " e)
        return (sockAddr, Just sock)

  -- We lose any other running threads when we 'forkProcess', so don't 'forkIO'
  -- before this point.
  (if cfRunAsDaemon conf then daemonize else id) .
    withLinksDo (showException [showLinkException]) $ do

    whenJust pidHandle $ \handle -> do
      hPutStrLn handle . show =<< getProcessID
      hClose handle

    whenJust (cfChangeRootDirectory conf) $ \dir -> do
      changeRootDirectory dir
      setCurrentDirectory "/"

    dropPrivileges ids

    let static = StaticState availFileDesc random statsSock reconfigSock
    runMainThread static testListeners dnsSock conf

-- | Given the command line arguments, check whether config options provided on
-- the command line and in an optional config file are well-formed. If they are,
-- exit with a successful status code. Otherwise, print an error message to
-- stderr and exit with an appropriate error code.
verifyConfig :: [String] -> IO a
verifyConfig args =
  case parseConfigArgs args of
    Left e -> exitStdErr Usage e
    Right conf ->
      case b "configfile"## `M.lookup` conf of
        Just fp -> do
          file <- E.catchJust E.ioErrors (B.readFile $ B.unpack fp) $ \e -> do
            hCat stderr "Opening config file failed: " e '\n'
            exitWith $ fromSysExitCode NoInput
          check DataError $ parseConfigFile file >>= makeConfig . M.union conf
        Nothing -> check Usage $ makeConfig conf
  where
    exitStdErr code e = hCat stderr e '\n' >> exitWith (fromSysExitCode code)
    check code = either (exitStdErr code) (const $ exitWith ExitSuccess)

-- | Install signal handlers, start children of the main thread, and enter the
-- main message-processing loop. Exit if we fail to start any threads.
runMainThread :: StaticState -> Map SockAddr (Maybe Socket) -> Socket
              -> Config -> IO ()
runMainThread static initTestListeners initDNSListener initConf = do
  mainChan <- newChan
  setTrapExit $ (writeChan mainChan .) . Exit

  installHandler sigPIPE Ignore Nothing
  let hupHandler = writeChan mainChan (Reconfigure Nothing)
      termHandler = writeChan mainChan . Terminate
  installHandler sigHUP (Catch hupHandler) Nothing
  installHandler sigINT (Catch $ termHandler sigINT) Nothing

  initState <- E.handle (\e -> do log Error "Starting failed: " e
                                  terminateLogger Nothing
                                  closeSystemLogger
                                  exitWith $ fromSysExitCode ConfigError) $ do
    initLogger <- initializeLogger initConf
    whenJust (cfChangeRootDirectory initConf) $ \dir ->
      log Notice "Chrooted in " (esc 256 $ B.pack dir) '.'
    when (any (isJust . ($ initConf)) [cfUser, cfGroup]) $
      log Notice "Dropped privileges to " (fromMaybe "" $ cfUser initConf) ':'
                 (fromMaybe "" $ cfGroup initConf) '.'
    initReconfig <- startReconfigServer (reconfigSocket static)
                      (((writeChan mainChan . Reconfigure) .) . curry Just)
    let cleanup = terminateReconfigServer Nothing initReconfig
    stats <- startStatsServer (statsSocket static)
      `E.catch` \e -> cleanup >> E.throwIO e
    let cleanup' = cleanup >> terminateStatsServer Nothing stats
    netState <- initializeNetworkStateManager
                  (mkExitTestConfig static initTestListeners initConf) initConf
      `E.catch` \e -> cleanup' >> E.throwIO e
    dns <- startDNSServer (mkDNSServerConfig initDNSListener initConf)
    return $ State (Just initLogger) (Just initReconfig) (Just stats) netState
                   dns initTestListeners initDNSListener S.empty

  log Notice "Successfully initialized all main subsystems. If no warnings "
             "appear above, it looks like everything is working."
  installHandler sigTERM (Catch $ termHandler sigTERM) Nothing
  flip fix (initConf, initState) $ \loop (!conf,!s) ->
    readChan mainChan >>= handleMessage mainChan static conf s >>= loop

-- | Process a 'MainThreadMessage', returning a new config and state.
handleMessage :: Chan MainThreadMessage -> StaticState -> Config -> State
              -> MainThreadMessage -> IO (Config, State)
handleMessage _ static conf s (Reconfigure reconf) = flip runStateT s $ do
  (mbNewConf,respond) <- case reconf of
    Just (newConf, respond) -> do
      log Notice "Reloaded config from reconfigure socket."
      return (Just newConf, respond)
    Nothing
      | Just configFile <- cfConfigFile conf -> do
          log Notice "Caught SIGHUP. Reloading config file."
          r <- liftIO . E.tryJust E.ioErrors $ B.readFile configFile
          case r of
            Left e -> do
              -- If we're chrooted, it's not suprising that we can't read our
              -- config file.
              when (isNothing $ cfChangeRootDirectory conf) $
                log Warn "Reading config file failed: " e '.'
              return (Nothing, const $ return ())
            Right file ->
              case parseConfigFile file >>= makeConfig of
                Left e -> do
                  log Warn "Parsing config file failed: " e '.'
                  return (Nothing, const $ return ())
                Right newConf -> return (Just newConf, const $ return ())
      | otherwise -> return (Nothing, const $ return ())
  let errorRespond msg = liftIO $ respond (Just msg) >> log Error msg
  case mbNewConf of
    Nothing
      | Just logger' <- logger s, ToFile _ <- logTarget (cfLogConfig conf) -> do
          -- Close and re-open the log file to allow for log rotation.
          r <- liftIO . E.tryJust syncExceptions $ reconfigureLogger id
          case r of
            Left _ -> modify' $ \s' ->
                        s' { logger = Nothing
                           , deadThreads = S.insert (threadId logger')
                                                    (deadThreads s') }
            Right _ -> return ()
          return conf
      | otherwise -> return conf
    Just newConf -> do
      let changedStatic = staticConfigOptionsChanged conf newConf
      when (not $ null changedStatic) $
        log Notice "Ignoring changed values for static config options "
                   (concat $ intersperse ", " changedStatic) '.'
      let newConf' = copyStaticConfigOptions conf newConf

      when (cfStateDirectory conf /= cfStateDirectory newConf') $
        liftIO $ checkDirectory Nothing Nothing (cfStateDirectory newConf')
          `E.catch` \e -> do
            errorRespond $ cat "Preparing new state directory failed: " e
                               "; exiting gracefully."
            terminateProcess Can'tCreate static s Nothing

      reconfigureOrRestartLogger newConf'
      reconfigureListenersAndNetworkStateManager static newConf' errorRespond
      reconfigureDNSListenerAndServer static conf newConf' errorRespond
      liftIO $ respond Nothing
      return newConf'

handleMessage _mainChan static _conf s (Terminate signal) = do
  log Notice "Caught signal (" signalStr "); exiting gracefully."
  terminateProcess OK static s $
    if signal == sigINT
      then Nothing
      else Just exitWaitPeriod
  where
    signalStr | signal == sigINT  = "SIGINT"
              | signal == sigTERM = "SIGTERM"
              | otherwise         = show signal
    exitWaitPeriod = 2 * 10^6

handleMessage mainChan static conf s (Exit tid reason)
  | deadThreadIs logger = do
      (r,dead) <- tryForkLinkIO $ initializeLogger conf
      mbNewLogger <- case r of
        Left _ -> return Nothing
        Right newLogger -> do
          log Warn "The logger thread exited unexpectedly: "
                   (showExitReason [] reason) "; restarted."
          return $ Just newLogger
      return (conf, s { logger = mbNewLogger
                      , deadThreads = S.insert dead (deadThreads s) })
  | deadThreadIs reconfigServer = do
      log Warn "The reconfigure server thread exited unexpectedly: "
               (showExitReason [] reason) "; restarting."
      (r,dead) <- tryForkLinkIO $ startReconfigServer (reconfigSocket static)
                           (((writeChan mainChan . Reconfigure) .) . curry Just)
      mbNewReconfigServer <- case r of
        Left e -> do
          log Warn "Restarting reconfigure server failed: "
                   (showExitReason [] e) "; disabling reconfigure server."
          return Nothing
        Right newReconfigServer -> return $ Just newReconfigServer
      return (conf, s { reconfigServer = mbNewReconfigServer
                      , deadThreads = S.insert dead (deadThreads s) })
  | deadThreadIs statsServer = do
      log Warn "The statistics server thread exited unexpectedly: "
               (showExitReason [] reason) "; restarting."
      (r,dead) <- tryForkLinkIO . startStatsServer $ statsSocket static
      mbNewStatsServer <- case r of
        Left e -> do
          log Warn "Restarting statistics server failed: " (showExitReason [] e)
                   "; disabling statistics server."
          return Nothing
        Right newStatsServer -> return $ Just newStatsServer
      return (conf, s { statsServer = mbNewStatsServer
                      , deadThreads = S.insert dead (deadThreads s) })
  | tid == threadId (networkStateManager s) = do
      log Warn "The network state manager thread exited unexpectedly: "
               (showExitReason [] reason) "; restarting."
      newManager <- initializeNetworkStateManager
                      (mkExitTestConfig static (exitTestListeners s) conf) conf
        `E.catch` \e -> do
          log Error "Restarting network state manager failed: " e
                    "; exiting gracefully."
          terminateProcess Internal static s Nothing
      return (conf, s { networkStateManager = newManager })
  | tid == threadId (dnsServer s) = do
      log Warn "The DNS server thread exited unexpectedly: "
               (showExitReason [] reason) "; restarting."
      newDNSServer <- startDNSServer $ mkDNSServerConfig (dnsListener s) conf
      return (conf, s { dnsServer = newDNSServer })
  | tid `S.member` deadThreads s
  = return (conf, s { deadThreads = S.delete tid (deadThreads s) })
  | otherwise = do
      log Warn "Bug: Received unexpected exit signal: "
               (showExitReason [] reason)
      return (conf, s)
  where deadThreadIs thr = ((tid ==) . threadId) `fmap` thr s == Just True

-- | Return the DNS server config given a listening DNS socket and the 'Config'.
mkDNSServerConfig :: Socket -> Config -> DNSConfig
mkDNSServerConfig dnsSock conf =
  DNSConfig
    { dnsSocket = dnsSock
    , dnsAuthZone = DomainName $ reverse authLabels
    , dnsMyName = cfDomainName conf
    , dnsSOA = SOA (cfAuthoritativeZone conf) ttl (cfDomainName conf)
                   (cfSOARName conf) 0 ttl ttl ttl ttl
    , dnsNS = NS (cfAuthoritativeZone conf) ttl (cfDomainName conf)
    , dnsA = A (cfAuthoritativeZone conf) ttl `fmap` cfAddress conf
    , dnsByteStats = incrementBytes
    , dnsRespStats = incrementResponses }
  where DomainName authLabels = cfAuthoritativeZone conf

-- | Return the exit test config.
mkExitTestConfig :: StaticState -> Map SockAddr (Maybe Socket) -> Config
                 -> TestConfig -> ExitTestConfig
mkExitTestConfig static testListeners conf testConf =
  ExitTestConfig
    { etcfListeners = testListeners
    , etcfConcClientLimit = (availableFileDesc static - extraFileDesc) `div` 2
    , etcfGetRandBytes = randBytes $ randomHandle static
    , etcfTorSocksAddr = cfTorSocksAddress conf
    , etcfTestAddress = fst $ tcfTestDestinationAddress testConf
    , etcfTestPorts = snd $ tcfTestDestinationAddress testConf }

-- | Start the logger thread, resetting the log target or disabling logging if
-- necessary.
initializeLogger :: Config -> IO Logger
initializeLogger conf = do
  newLogTarget <- checkLogTarget . logTarget . cfLogConfig $ conf
  let newLogConfig = (cfLogConfig conf) { logTarget = newLogTarget }
  if cfRunAsDaemon conf && any (newLogTarget ==) [ToStdOut, ToStdErr]
    then startLogger newLogConfig { logEnabled = False }
    else startLogger newLogConfig

-- | Start the network state manager thread.
initializeNetworkStateManager
  :: (TestConfig -> ExitTestConfig) -> Config -> IO NetworkStateManager
initializeNetworkStateManager exitTestConfig conf = do
  startNetworkStateManager NetworkStateManagerConfig
    { nsmcfTorControlAddr = cfTorControlAddress conf
    , nsmcfTorControlPasswd = cfTorControlPassword conf
    , nsmcfStateDir = cfStateDirectory conf
    , nsmcfExitTestConfig = exitTestConfig `fmap` cfTestConfig conf }

-- | Reconfigure the logger if it's running, or attempt to restart it if it's
-- not running, given the new config.
reconfigureOrRestartLogger :: Config -> StateT State IO ()
reconfigureOrRestartLogger conf = do
  s <- get
  case logger s of
    Just logger' -> do
      logConf <- if cfRunAsDaemon conf &&
        any (logTarget (cfLogConfig conf) ==) [ToStdOut, ToStdErr]
        then do
          log Warn "Cannot log to " (logTarget $ cfLogConfig conf)
                   " when daemonized. Disabling logging."
          return (cfLogConfig conf) { logEnabled = False }
        else return $ cfLogConfig conf
      r <- liftIO . E.tryJust syncExceptions $ reconfigureLogger (const logConf)
      case r of
        Left _ -> put $! s { logger = Nothing
                           , deadThreads = S.insert (threadId logger')
                                                    (deadThreads s) }
        Right _ -> return ()
    Nothing -> do
      (r,dead) <- liftIO . tryForkLinkIO $ initializeLogger conf
      let mbNewLogger = either (const Nothing) Just r
      put $! s { logger = mbNewLogger
               , deadThreads = S.insert dead (deadThreads s) }

-- | Reconfigure the exit test listeners and network state manager.
reconfigureListenersAndNetworkStateManager
  :: StaticState -> Config -> (String -> StateT State IO ())
  -> StateT State IO ()
reconfigureListenersAndNetworkStateManager static conf errorRespond = do
  s <- get
  let (mbNewListeners,newListenerMap) = updateListeners s
  r <- liftIO . E.tryJust syncExceptions $
         reconfigureNetworkStateManager
           (\c -> c { nsmcfTorControlAddr = cfTorControlAddress conf
                    , nsmcfTorControlPasswd = cfTorControlPassword conf
                    , nsmcfStateDir = cfStateDirectory conf
                    , nsmcfExitTestConfig =
                        mkExitTestConfig static newListenerMap conf
                          `fmap` cfTestConfig conf })
           (networkStateManager s)
  case r of
    Left e -> do
      errorRespond $ cat "Reconfiguring network state manager failed: " e
                         "; exiting gracefully."
      get >>= liftIO . flip (terminateProcess ConfigError static) Nothing
    Right _ -> do
      put $! s { exitTestListeners = newListenerMap }
      whenJust mbNewListeners $ \newListeners ->
        forM_ (M.assocs $ exitTestListeners s `M.difference` newListeners) $
          \(addr,mbSock) -> whenJust mbSock $ \sock -> do
            log Notice "Closing exit test listener on " addr '.'
            liftIO $ sClose sock
  where
    updateListeners s =
      case cfTestConfig conf of
        Just testConf ->
          let addr = htonl . fst $ tcfTestListenAddress testConf
              newListeners = M.fromList $
                map (\port -> (SockAddrInet (fromIntegral port) addr, Nothing))
                    (snd $ tcfTestListenAddress testConf)
          in ( Just newListeners
             , M.intersection (exitTestListeners s) newListeners
                 `M.union` newListeners )
        Nothing -> (Nothing, exitTestListeners s)

-- | Reconfigure the DNS server, and the DNS listener if necessary.
reconfigureDNSListenerAndServer
  :: StaticState -> Config -> Config -> (String -> StateT State IO ())
  -> StateT State IO ()
reconfigureDNSListenerAndServer static oldConf newConf errorRespond = do
  when (cfDNSListenAddress oldConf /= cfDNSListenAddress newConf) $ do
    log Notice "Opening DNS listener on " (cfDNSListenAddress newConf) '.'
    r <- liftIO . E.tryJust E.ioErrors $
           bindUDPSocket $ cfDNSListenAddress newConf
    case r of
      Left e -> do
        errorRespond $
          cat "Opening DNS listener on " (cfDNSListenAddress newConf)
              " failed: " e "; exiting gracefully."
        s <- get
        liftIO $ terminateProcess (bindErrorCode e) static s Nothing
      Right sock -> do
        log Notice "Closing DNS listener on " (cfDNSListenAddress oldConf) '.'
        modify' $ \s -> s { dnsListener = sock }
  s <- get
  r <- liftIO . E.tryJust syncExceptions $
          reconfigureDNSServer
            (const $ mkDNSServerConfig (dnsListener s) newConf) (dnsServer s)
  case r of
    Left e -> do
      errorRespond $ cat "Reconfiguring DNS Server failed: " e
                         "; exiting gracefully."
      get >>= liftIO . flip (terminateProcess IOError static) Nothing
    Right _ -> return ()

-- | Terminate the process by first asking all our linked, child threads to
-- terminate gracefully, then releasing the resources held in 'StaticState'.
terminateProcess :: SysExitCode -> StaticState -> State -> Maybe Int -> IO a
terminateProcess status static s mbWait = do
  whenJust (reconfigServer s) (terminateReconfigServer mbWait)
  terminateNetworkStateManager mbWait $ networkStateManager s
  terminateDNSServer mbWait $ dnsServer s
  whenJust (statsServer s) (terminateStatsServer mbWait)
  forM_ (M.assocs $ exitTestListeners s) $ \(addr,mbSock) ->
    whenJust mbSock $ \sock -> do
      log Info "Closing exit test listener on " addr '.'
      ignoreJust E.ioErrors $ sClose sock
  log Info "Closing DNS listener."
  ignoreJust E.ioErrors . sClose $ dnsListener s
  log Info "Closing statistics listener."
  ignoreJust E.ioErrors . sClose $ statsSocket static
  log Info "Closing reconfigure listener."
  ignoreJust E.ioErrors . sClose $ reconfigSocket static
  ignoreJust E.ioErrors . hClose $ randomHandle static
  log Notice "All subsystems have terminated. Exiting now."
  terminateLogger mbWait
  closeSystemLogger
  exitWith $ fromSysExitCode status

--------------------------------------------------------------------------------
-- Daemon operations

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
    throwErrnoPathIfMinus1_ "changeRootDirectory" dir (c_chroot s)

-- | Run an IO action as a daemon. This action doesn't return.
daemonize :: IO () -> IO ()
daemonize io = do
  forkProcess $ do
    createSession
    forkProcess $ do
      setCurrentDirectory "/"
      mapM_ closeFd stdFds
      nullFd <- openFd "/dev/null" ReadWrite Nothing defaultFileFlags
      mapM_ (dupTo nullFd) stdFds
      closeFd nullFd
      io
    exitImmediately ExitSuccess
  exitImmediately ExitSuccess
  where stdFds = [stdInput, stdOutput, stdError]

--------------------------------------------------------------------------------
-- Helpers

-- | Ensure that the current limit on open file descriptors is at least
-- @lowerLimit@ and at least the minimum of @cap@ and FD_SETSIZE. Return the
-- new current limit.
setMaxOpenFiles :: ResourceLimit -> ResourceLimit -> IO Integer
setMaxOpenFiles lowerLimit cap = do
  let fdSetSize = ResourceLimit #{const FD_SETSIZE}

  euid <- getEffectiveUserID
  limits <- getResourceLimit ResourceOpenFiles

  when (euid /= 0 && hardLimit limits < lowerLimit) $
    exitPrint NoPermission $
      cat "The hard limit on file descriptors is set to " (hardLimit limits)
          ", but we need at least " lowerLimit '.'
  when (fdSetSize < lowerLimit) $
    exitPrint Internal $
      cat "FD_SETSIZE is " fdSetSize ", but we need at least " lowerLimit
          " file descriptors."

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

-- | Set up the state or runtime directory with proper ownership and
-- permissions.
checkDirectory :: Maybe UserID -> Maybe FilePath -> FilePath -> IO ()
checkDirectory uid newRoot path = do
  createDirectoryIfMissing True fullPath
  desiredUID <- maybe getEffectiveUserID return uid
  st <- getFileStatus fullPath
  when (fileOwner st /= desiredUID) $
    setOwnerAndGroup fullPath desiredUID (-1)
  when (fileMode st .&. 0o700 /= 0o700) $
    setFileMode fullPath (fileMode st .|. 0o700)
  where fullPath = maybe id ((++) . (++ "/")) newRoot path

-- | Check if the log target can be used. If it can, return it. Otherwise,
-- return 'ToStdOut'.
checkLogTarget :: LogTarget -> IO LogTarget
checkLogTarget target@(ToFile logPath) =
  E.catchJust E.ioErrors
    (do E.bracket (openFile logPath AppendMode) hClose (const $ return ())
        return target)
    (const $ return ToStdOut)
checkLogTarget target = return target

-- | System exit status codes from sysexits.h.
data SysExitCode
  = OK            -- ^ Successful termination
  | Usage         -- ^ Command line usage error
  | DataError     -- ^ Data format error
  | NoInput       -- ^ Cannot open input
  | NoUser        -- ^ Addressee unknown
  | NoHost        -- ^ Host name unknown
  | Unavailable   -- ^ Service unavailable
  | Internal      -- ^ Internal software error
  | OSError       -- ^ System error (e.g., can't fork)
  | OSFile        -- ^ Critical OS file missing
  | Can'tCreate   -- ^ Can't create (user) output file
  | IOError       -- ^ Input/output error
  | TempFailure   -- ^ Temp failure; user is invited to retry
  | ProtocolError -- ^ Remote error in protocol
  | NoPermission  -- ^ Permission denied
  | ConfigError   -- ^ Configuration error

-- | Convert a system exit status code to an 'ExitCode' for 'exitWith'.
fromSysExitCode :: SysExitCode -> ExitCode
fromSysExitCode status = case status of
  OK            -> ExitSuccess
  Usage         -> ExitFailure #{const EX_USAGE}
  DataError     -> ExitFailure #{const EX_DATAERR}
  NoInput       -> ExitFailure #{const EX_NOINPUT}
  NoUser        -> ExitFailure #{const EX_NOUSER}
  NoHost        -> ExitFailure #{const EX_NOHOST}
  Unavailable   -> ExitFailure #{const EX_UNAVAILABLE}
  Internal      -> ExitFailure #{const EX_SOFTWARE}
  OSError       -> ExitFailure #{const EX_OSERR}
  OSFile        -> ExitFailure #{const EX_OSFILE}
  Can'tCreate   -> ExitFailure #{const EX_CANTCREAT}
  IOError       -> ExitFailure #{const EX_IOERR}
  TempFailure   -> ExitFailure #{const EX_TEMPFAIL}
  ProtocolError -> ExitFailure #{const EX_PROTOCOL}
  NoPermission  -> ExitFailure #{const EX_NOPERM}
  ConfigError   -> ExitFailure #{const EX_CONFIG}

-- | Return the system exit code corresponding to an 'IOError' generated by the
-- failure to open a listening socket.
bindErrorCode :: IOError -> SysExitCode
bindErrorCode e | isPermissionError e = NoPermission
                | otherwise           = OSError

-- | Lift an @Either ShowS@ computation into the 'IO' monad by logging @Left e@
-- as an error message and exiting.
exitLeft :: SysExitCode -> Either ShowS a -> IO a
exitLeft status = either (exitPrint status) return

-- | Print the given string as an error message and exit with the given status.
exitPrint :: SysExitCode -> ShowS -> IO a
exitPrint status msg = do
  log Error msg
  exitUsage stderr $ fromSysExitCode status

-- | Lift a 'Maybe' into a monadic action.
liftMb :: Monad m => (a -> m b) -> Maybe a -> m (Maybe b)
liftMb f = maybe (return Nothing) (liftM Just . f)

infixr 8 `liftMb`

-- | An alias for packAddress.
b :: Addr## -> ByteString
b = B.packAddress

foreign import ccall unsafe "unistd.h chroot"
  c_chroot :: CString -> IO CInt
