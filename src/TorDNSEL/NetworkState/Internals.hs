{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, pattern guards, bang patterns)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Manages our current view of the Tor network, initiating test connections
-- through exit nodes when necessary and storing results of those tests in
-- the file system.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.NetworkState.Internals (
    NetworkStateManager(..)
  , networkStateMV
  , NetworkStateManagerConfig(..)
  , ExitTestConfig(..)
  , ManagerState(..)
  , ExitTestState(..)
  , startNetworkStateManager
  , reconfigureNetworkStateManager
  , terminateNetworkStateManager
  , handleMessage
  , withCookie
  , lookupRouters
  , modifyNetworkState
  , readNetworkState
  , modify'

  -- * Tor controller
  , startTorController

  -- * Exit tests
  , initExitTestServerConfig
  , initExitTestInitiatorConfig
  , initializeExitTests
  , terminateExitTests

  -- * Pure network state updates
  , mergeExitAddrsWithNetState
  , newExitAddress
  , newDescriptor
  , newRouterStatus
  , expireOldInfo
  , insertAddress
  , deleteAddress
  ) where

import Prelude hiding (log)
import Control.Arrow ((&&&))
import Control.Monad (liftM2, when)
import Control.Monad.Fix (fix)
import Control.Monad.State
  (MonadState, StateT, runStateT, execStateT, get, gets, put, MonadIO, liftIO)
import Control.Concurrent (threadDelay)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newMVar, readMVar, swapMVar)
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)
import Data.List (foldl')
import Data.Maybe (mapMaybe, isJust, fromMaybe)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Set as S
import Data.Set (Set)
import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import Network.Socket
  ( HostAddress, SockAddr, Socket, Family(AF_INET), SocketType(Stream)
  , socket, connect, sClose, socketToHandle )
import System.IO (IOMode(ReadWriteMode))
import System.IO.Unsafe (unsafePerformIO)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.Directory
import TorDNSEL.ExitTest.Initiator
import TorDNSEL.ExitTest.Request
import TorDNSEL.ExitTest.Server
import TorDNSEL.Log
import TorDNSEL.NetworkState.Storage
import TorDNSEL.NetworkState.Types
import TorDNSEL.TorControl
import TorDNSEL.Util

-- | A handle to the network state manager thread.
data NetworkStateManager
  = NetworkStateManager (ManagerMessage -> IO ()) ThreadId

instance Thread NetworkStateManager where
  threadId (NetworkStateManager _ tid) = tid

-- | A mutable variable containing the current network state.
networkStateMV :: MVar NetworkState
{-# NOINLINE networkStateMV #-}
networkStateMV = unsafePerformIO $ newMVar emptyNetworkState

-- | The network state manager configuration.
data NetworkStateManagerConfig = NetworkStateManagerConfig
  { -- | Address to connect to the Tor controller interface.
    nsmcfTorControlAddr   :: !SockAddr,
    -- | The password used for Tor controller auth.
    nsmcfTorControlPasswd :: !(Maybe ByteString),
    -- | Where to store exit test results.
    nsmcfStateDir         :: !FilePath,
    -- | The exit test configuration, if exit tests are enabled.
    nsmcfExitTestConfig   :: !(Maybe ExitTestConfig) } deriving Eq

-- | The exit test configuration.
data ExitTestConfig = ExitTestConfig
  { -- | Addresses on which to listen for exit test connection and the
    -- associated listening sockets, when they are open.
    etcfListeners       :: !(Map SockAddr (Maybe Socket)),
    -- | The maximum number of exit tests to run concurrently.
    etcfConcClientLimit :: !Integer,
    -- | Get an arbitrary number of bytes from OpenSSL's PRNG.
    etcfGetRandBytes    :: !(Int -> IO ByteString),
    -- | Where Tor is listening for SOCKS connections.
    etcfTorSocksAddr    :: !SockAddr,
    -- | The IP address to which we make exit test connections through Tor.
    etcfTestAddress     :: !HostAddress,
    -- | The ports to which we make exit test connections through Tor.
    etcfTestPorts       :: ![Port] }

instance Eq ExitTestConfig where
  x == y = all (\(===) -> x === y)
    [ eq etcfListeners, eq etcfConcClientLimit, eq etcfTorSocksAddr
    , eq etcfTestAddress, eq etcfTestPorts ]
    where
      eq :: Eq b => (a -> b) -> a -> a -> Bool
      eq = on (==)

-- | An internal type representing the current exit test manager state.
data ManagerState = ManagerState
  { networkState   :: !NetworkState
  , torControlConn :: !(Either (ThreadId, Int) Connection)
  , deadThreads    :: !(Set ThreadId)
  , exitTestState  :: !(Maybe ExitTestState) }

-- | An internal type representing the current exit test state.
data ExitTestState = ExitTestState
  { storageManager    :: !StorageManager
  , exitTestServer    :: !ExitTestServer
  , exitTestInitiator :: !ExitTestInitiator
  , cookies           :: !(Map Cookie (RouterID, UTCTime, Port)) }

-- | An internal type for messages sent to the network state manager.
data ManagerMessage
  = NewDescriptors [Descriptor] -- ^ New descriptors are available.
  | NewNetworkStatus [RouterStatus] -- ^ New router status entries are available
  -- | Map a new cookie to an exit node identifier, descriptor published time,
  -- and port.
  | MapCookie Cookie RouterID UTCTime Port
  | UnmapCookie Cookie -- ^ Remove a cookie to exit node identity mapping.
  -- | We've received a cookie from an incoming exit test connection.
  | NewExitAddress UTCTime Cookie HostAddress
  -- | Reconfigure the network state manager.
  | Reconfigure (NetworkStateManagerConfig -> NetworkStateManagerConfig) (IO ())
  | Terminate ExitReason -- ^ Terminate the network state manager gracefully.
  -- | An exit signal sent to the network state manager.
  | Exit ThreadId ExitReason

-- | Start the network state manager given an initial config, returning a handle
-- to it. Link the network state manager to the calling thread. If the network
-- state manager exits before completely starting, throw its exit signal in the
-- calling thread.
startNetworkStateManager :: NetworkStateManagerConfig -> IO NetworkStateManager
startNetworkStateManager initConf = do
  log Info "Starting network state manager."
  chan <- newChan
  tid <- startLink $ \signal -> do
    setTrapExit $ (writeChan chan .) . Exit
    net <- NetworkStateManager (writeChan chan) `fmap` myThreadId
    (controller,deadTid) <- startTorController net initConf Nothing
    let emptyState = ManagerState emptyNetworkState controller
                                  (S.singleton deadTid) Nothing
    initState <- case nsmcfExitTestConfig initConf of
      -- Only fork exit test threads when the controller is running.
      Just testConf | Right conn <- controller ->
        execStateT (initializeExitTests net (nsmcfStateDir initConf) testConf)
                   emptyState
          `E.catch` \e -> closeConnection conn >> E.throwIO e
      _ -> return emptyState
    swapMVar networkStateMV $! networkState initState
    signal
    flip fix (initConf, initState) $ \loop (!conf,!s) -> do
      msg <- readChan chan
      -- XXX This should be the strict StateT rather than the lazy one.
      runStateT (handleMessage net conf msg) s >>= loop

  return $ NetworkStateManager (writeChan chan) tid

-- | Reconfigure the network state mananger synchronously with the given
-- function. If the thread exits abnormally before reconfiguring itself, throw
-- its exit signal in the calling thread.
reconfigureNetworkStateManager
  :: (NetworkStateManagerConfig -> NetworkStateManagerConfig)
  -> NetworkStateManager -> IO ()
reconfigureNetworkStateManager reconf (NetworkStateManager send tid) =
  sendSyncMessage (send . Reconfigure reconf) tid

-- | Terminate the network state manager gracefully. The optional parameter
-- specifies the amount of time in microseconds to wait for the thread to
-- terminate. If the thread hasn't terminated by the timeout, an uncatchable
-- exit signal will be sent.
terminateNetworkStateManager :: Maybe Int -> NetworkStateManager -> IO ()
terminateNetworkStateManager mbWait (NetworkStateManager send tid) =
  terminateThread mbWait tid (send $ Terminate Nothing)

-- | Process a 'ManagerMessage' and return the new config and state, given the
-- current config and state.
handleMessage
  :: NetworkStateManager -> NetworkStateManagerConfig -> ManagerMessage
  -> StateT ManagerState IO NetworkStateManagerConfig
handleMessage _net conf (NewDescriptors ds) = do
  now <- liftIO getCurrentTime
  networkState' <- gets $ \s -> foldl' (newDescriptor now) (networkState s) ds
  modifyNetworkState networkState'
  mbTestState <- gets exitTestState
  whenJust mbTestState $ \testState ->
    liftIO $ notifyNewDirInfo (lookupRouters networkState' descRouterID ds)
                              (exitTestInitiator testState)
  return conf

handleMessage _net conf (NewNetworkStatus rss) = do
  now <- liftIO getCurrentTime
  networkState' <- gets $ \s -> expireOldInfo now $ foldl' (newRouterStatus now)
                                                           (networkState s) rss
  modifyNetworkState networkState'
  mbTestState <- gets exitTestState
  whenJust mbTestState $ \testState -> liftIO $ do
    notifyNewDirInfo (lookupRouters networkState' rsRouterID rss)
                     (exitTestInitiator testState)
    rebuildExitAddressStorage (nsRouters networkState')
                              (storageManager testState)
  return conf

handleMessage _net conf (MapCookie cookie rid published port) = do
  mbTestState <- gets exitTestState
  case mbTestState of
    Just testState -> modify' $ \s ->
      s { exitTestState = Just $! testState { cookies =
            M.insert cookie (rid, published, port) (cookies testState) } }
    Nothing -> log Debug "Ignoring request to map a cookie for router " rid
                         " since exit tests are disabled."
  return conf

handleMessage _net conf (UnmapCookie cookie) = do
  mbTestState <- gets exitTestState
  case mbTestState of
    Just testState -> modify' $ \s ->
      s { exitTestState = Just $! testState { cookies =
            M.delete cookie (cookies testState) } }
    Nothing -> log Debug "Ignoring request to unmap a cookie since exit tests \
                         \are disabled."
  return conf

handleMessage _net conf (NewExitAddress tested cookie address) = do
  mbTestState <- gets exitTestState
  case mbTestState of
    Nothing -> log Info "Ignoring exit test request from " (inet_htoa address)
                        " since exit tests are disabled."
    Just testState ->
      case cookie `M.lookup` cookies testState of
        Nothing -> log Info "Received unrecognized cookie from "
                            (inet_htoa address) "; discarding."
        Just (rid,published,port) -> do
          mbRouter <- gets (M.lookup rid . nsRouters . networkState)
          case mbRouter of
            Nothing -> log Info "Received cookie for unrecognized router " rid
                                "; discarding."
            Just router -> do
              log Info "Exit test through router " rid " port " port
                      " accepted from " (inet_htoa address) '.'
              (router',networkState') <- gets $ newExitAddress tested published
                                               router rid address . networkState
              modifyNetworkState networkState'

              when ((M.member address . tstAddresses) `fmap`
                    rtrTestResults router == Just False) $
                -- If we haven't seen this address before, test through this
                -- router again in case the router is rotating exit addresses.
                liftIO $ scheduleNextExitTest rid (exitTestInitiator testState)

              liftIO $ storeNewExitAddress rid router' (nsRouters networkState')
                                           (storageManager testState)
  return conf

handleMessage net conf (Reconfigure reconf signal)
  | conf == newConf = liftIO signal >> return newConf
  | otherwise = do
      log Notice "Reconfiguring network state manager."
      when (nsmcfTorControlAddr conf /= nsmcfTorControlAddr newConf) $ do
        controlConn <- gets torControlConn
        deadTid1 <- case controlConn of
          Left (tid,_) -> return tid
          Right conn -> do
            log Notice "Closing Tor controller connection."
            liftIO $ closeConnection conn
            return $ threadId conn
        (controller,deadTid2) <- startTorController net newConf Nothing
        modify' $ \s ->
          s { torControlConn = controller
            , deadThreads = S.insert deadTid2 . S.insert deadTid1 $
                              deadThreads s }
      s <- get
      case exitTestState s of
        Nothing
          | Just testConf <- nsmcfExitTestConfig newConf
          , Right _ <- torControlConn s ->
              initializeExitTests net (nsmcfStateDir newConf) testConf >>=
               liftIO . notifyNewDirInfo (M.assocs . nsRouters $ networkState s)
          | otherwise -> return ()
        Just testState
          | Just testConf <- nsmcfExitTestConfig newConf
          , Right _ <- torControlConn s -> liftIO $ do
              flip reconfigureExitTestInitiator (exitTestInitiator testState) $
                \c -> c { eticfConcClientLimit = etcfConcClientLimit testConf
                        , eticfSocksServer = etcfTorSocksAddr testConf
                        , eticfTestAddress = etcfTestAddress testConf
                        , eticfTestPorts = etcfTestPorts testConf }
              flip reconfigureExitTestServer (exitTestServer testState) $ \c ->
                c { etscfConcClientLimit = etcfConcClientLimit testConf
                  , etscfListenAddrs = M.keysSet $ etcfListeners testConf }
              reconfigureStorageManager
                (\c -> c { stcfStateDir = nsmcfStateDir newConf })
                (storageManager testState)
          | otherwise -> terminateExitTests testState
      liftIO signal
      return newConf
  where newConf = reconf conf

handleMessage _net _conf (Terminate reason) = do
  log Info "Terminating network state manager."
  s <- get
  either (const $ return ()) (liftIO . closeConnection) (torControlConn s)
  whenJust (exitTestState s) $ \testState -> do
    terminateExitTests testState
    return ()
  liftIO $ exit reason

handleMessage net conf (Exit tid reason) = get >>= handleExit where
  handleExit s
    | Left (timer,delay) <- torControlConn s, tid == timer = do
        (controller,deadTid) <- startTorController net conf (Just delay)
        put $! s { torControlConn = controller
                 , deadThreads = S.insert deadTid (deadThreads s) }
        case controller of
          Right _ | Just testConf <- nsmcfExitTestConfig conf ->
            initializeExitTests net (nsmcfStateDir conf) testConf >>=
             liftIO . notifyNewDirInfo (M.assocs . nsRouters . networkState $ s)
          _ -> return ()
        return conf
    | Right conn <- torControlConn s, tid == threadId conn = do
        log Warn "The Tor controller thread exited unexpectedly: "
                 (showExitReason [showTorControlError] reason) "; restarting."
        (controller,deadTid) <- startTorController net conf Nothing
        put $! s { torControlConn = controller
                 , deadThreads = S.insert deadTid (deadThreads s) }
        case controller of
          Left _ | Just testState <- exitTestState s ->
            terminateExitTests testState
          _ -> return ()
        return conf
    | tid `S.member` deadThreads s = do
        put $! s { deadThreads = S.delete tid (deadThreads s) }
        return conf
    | otherwise
    = case liftM2 (,) (nsmcfExitTestConfig conf) (exitTestState s) of
        Just (testConf,testState)
          | tid == toTid storageManager -> do
              log Warn "The storage manager thread exited unexpectedly: "
                      (showExitReason [] reason) "; restarting."
              storage <- liftIO . startStorageManager . StorageConfig $
                           nsmcfStateDir conf
              liftIO $ rebuildExitAddressStorage (nsRouters $ networkState s)
                                                 storage
              putTestState testState { storageManager = storage }
              return conf
          | tid == toTid exitTestServer -> do
              log Warn "The exit test server thread exited unexpectedly: "
                       (showExitReason [] reason) "; restarting."
              server <- liftIO $ startExitTestServer
                                   (M.assocs $ etcfListeners testConf)
                                   (initExitTestServerConfig net testConf)
              putTestState testState { exitTestServer = server }
              return conf
          | tid == toTid exitTestInitiator -> do
              log Warn "The exit test initiator thread exited unexpectedly: "
                       (showExitReason [] reason) "; restarting."
              initiator <- liftIO $ startExitTestInitiator
                                      (initExitTestInitiatorConfig net testConf)
              putTestState testState { exitTestInitiator = initiator }
              return conf
          where
            toTid f = threadId $ f testState
            putTestState x = put $! s { exitTestState = Just $! x}
        _ | isJust reason -> liftIO $ exit reason
          | otherwise -> return conf

-- | Register a mapping from cookie to router identifier, descriptor published
-- time and port, passing the cookie to the given 'IO' action. The cookie is
-- guaranteed to be released when the action terminates.
withCookie :: NetworkStateManager -> (Int -> IO ByteString) -> RouterID
           -> UTCTime -> Port -> (Cookie -> IO a) -> IO a
withCookie (NetworkStateManager send _) getRandBytes rid published port =
  E.bracket addNewCookie (send . UnmapCookie) where
    addNewCookie = do
      cookie <- newCookie getRandBytes
      send $ MapCookie cookie rid published port
      return cookie

-- | Lookup a list of routers in the network state.
lookupRouters :: NetworkState -> (a -> RouterID) -> [a] -> [(RouterID, Router)]
lookupRouters ns f =
  mapMaybe $ \x -> let rid = f x in (,) rid `fmap` M.lookup rid (nsRouters ns)

-- | Replace the current network state with a new network state.
modifyNetworkState :: NetworkState -> StateT ManagerState IO ()
modifyNetworkState ns = do
  liftIO $ swapMVar networkStateMV $! ns
  modify' $ \s -> s { networkState = ns }

-- | Read the current network state.
readNetworkState :: IO NetworkState
readNetworkState = readMVar networkStateMV

--------------------------------------------------------------------------------
-- Tor controller

-- | Attempt to start the Tor controller, given a delay in seconds to wait
-- before trying again if starting it fails. If starting the controller fails,
-- return the 'ThreadId' of a timer thread counting down until the next attempt
-- to start the controller. Also return the next delay period, subject to an
-- exponential backoff. If starting the controller succeeds, return its
-- 'ThreadId'.
startTorController
  :: MonadIO m => NetworkStateManager -> NetworkStateManagerConfig -> Maybe Int
  -> m (Either (ThreadId, Int) Connection, ThreadId)
startTorController net conf mbDelay = liftIO $ do
  log Info "Starting Tor controller."
  (r,tid) <- tryForkLinkIO $ do
    E.bracketOnError (socket AF_INET Stream tcpProtoNum)
                     (ignoreJust syncExceptions . sClose) $ \sock -> do
      connect sock $ nsmcfTorControlAddr conf
      E.bracketOnError
        (do handle <- socketToHandle sock ReadWriteMode
            openConnection handle $ nsmcfTorControlPasswd conf)
        (ignoreJust syncExceptions . closeConnection) $ \conn -> do
          setConfWithRollback fetchUselessDescriptors (Just True) conn
          when (torVersion (protocolInfo conn) >= TorVersion 0 2 0 13 B.empty) $
            setConfWithRollback fetchDirInfoEarly (Just True) conn

          let newNS = networkStatusEvent $ \errors ns -> do
                logTorControlErrors "NS" errors
                updateNetworkStatus net ns
              newDesc = flip newDescriptorsEvent conn $ \errors ds -> do
                logTorControlErrors "NewDesc" errors
                updateDescriptors net ds
          registerEventHandlers [newNS, newDesc] conn

          getNetworkStatus conn >>= logParseErrors >>= updateNetworkStatus net
          getAllDescriptors conn >>= logParseErrors >>= updateDescriptors net

          return conn
  case r of
    Left reason -> do
      log Warn "Initializing Tor controller connection failed: "
                (showExitReason [showTorControlError] reason)
                "; I'll try again in " delay " seconds."
      timerTid <- forkLinkIO $ threadDelay (delay * 10^6)
      return (Left (timerTid, nextDelay), tid)
    Right conn -> do
      log Info "Successfully initialized Tor controller connection."
      return (Right conn, tid)
  where
    logTorControlErrors event = mapM_ (log Warn "Error in " event " event: ")
    logParseErrors (xs,errors) = mapM_ (log Warn) errors >> return xs
    updateDescriptors (NetworkStateManager send _) = send . NewDescriptors
    updateNetworkStatus (NetworkStateManager send _) = send . NewNetworkStatus
    nextDelay | delay' < maxDelay = delay'
              | otherwise          = maxDelay
    delay' = delay * backoffFactor
    delay = fromMaybe minDelay mbDelay
    backoffFactor = 2
    minDelay = 3
    maxDelay = 300

--------------------------------------------------------------------------------
-- Exit tests

-- | The initial exit test server config.
initExitTestServerConfig
  :: NetworkStateManager -> ExitTestConfig -> ExitTestServerConfig
initExitTestServerConfig net conf = ExitTestServerConfig
  { etscfNotifyNewExitAddress = updateExitAddress net
  , etscfConcClientLimit = etcfConcClientLimit conf
  , etscfListenAddrs = M.keysSet $ etcfListeners conf }
  where
    updateExitAddress (NetworkStateManager send _) tested cookie address =
      send $ NewExitAddress tested cookie address

-- | The initial exit test initiator config.
initExitTestInitiatorConfig
  :: NetworkStateManager -> ExitTestConfig -> ExitTestInitiatorConfig
initExitTestInitiatorConfig net conf = ExitTestInitiatorConfig
  { eticfGetNetworkState = readNetworkState
  , eticfWithCookie = withCookie net (etcfGetRandBytes conf)
  , eticfConcClientLimit = etcfConcClientLimit conf
  , eticfSocksServer = etcfTorSocksAddr conf
  , eticfTestAddress = etcfTestAddress conf
  , eticfTestPorts = etcfTestPorts conf }

-- | Enable exit testing by starting the storage manager, merging exit addresses
-- from the store into the current network state, starting the exit test server,
-- and starting the exit test initiator.
initializeExitTests :: NetworkStateManager -> FilePath -> ExitTestConfig
                    -> StateT ManagerState IO ExitTestInitiator
initializeExitTests net stateDir conf = do
  log Info "Initializing exit tests."
  storage <- liftIO . startStorageManager $ StorageConfig stateDir
  exitAddrs <- liftIO $ readExitAddressesFromStorage storage
  now <- liftIO getCurrentTime
  modify' $ \s -> s { networkState = expireOldInfo now .
                       mergeExitAddrsWithNetState exitAddrs . networkState $ s }
  routers <- gets (nsRouters . networkState)
  liftIO $ rebuildExitAddressStorage routers storage
  testServer <- liftIO $ startExitTestServer (M.assocs $ etcfListeners conf)
                                             (initExitTestServerConfig net conf)
  testInitiator <- liftIO . startExitTestInitiator $
                     initExitTestInitiatorConfig net conf
  let newTestState = ExitTestState storage testServer testInitiator M.empty
  modify' $ \s -> s { exitTestState = Just $! newTestState }
  return testInitiator

-- | Terminate all the threads enabling and supporting exit tests.
terminateExitTests :: ExitTestState -> StateT ManagerState IO ()
terminateExitTests testState = do
  log Info "Halting exit tests."
  liftIO $ do
    terminateExitTestInitiator Nothing $ exitTestInitiator testState
    terminateExitTestServer Nothing $ exitTestServer testState
    terminateStorageManager Nothing $ storageManager testState
  modify' $ \s ->
    s { exitTestState = Nothing
      , deadThreads = foldl' (flip S.insert) (deadThreads s)
                             [ threadId $ exitTestInitiator testState
                             , threadId $ exitTestServer testState
                             , threadId $ storageManager testState ] }

--------------------------------------------------------------------------------
-- Pure network state updates

-- | Merge a list of exit addresses from the store with the network state.
mergeExitAddrsWithNetState :: [ExitAddress] -> NetworkState -> NetworkState
mergeExitAddrsWithNetState = flip $ foldl' mergeAddr where
  mergeAddr (NetworkState addrs rtrs) (ExitAddress rid pub status exits) =
    NetworkState (foldl' insertAddr addrs $ M.keys exits)
                 (alter' updateRouter rid rtrs)
    where
      insertAddr addrs' addr = insertAddress addr rid addrs'
      updateRouter Nothing  = Just initialRouter
      updateRouter (Just r) =
        Just r { rtrTestResults = mergeTestResults (rtrTestResults r) }
      mergeTestResults Nothing    = Just $! initialTestResults
      mergeTestResults (Just old) =
        Just $! TestResults (pub `max` tstPublished old)
                            (M.unionWith max (tstAddresses old) exits)
      initialRouter = Router Nothing (Just $! initialTestResults) False status
      initialTestResults = TestResults pub exits

-- | Update the network state with the results of an exit test. Return the
-- updated router information.
newExitAddress
  :: UTCTime -> UTCTime -> Router -> RouterID -> HostAddress -> NetworkState
  -> (Router, NetworkState)
newExitAddress tested published r rid addr s
  | Just test <- rtrTestResults r
  = results $ TestResults (tstPublished test `max` published)
                          (M.insert addr tested $ tstAddresses test)
  | otherwise = results $ TestResults published (M.singleton addr tested)
  where
    results test = (id &&& s') r { rtrTestResults = Just $! test }
    s' !r' = s { nsAddrs   = insertAddress addr rid (nsAddrs s)
               , nsRouters = M.insert rid r' (nsRouters s) }

-- | Update the network state with a new router descriptor.
newDescriptor :: UTCTime -> NetworkState -> Descriptor -> NetworkState
newDescriptor now s !newD
  -- we know about this router already, but we might not have its descriptor
  | Just router <- M.lookup rid (nsRouters s)
  = case rtrDescriptor router of
      -- we have a descriptor, and therefore a possibly outdated address
      Just oldD
        -- the descriptor we already have is newer than this one
        | descPublished oldD > descPublished newD -> s
        -- address changed: delete old address, insert new address
        | descListenAddr newD /= descListenAddr oldD ->
            s { nsAddrs   = insertAddr newD . deleteAddr oldD . nsAddrs $ s
              , nsRouters = updateRoutersTests (descListenAddr oldD) }
        -- address hasn't changed: don't update addrs
        | otherwise -> s { nsRouters = updateRouters }
      -- we didn't have an address before: insert new address
      _ -> s { nsAddrs   = insertAddr newD (nsAddrs s)
             , nsRouters = updateRouters }
  -- this is a new router: insert into routers and addrs
  | otherwise = s { nsAddrs   = insertAddr newD (nsAddrs s)
                  , nsRouters = insertRouters }
  where
    updateRouters =
      adjust' (\r -> r { rtrDescriptor = Just newD }) rid (nsRouters s)
    updateRoutersTests oldAddr =
      adjust' (\r -> r { rtrDescriptor = Just newD
                       , rtrTestResults = updateTests oldAddr r })
              rid (nsRouters s)
    updateTests oldAddr (Router _ (Just test) _ _)
      | not (M.null addrs') = Just $! test { tstAddresses = addrs' }
      where addrs' = M.delete oldAddr (tstAddresses test)
    updateTests _ _ = Nothing
    insertRouters =
      mapInsert' rid (Router (Just newD) Nothing False now) (nsRouters s)
    insertAddr d = insertAddress (descListenAddr d) rid
    deleteAddr d = deleteAddress (descListenAddr d) rid
    rid = descRouterID newD

-- | Update the network state with a new router status entry.
newRouterStatus :: UTCTime -> NetworkState -> RouterStatus -> NetworkState
newRouterStatus now s rs =
  s { nsRouters = alter' (Just . maybe newRouter updateRouter)
                         (rsRouterID rs) (nsRouters s) }
  where
    newRouter = Router Nothing Nothing (rsIsRunning rs) now
    updateRouter r = r { rtrIsRunning = rsIsRunning rs, rtrLastStatus = now }

-- | Discard routers whose last status update was received more than
-- @maxRouterAge@ seconds ago and exit test results older than @maxExitTestAge@.
expireOldInfo :: UTCTime -> NetworkState -> NetworkState
expireOldInfo now s = s { nsAddrs = addrs'', nsRouters = routers'' }
  where
    (addrs'',routers'') = M.mapAccumWithKey updateTests addrs' routers'
    updateTests addrs rid r@(Router d (Just test) _ _)
      | M.null oldExits    = (addrs, r)
      | M.null recentExits = update Nothing
      | otherwise          = update (Just $! test {tstAddresses = recentExits})
      where
        update test' = (recentAddrs, r { rtrTestResults = test' })
        recentAddrs =
          foldl' (\as addr -> deleteAddress addr rid as) addrs
                 (M.keys $ maybe id (M.delete . descListenAddr) d oldExits)
        (oldExits,recentExits) = M.partition isTestOld (tstAddresses test)
    updateTests addrs _ r = (addrs, r)
    (oldRouters,routers') = M.partition isRouterOld (nsRouters s)
    addrs' = foldl' deleteAddrs (nsAddrs s) (M.toList oldRouters)
    isRouterOld r = now `diffUTCTime` rtrLastStatus r > maxRouterAge
    isTestOld tested = now `diffUTCTime` tested > maxExitTestAge
    deleteAddrs addrs (rid,r) =
      maybe id (\d -> deleteAddress (descListenAddr d) rid) (rtrDescriptor r) .
      maybe id (deleteExitAddresses rid) (rtrTestResults r) $ addrs
    deleteExitAddresses rid test addrs =
      foldl' (\as addr -> deleteAddress addr rid as) addrs
             (M.keys $ tstAddresses test)
    maxRouterAge = 24 * 60 * 60
    maxExitTestAge = 24 * 60 * 60

-- | Add a new router associated with an address to the address map.
insertAddress :: HostAddress -> RouterID -> Map HostAddress (Set RouterID)
              -> Map HostAddress (Set RouterID)
insertAddress addr !rid =
  alter' (Just . maybe (S.singleton rid) (S.insert rid)) addr

-- | Remove a router associated with an address from the address map.
deleteAddress :: HostAddress -> RouterID -> Map HostAddress (Set RouterID)
              -> Map HostAddress (Set RouterID)
deleteAddress addr rid = update' deleteRouterID addr
  where
    deleteRouterID set
      | S.null set' = Nothing
      | otherwise   = Just set'
      where set' = S.delete rid set

--------------------------------------------------------------------------------
