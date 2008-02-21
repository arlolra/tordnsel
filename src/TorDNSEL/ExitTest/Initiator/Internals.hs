{-# LANGUAGE PatternGuards, BangPatterns, Rank2Types #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitTest.Initiator.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions, pattern guards,
--                             bang patterns, rank-2 types, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- A thread that initiates test connections through exit nodes to determine the
-- IP addresses they exit through.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.ExitTest.Initiator.Internals (
    ExitTestInitiator(..)
  , InitiatorMessage(..)
  , ExitTestInitiatorConfig(..)
  , InitiatorState(..)
  , TestStatus(..)
  , startExitTestInitiator
  , handleMessage
  , notifyNewDirInfo
  , scheduleNextExitTest
  , reconfigureExitTestInitiator
  , terminateExitTestInitiator

  -- * Scheduling exit tests
  , testsToSchedule
  , testsToExecute

  -- * Threads
  , forkTestClient
  , forkTestTimer
  , forkPeriodicTestTimer

  -- * Exit test history
  , historyRetentionPeriod
  , maxTestInterval
  , TestHistoryEntry(..)
  , TestHistory(..)
  , emptyTestHistory
  , appendTestsToHistory
  , removeExpiredTests
  , currentTestInterval
  ) where

import Prelude hiding (log)
import Control.Arrow (first, second)
import Control.Concurrent (threadDelay)
import Control.Concurrent.Chan (Chan, newChan, writeChan, readChan)
import qualified Control.Exception as E
import Control.Monad (replicateM_, guard)
import qualified Data.ByteString.Char8 as B
import Data.Dynamic (fromDynamic)
import qualified Data.Foldable as F
import Data.List (foldl', unfoldr, mapAccumL)
import qualified Data.Map as M
import Data.Map (Map)
import Data.Maybe (mapMaybe, isJust)
import qualified Data.Sequence as Seq
import Data.Sequence (Seq, ViewL((:<)), viewl, (<|), (|>), ViewR((:>)), viewr)
import qualified Data.Set as Set
import Data.Set (Set)
import Data.Time (UTCTime, NominalDiffTime, getCurrentTime, addUTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Network.Socket
  ( HostAddress, SockAddr, Family(AF_INET), SocketType(Stream)
  , socket, connect, sClose, socketToHandle )
import System.IO (hClose, IOMode(ReadWriteMode))

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.Directory
import qualified TorDNSEL.DistinctQueue as Q
import TorDNSEL.DistinctQueue (DistinctQueue)
import TorDNSEL.ExitTest.Request
import TorDNSEL.Log
import TorDNSEL.NetworkState.Types
import TorDNSEL.Socks
import TorDNSEL.System.Timeout
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Exit test initiator

-- | A handle to the exit test initiator thread.
data ExitTestInitiator = ExitTestInitiator (InitiatorMessage -> IO ()) ThreadId

instance Thread ExitTestInitiator where
  threadId (ExitTestInitiator _ tid) = tid

-- | An internal type for messages sent to the exit test initiator.
data InitiatorMessage
  -- | Use new directory information to schedule exit tests.
  = NewDirInfo [(RouterID, Router)]
  -- | Place a router at the front of the exit test queue.
  | ScheduleNextExitTest RouterID
  -- | Reconfigure the exit test initiator.
  | Reconfigure (ExitTestInitiatorConfig -> ExitTestInitiatorConfig) (IO ())
  | Terminate ExitReason -- ^ Terminate the exit test initiator gracefully.
  -- | An exit signal sent to the exit test initiator.
  | Exit ThreadId ExitReason

-- | The exit test initiator configuration.
data ExitTestInitiatorConfig = ExitTestInitiatorConfig
  { -- | An action for fetching the current network state.
    eticfGetNetworkState :: !(IO NetworkState),
    -- | A safe wrapper for allocating an exit test cookie.
    eticfWithCookie      :: !(forall a. RouterID -> UTCTime -> Port ->
                              (Cookie -> IO a) -> IO a),
    -- | The maximum number of exit test clients to run concurrently.
    eticfConcClientLimit :: !Integer,
    -- | Where Tor is listening for SOCKS connections.
    eticfSocksServer     :: !SockAddr,
    -- | The IP address to which we make exit test connections through Tor.
    eticfTestAddress     :: !HostAddress,
    -- | The ports to which we make exit test connections through Tor.
    eticfTestPorts       :: ![Port] }

-- | An internal type representing the current exit test initiator state.
data InitiatorState = InitiatorState
  { initiatorChan     :: !(Chan InitiatorMessage)
  , runningClients    :: !(Set ThreadId)
  , pendingTests      :: !(DistinctQueue RouterID)
  , testHistory       :: !TestHistory
  , testStatus        :: !TestStatus
  , periodicTestTimer :: !ThreadId }

-- | The status of the next scheduled exit test.
data TestStatus
  = TimerRunning !ThreadId -- ^ We're waiting for a timer to expire.
  | TestWaiting !RouterID ![Port] !UTCTime -- ^ Run this test next.
  | NoTestsPending -- ^ No timer is currently running.
  deriving Eq

-- | Start the exit test initiator thread, given an initial config. Return a
-- handle to the thread. Link the exit test initiator thread to the calling
-- thread.
startExitTestInitiator :: ExitTestInitiatorConfig -> IO ExitTestInitiator
startExitTestInitiator initConf = do
  log Notice "Starting exit test initiator."
  chan <- newChan
  initiatorTid <- forkLinkIO $ do
    setTrapExit ((writeChan chan .) . Exit)
    tid <- forkPeriodicTestTimer
    loop initConf $ InitiatorState chan Set.empty Q.empty emptyTestHistory
                                   NoTestsPending tid
  return $ ExitTestInitiator (writeChan chan) initiatorTid
  where
    -- An exit test can be run immediately if forking its test clients would
    -- keep the number of currently running clients below eticfConcClientLimit.
    canRunExitTest conf s ports =
      toInteger (Set.size (runningClients s) + length ports) <=
        eticfConcClientLimit conf

    loop !conf !s
      | TestWaiting rid ports published <- testStatus s
      , canRunExitTest conf s ports = do
          log Info "Forking exit test clients for router " rid
                   " ports " ports '.'
          newClients <- mapM (forkTestClient conf rid published) ports
          let newRunningClients = foldl' (flip Set.insert) (runningClients s)
                                         newClients
          log Info "Exit test clients currently running: "
                   (Set.size newRunningClients) '.'
          if Q.length (pendingTests s) == 0
            then do
              log Info "Pending exit tests: 0."
              loop conf s { runningClients = newRunningClients
                          , testStatus = NoTestsPending }
            else do
              now <- getCurrentTime
              let newS = s { runningClients = newRunningClients
                           , testHistory = removeExpiredTests now $
                                             testHistory s }
              tid <- forkTestTimer newS
              loop conf newS { testStatus = TimerRunning tid }
      | otherwise
      = readChan (initiatorChan s) >>= handleMessage conf s >>= uncurry loop

-- | Process an 'InitiatorMessage' and return the new config and state, given
-- the current config and state. Only 'Reconfigure' returns a changed config.
handleMessage
  :: ExitTestInitiatorConfig -> InitiatorState -> InitiatorMessage
  -> IO (ExitTestInitiatorConfig, InitiatorState)
handleMessage conf s (NewDirInfo routers)
  | nRouterTests == 0 = return (conf, s)
  | otherwise = do
      log Info "Scheduling exit tests for " nRouterTests " routers."
      now <- getCurrentTime
      let newS = s { pendingTests = newPendingTests
                   , testHistory = appendTestsToHistory now nRouterTests .
                                     removeExpiredTests now $ testHistory s }
      if testStatus s == NoTestsPending
        then do
          tid <- forkTestTimer newS
          return (conf, newS { testStatus = TimerRunning tid })
        else return (conf, newS)
  where
    (newPendingTests,nRouterTests) = second (toInteger . length . filter id) $
      mapAccumL ((swap .) . flip Q.enqueue) (pendingTests s)
                (testsToSchedule conf routers)

handleMessage conf s (ScheduleNextExitTest rid)
  | not testAdded = return (conf, s)
  | otherwise = do
      now <- getCurrentTime
      let newS = s { pendingTests = newPendingTests
                   , testHistory = removeExpiredTests now $ testHistory s }
      if testStatus s == NoTestsPending
        then do
          tid <- forkTestTimer newS
          return (conf, newS { testStatus = TimerRunning tid })
        else return (conf, newS)
  where (testAdded,newPendingTests) = Q.unGetQueue rid (pendingTests s)

handleMessage conf s (Reconfigure reconf signal) =
  signal >> return (reconf conf, s)

handleMessage _ s (Terminate reason) = do
  log Notice "Terminating exit test initiator."
  F.forM_ (runningClients s) $ \client ->
    terminateThread Nothing client (killThread client)
  exit reason

handleMessage conf s (Exit tid reason)
  | tid `Set.member` runningClients s
  = return (conf, s { runningClients = Set.delete tid (runningClients s) })
  -- Run the next queued exit test, if any are still eligible for testing.
  | TimerRunning timerThread <- testStatus s
  , tid == timerThread = do
      routers <- nsRouters `fmap` eticfGetNetworkState conf
      case testsToExecute conf routers (pendingTests s) of
        Nothing -> do
          log Info "Pending exit tests: 0."
          return (conf, s { pendingTests = Q.empty
                          , testStatus = NoTestsPending })
        Just (rid,ports,published,newPendingTests) -> do
          log Info "Pending exit tests: " (Q.length newPendingTests + 1) '.'
          log Debug "Waiting to run exit test for router " rid
                    " ports " ports '.'
          return (conf, s { pendingTests = newPendingTests
                          , testStatus = TestWaiting rid ports published })
  -- Periodically, add every eligible router to the exit test queue. This should
  -- catch some routers for which previous exit tests failed.
  | tid == periodicTestTimer s = do
      (_,newS) <- handleMessage conf s . NewDirInfo . M.assocs . nsRouters
                    =<< eticfGetNetworkState conf
      newTid <- forkPeriodicTestTimer
      return (conf, newS { periodicTestTimer = newTid })
  | isJust reason = exit reason
  | otherwise = return (conf, s)

-- | Notify the exit test initiator of new directory information.
notifyNewDirInfo :: [(RouterID, Router)] -> ExitTestInitiator -> IO ()
notifyNewDirInfo routers (ExitTestInitiator send _) = send $ NewDirInfo routers

-- | Schedule a router for immediate exit testing, placing it ahead of any
-- already-queued routers.
scheduleNextExitTest :: RouterID -> ExitTestInitiator -> IO ()
scheduleNextExitTest rid (ExitTestInitiator send _) =
  send $ ScheduleNextExitTest rid

-- | Reconfigure the exit test initiator synchronously with the given function.
-- If the initiator exits abnormally before reconfiguring itself, throw its exit
-- signal in the calling thread.
reconfigureExitTestInitiator
  :: (ExitTestInitiatorConfig -> ExitTestInitiatorConfig) -> ExitTestInitiator
  -> IO ()
reconfigureExitTestInitiator reconf (ExitTestInitiator send tid) =
  sendSyncMessage (send . Reconfigure reconf) tid

-- | Terminate the exit test initiator gracefully. The optional parameter
-- specifies the amount of time in microseconds to wait for the thread to
-- terminate. If the thread hasn't terminated by the timeout, an uncatchable
-- exit signal will be sent.
terminateExitTestInitiator :: Maybe Int -> ExitTestInitiator -> IO ()
terminateExitTestInitiator mbWait (ExitTestInitiator send tid) =
  terminateThread mbWait tid (send $ Terminate Nothing)

--------------------------------------------------------------------------------
-- Scheduling exit tests

-- | Given a list of routers that should be considered for exit testing, return
-- a list of routers that should be added to the exit test queue.
testsToSchedule :: ExitTestInitiatorConfig -> [(RouterID, Router)] -> [RouterID]
testsToSchedule conf routers =
  [rid | (rid,rtr) <- routers, isEligibleForTesting rtr]
  where
    -- A router is eligible for being added to the exit test queue if it's
    -- marked running, we have its descriptor, and we haven't completed any
    -- exit tests through it since we received its current descriptor.
    isEligibleForTesting r
      | not $ rtrIsRunning r = False
      | otherwise = case rtrDescriptor r of
          Nothing -> False
          Just d
            | Just t <- rtrTestResults r
            , tstPublished t >= posixSecondsToUTCTime (descPublished d) -> False
            | otherwise -> anyAllowedPorts (descExitPolicy d)

    anyAllowedPorts policy =
      any (\port -> exitPolicyAccepts (eticfTestAddress conf) port policy)
          (eticfTestPorts conf)

-- | Given the current network state and the queue of pending exit tests, return
-- the router identifier, ports, and descriptor publication time of the next
-- exit test we should execute. Also return the new queue of pending tests. If
-- none of the routers in the pending test queue are still eligible for testing,
-- return 'Nothing'.
testsToExecute
  :: ExitTestInitiatorConfig -> Map RouterID Router -> DistinctQueue RouterID
  -> Maybe (RouterID, [Port], UTCTime, DistinctQueue RouterID)
testsToExecute conf routers q
  -- Take the first scheduled router that's still eligible for testing.
  | test:_ <- mapMaybe toTest $ queueTails q = Just test
  | otherwise                                = Nothing
  where
    -- A router is eligible for immediate exit testing if it's marked running,
    -- we have its descriptor, and its exit policy allows connections to at
    -- least one of our listening ports.
    toTest (rid,q') = do
      r <- M.lookup rid routers
      guard $ rtrIsRunning r
      d <- rtrDescriptor r
      ports'@(_:_) <- return . allowedPorts $ descExitPolicy d
      return (rid, ports', posixSecondsToUTCTime $ descPublished d, q')

    allowedPorts policy =
      filter (\port -> exitPolicyAccepts (eticfTestAddress conf) port policy)
             (eticfTestPorts conf)

    queueTails = unfoldr (maybe Nothing (\r@(_,q') -> Just (r,q')) . Q.dequeue)

--------------------------------------------------------------------------------
-- Threads

-- | Fork an exit test client thread for a given router identifier, descriptor
-- publication time, and port. The exit test client associates a new cookie with
-- the test information and passes it to the exit test server with an HTTP
-- request through Tor.
forkTestClient
  :: ExitTestInitiatorConfig -> RouterID -> UTCTime -> Port -> IO ThreadId
forkTestClient conf rid published port =
  forkLinkIO $ do
    r <- E.tryJust clientExceptions .
      eticfWithCookie conf rid published port $ \cookie ->
        timeout connectionTimeout .
          E.bracket connectToSocksServer hClose $ \handle ->
            withSocksConnection handle (Addr exitHost) port $ do
              B.hPut handle $ createRequest testHost port cookie
              B.hGet handle 1024 -- ignore response
              return ()
    case r of
      Left e@(E.DynException d) | Just (e' :: SocksError) <- fromDynamic d -> do
        log Info "Exit test for router " rid " port " port " failed: " e'
        E.throwIO e
      Left e -> do
        log Warn "Exit test for router " rid " port " port " failed : " e
                 ". This might indicate a problem with making application \
                 \connections through Tor. Is Tor running? Is its SocksPort \
                 \listening on " (eticfSocksServer conf) '?'
        E.throwIO e
      Right Nothing ->
        log Info "Exit test for router " rid " port " port " timed out."
      _ ->
        log Debug "Exit test client for router " rid " port " port " finished."
  where
    exitHost = B.concat [ testHost, b 1 "."#, encodeBase16RouterID rid
                        , b 5 ".exit"# ]
    testHost = B.pack . inet_htoa . eticfTestAddress $ conf

    connectToSocksServer =
      E.bracketOnError (socket AF_INET Stream tcpProtoNum) sClose $ \sock -> do
        connect sock (eticfSocksServer conf)
        socketToHandle sock ReadWriteMode

    clientExceptions e@(E.DynException d)
      | Just (_ :: SocksError) <- fromDynamic d = Just e
    clientExceptions e@(E.IOException _)        = Just e
    clientExceptions _                          = Nothing

    connectionTimeout = 120 * 10^6

    b = B.unsafePackAddress

-- | Fork a timer thread for the next exit test, returning its 'ThreadId'.
forkTestTimer :: InitiatorState -> IO ThreadId
forkTestTimer s = forkLinkIO $ do
  log Debug "Total routers scheduled in exit test history: "
            (nTotalRouters $ testHistory s) ". "
            (show . F.toList . historySeq $ testHistory s)
  log Info "Running next exit test in " currentInterval " microseconds."
  threadDelay $ fromIntegral currentInterval
  where
    currentInterval = currentTestInterval nPending (testHistory s)
    nPending = toInteger . Q.length . pendingTests $ s

-- | Fork a timer thread for periodic exit tests, returning its 'ThreadId'.
forkPeriodicTestTimer :: IO ThreadId
forkPeriodicTestTimer =
  forkLinkIO . replicateM_ 2 $ threadDelay halfPeriodicTestInterval
  where halfPeriodicTestInterval = 30 * 60 * 10^6

--------------------------------------------------------------------------------
-- Exit test history

-- | The period from which we consider past scheduled exit tests when
-- calculating the current interval between tests.
historyRetentionPeriod :: NominalDiffTime
historyRetentionPeriod = 150 * 60

-- | The maximum interval in microseconds between running scheduled exit tests.
maxTestInterval :: Integer
maxTestInterval = 20 * 10^6

-- | A record of when a single set of exit tests were scheduled in the test
-- history.
data TestHistoryEntry = TestHistoryEntry
  { scheduledAt :: !UTCTime -- ^ When the tests were added to the queue.
  , nRouters    :: !Integer -- ^ The number of routers added to the queue.
  }

instance Show TestHistoryEntry where
  showsPrec _ entry = cat (nRouters entry) '@' (showUTCTime $ scheduledAt entry)

-- | An abstract type representing a persistent record of how many exit tests
-- were scheduled in the last 'historyRetentionPeriod' seconds.
data TestHistory = TestHistory
  { -- | The total number of routers added to the queue in the test history.
    nTotalRouters :: !Integer,
    -- | The rolling sequence of recently scheduled exit tests.
    historySeq    :: !(Seq TestHistoryEntry) }

-- | The empty test history.
emptyTestHistory :: TestHistory
emptyTestHistory = TestHistory 0 Seq.empty

-- | Given the current time and a count of exit tests being added to the pending
-- test queue, add those tests to the test history
appendTestsToHistory :: UTCTime -> Integer -> TestHistory -> TestHistory
appendTestsToHistory _ 0 history = history
appendTestsToHistory now nTests history
  -- If the latest history entry was added in the last 5 minutes, attribute new
  -- tests to it. This prevents bloating the test history length with
  -- unnecessarily fine-grained information.
  | history' :> latestEntry <- viewr (historySeq history)
  , scheduledAt latestEntry > addUTCTime (negate entryMergePeriod) now
  = let updatedEntry = latestEntry { nRouters = nTests + nRouters latestEntry }
    in newHistory { historySeq = history' |> updatedEntry }
  | otherwise
  = let newEntry = TestHistoryEntry { scheduledAt = now, nRouters = nTests }
    in newHistory { historySeq = historySeq history |> newEntry }
  where
    newHistory = history { nTotalRouters = nTests + nTotalRouters history }
    entryMergePeriod = 300

-- | Remove the record of exit tests older than 'historyRetentionPeriod' from
-- the test history, given the current time.
removeExpiredTests :: UTCTime -> TestHistory -> TestHistory
removeExpiredTests now history
  | Seq.length expired > 0
  = history { nTotalRouters = nTotalRouters history -
                                F.sum (fmap nRouters expired)
            , historySeq = rest }
  | otherwise = history
  where
    (expired,rest) = spanL ((< cutoff) . scheduledAt) $ historySeq history
    cutoff = addUTCTime (negate historyRetentionPeriod) now
    spanL p xxs
      | x :< xs <- viewl xxs, p x = first (x <|) $ spanL p xs
      | otherwise                 = (Seq.empty, xxs)

-- | Given the number of pending exit tests in the test queue and the test
-- history, return the interval of time in microseconds we should wait before
-- running the next exit test.
currentTestInterval :: Integer -> TestHistory -> Integer
currentTestInterval nPendingTests history
  | nConsideredTests == 0 = maxTestInterval
  | otherwise             = testInterval `min` maxTestInterval
  where
    -- The idea here is to schedule a historyRetentionPeriod's worth of exit
    -- tests in 25% of a 'historyRetentionPeriod'.
    testInterval = touSec historyRetentionPeriod `div` nConsideredTests `div` 4
    nConsideredTests = nTotalRouters history `max` nPendingTests
    touSec = truncate . (10^6 *)
