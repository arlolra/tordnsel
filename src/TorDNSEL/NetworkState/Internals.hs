{-# LANGUAGE PatternGuards #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, STM, pattern guards)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Managing our current view of the Tor network. The network state constantly
-- changes as we receive new router information from Tor and new exit test
-- results.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.NetworkState.Internals (
  -- * Network state
    Network(..)
  , newNetwork
  , NetworkState(..)
  , emptyNetworkState
  , Router(..)
  , TestResults(..)

  -- * State events
  , updateDescriptors
  , updateNetworkStatus
  , withCookie
  , updateExitAddress
  , readNetworkState
  , StateEvent(..)
  , TestState(..)
  , stateEventHandler
  , eventHandler
  , testingEventHandler
  , isTestable
  , newExitAddress
  , newDescriptor
  , newRouterStatus
  , expireOldInfo
  , insertAddress
  , deleteAddress

  -- * Exit list queries
  , ExitListQuery(..)
  , isExitNode
  , isRunning

  -- * Exit tests
  , ExitTestChan(..)
  , newExitTestChan
  , addExitTest
  , isReadingExitTestChan
  , ExitTestConfig(..)
  , bindListeningSocket
  , startTestListeners
  , startExitTests

  -- ** HTTP requests
  , createRequest
  , parseRequest

  -- ** Cookies
  , Cookie(..)
  , newCookie
  , cookieLen

  -- ** Exit test result storage
  , ExitAddress(..)
  , renderExitAddress
  , parseExitAddress
  , readExitAddresses
  , replaceExitAddresses
  , mkExitAddress
  , appendExitAddressToJournal
  , isJournalTooLarge

  -- * Helpers
  , b
  ) where

import Control.Arrow ((&&&))
import Control.Monad (liftM, liftM2, forM_, replicateM_, guard)
import Control.Monad.Error (MonadError(..))
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.MVar
  (MVar, newMVar, readMVar, swapMVar, withMVar, isEmptyMVar)
import Control.Concurrent.STM (atomically)
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (toLower, toUpper, isSpace)
import Data.Dynamic (fromDynamic)
import Data.List (foldl', sortBy)
import Data.Maybe (mapMaybe)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Sequence as Seq
import Data.Sequence (Seq, (<|), (|>), viewr, ViewR(..))
import qualified Data.Set as S
import Data.Set (Set)
import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import Data.Time.Clock.POSIX (POSIXTime, posixSecondsToUTCTime)
import Network.Socket
  ( Socket, HostAddress, SockAddr(SockAddrInet), Family(AF_INET)
  , SocketOption(ReuseAddr), SocketType(Stream), socket, connect, bindSocket
  , listen, accept, setSocketOption, sOMAXCONN, socketToHandle, sClose )
import System.Directory (renameFile)
import System.IO
  (Handle, hClose, IOMode(ReadWriteMode, WriteMode), hFlush, openFile)
import System.Posix.Files (getFileStatus, fileSize)

import GHC.Prim (Addr#)

import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Random
import TorDNSEL.Socks
import TorDNSEL.System.Timeout
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Network state

-- | An abstract type supporting the interface to reading and updating the
-- network state.
data Network = Network
  { -- | A channel over which state changes are sent.
    nChan  :: {-# UNPACK #-} !(Chan StateEvent)
    -- | The network state shared with an 'MVar'. This 'MVar' is read-only from
    -- the point of view of other threads. It exists to overcome a performance
    -- problem with pure message passing.
  , nState :: {-# UNPACK #-} !(MVar NetworkState) }

-- | Create a new network event handler given the exit test chan and the path to
-- our state directory. This should only be called once.
newNetwork :: Maybe (ExitTestChan, FilePath, ExitPolicy -> Bool) -> IO Network
newNetwork testConf = do
  net <- liftM2 Network newChan (newMVar emptyNetworkState)
  forkIO $ stateEventHandler net testConf
  return net

-- | Our current view of the Tor network.
data NetworkState = NetworkState
  { -- | A map from listen address to routers.
    nsAddrs   :: {-# UNPACK #-} !(Map HostAddress (Set RouterID)),
    -- | All the routers we know about.
    nsRouters :: {-# UNPACK #-} !(Map RouterID Router) }

-- | The empty network state.
emptyNetworkState :: NetworkState
emptyNetworkState = NetworkState M.empty M.empty

-- | A Tor router.
data Router = Router
  { -- | This router's descriptor, if we have it yet.
    rtrDescriptor  :: {-# UNPACK #-} !(Maybe Descriptor),
    -- | This router's exit test results, if one has been completed.
    rtrTestResults :: {-# UNPACK #-} !(Maybe TestResults),
    -- | Whether we think this router is running.
    rtrIsRunning   :: {-# UNPACK #-} !Bool,
    -- | The last time we received a router status entry for this router.
    rtrLastStatus  :: {-# UNPACK #-} !UTCTime }

-- | The results of exit tests.
data TestResults = TestResults
  { -- | The descriptor's published time when the last exit test was initiated.
    tstPublished :: {-# UNPACK #-} !UTCTime,
    -- | A map from exit address to when the address was last seen.
    tstAddresses :: {-# UNPACK #-} !(Map HostAddress UTCTime) }

--------------------------------------------------------------------------------
-- State events

-- | Update the network state with new router descriptors.
updateDescriptors :: Network -> [Descriptor] -> IO ()
updateDescriptors net = writeChan (nChan net) . NewDesc

-- | Update the network state with new router status entries.
updateNetworkStatus :: Network -> [RouterStatus] -> IO ()
updateNetworkStatus net = writeChan (nChan net) . NewNS

-- | Register a mapping from cookie to fingerprint and descriptor published
-- time, passing the cookie to the given 'IO' action. The cookie is guaranteed
-- to be released when the action terminates.
withCookie :: Network -> Handle -> RouterID -> UTCTime -> Port
           -> (Cookie -> IO a) -> IO a
withCookie net random rid published port =
  E.bracket addNewCookie (writeChan (nChan net) . DeleteCookie)
  where
    addNewCookie = do
      cookie <- newCookie random
      writeChan (nChan net) (AddCookie cookie rid published port)
      return cookie

-- | Update our known exit address from an incoming test connection.
updateExitAddress :: Network -> UTCTime -> Cookie -> HostAddress -> IO ()
updateExitAddress net tested c = writeChan (nChan net) . NewExitAddress tested c

-- | Read the current network state.
readNetworkState :: Network -> IO NetworkState
readNetworkState = readMVar . nState

-- | A message sent to update the network state.
data StateEvent
  -- | New descriptors are available.
  = NewDesc {-# UNPACK #-} ![Descriptor]
  -- | New router status entries are available.
  | NewNS {-# UNPACK #-} ![RouterStatus]
  -- | Discard inactive routers and old exit test results.
  | ExpireOldInfo
  -- | Map a new cookie to an exit node identity, descriptor published time,
  -- and port.
  | AddCookie {-# UNPACK #-} !Cookie  {-# UNPACK #-} !RouterID
              {-# UNPACK #-} !UTCTime {-# UNPACK #-} !Port
  -- | Remove a cookie to exit node identity mapping.
  | DeleteCookie {-# UNPACK #-} !Cookie
  -- | We've received a cookie from an incoming test connection.
  | NewExitAddress {-# UNPACK #-} !UTCTime {-# UNPACK #-} !Cookie
                   {-# UNPACK #-} !HostAddress
  -- | Rebuild the exit addresses storage.
  | ReplaceExitAddresses
  -- | Schedule periodic exit tests.
  | SchedulePeriodicTests
  -- | Run a single scheduled exit test.
  | RunExitTest

-- | An internal type representing the current exit test state.
data TestState = TestState
  { tsTests      :: Seq (RouterID, Maybe Port)
  , tsCookies    :: !(Map Cookie (RouterID, UTCTime, Port))
  , tsAddrLen
  , tsJournalLen :: !Integer
  , tsJournal    :: !Handle }

-- | Receive and carry out state update events.
stateEventHandler
  :: Network -> Maybe (ExitTestChan, FilePath, ExitPolicy -> Bool) -> IO ()
stateEventHandler net testConf = do
  forkIO . forever $ do
    -- check for and discard old routers every 30 minutes
    threadDelay (30 * 60 * 10^6)
    writeChan (nChan net) ExpireOldInfo

  maybe (eventHandler net) (testingEventHandler net) testConf

-- | Handle non-testing events.
eventHandler :: Network -> IO ()
eventHandler net = loop emptyNetworkState
  where
    loop s = do
      event <- readChan $ nChan net
      now <- getCurrentTime
      case event of
        NewDesc ds ->
          let s' = foldl' (newDescriptor now) s ds
          in s' `seq` swapMVar (nState net) s' >> loop s'
        NewNS rss ->
          let s' =  foldl' (newRouterStatus now) s rss
          in s' `seq` swapMVar (nState net) s' >> loop s'
        ExpireOldInfo ->
          let s' = expireOldInfo now s
          in s' `seq` swapMVar (nState net) s' >> loop s'
        _ -> error "unexpected message" -- XXX log this

-- | Handle testing events.
testingEventHandler
  :: Network -> (ExitTestChan, FilePath, ExitPolicy -> Bool) -> IO ()
testingEventHandler net (testChan,stateDir,allowsExit) = do
  -- initialize network state with test results from state directory
  exitAddrs <- readExitAddresses stateDir
  s <- flip expireOldInfo (initialNetState exitAddrs) `fmap` getCurrentTime
  swapMVar (nState net) s

  -- remove old info and merge journal into exit-addresses
  addrLen <- replaceExitAddresses stateDir (nsRouters s)
  journal <- openFile (stateDir ++ "/exit-addresses.new") WriteMode

  forkIO . forever $ do
    -- rebuild exit-addresses every 15 minutes so LastStatus entries
    -- stay up to date
    threadDelay (15 * 60 * 10^6)
    writeChan (nChan net) ReplaceExitAddresses

  forkIO . forever $ do
    -- run periodic tests every 150 minutes
    replicateM_ 5 $ threadDelay (30 * 60 * 10^6)
    writeChan (nChan net) SchedulePeriodicTests

  forkIO . forever $ do
    -- rate-limit exit tests to one router every 3 seconds
    threadDelay (3 * 10^6)
    writeChan (nChan net) RunExitTest

  loop s (TestState Seq.empty M.empty addrLen 0 journal)
  where
    loop ns ts = do
      event <- readChan $ nChan net
      now <- getCurrentTime
      case event of
        NewDesc ds -> do
          let ns' = foldl' (newDescriptor now) ns ds
          ns' `seq` swapMVar (nState net) ns'
          loop ns' ts
            { tsTests = scheduleExitTests (map descRouterID ds) (nsRouters ns')
                                          (tsTests ts) }

        NewNS rss -> do
          let ns' = foldl' (newRouterStatus now) ns rss
          ns' `seq` swapMVar (nState net) ns'
          loop ns' ts
            { tsTests = scheduleExitTests (map rsRouterID rss) (nsRouters ns')
                                          (tsTests ts) }

        SchedulePeriodicTests ->
          let canTest r = rtrIsRunning r && isPeriodicTestable allowsExit now r
              rids = M.keys . M.filter canTest . nsRouters $ ns
          in loop ns ts { tsTests = enqueueTests (tsTests ts) rids }

        RunExitTest -> do
          isReading <- isReadingExitTestChan testChan
          case (isReading, viewr (tsTests ts)) of
            (True, tests :> (rid, port)) -> do
              addExitTest testChan port rid
              loop ns ts { tsTests = tests }
            _ -> loop ns ts

        ExpireOldInfo ->
          let ns' = expireOldInfo now ns
          in ns' `seq` swapMVar (nState net) ns' >> loop ns' ts

        AddCookie c rid published port ->
          loop ns ts { tsCookies = M.insert c (rid, published, port)
                                              (tsCookies ts) }

        DeleteCookie c -> loop ns ts { tsCookies = M.delete c (tsCookies ts) }

        NewExitAddress tested c addr
          | Just (rid,published,port) <- c  `M.lookup` tsCookies ts
          , Just r                    <- rid `M.lookup` nsRouters ns -> do

          let (r',ns') = newExitAddress tested published r rid addr ns
          ns' `seq` swapMVar (nState net) ns'

          -- have we seen this exit address before?
          let ts' = case (M.member addr . tstAddresses) `fmap` rtrTestResults r
               of -- test this port twice more in case exit addresses vary
                  -- the exponential increase in tests should catch more exit
                  -- addresses
                  Just False -> ts { tsTests = tsTests ts |> (rid, Just port)
                                                          |> (rid, Just port) }
                  _          -> ts

          len <- appendExitAddressToJournal (tsJournal ts) rid r'
          if isJournalTooLarge (tsAddrLen ts) (tsJournalLen ts + len)
            then rebuildExitStorage ns' ts' >>= loop ns'
            else loop ns' ts' { tsJournalLen = tsJournalLen ts + len }

          | otherwise -> loop ns ts -- XXX log this

        ReplaceExitAddresses -> rebuildExitStorage ns ts >>= loop ns

    enqueueTests = foldl' (\a x -> (x, Nothing) <| a)

    scheduleExitTests rids routers tests =
      enqueueTests tests (mapMaybe isTestable' rids)
      where
        isTestable' rid = do
          r <- M.lookup rid routers
          guard $ rtrIsRunning r && isTestable allowsExit r
          return rid

    rebuildExitStorage ns ts = do
      hClose $ tsJournal ts
      addrLen <- replaceExitAddresses stateDir (nsRouters ns)
      h <- openFile (stateDir ++ "/exit-addresses.new") WriteMode
      return ts { tsAddrLen = addrLen, tsJournalLen = 0, tsJournal = h }

    initialNetState exitAddrs =
      NetworkState (foldl' insertExits M.empty exitAddrs)
                   (M.fromDistinctAscList $ map initialRouter exitAddrs)
      where
        insertExits addrs (ExitAddress rid _ _ exits) =
          foldl' (\addrs' (addr,_) -> insertAddress addr rid addrs') addrs
                 (M.assocs exits)
        initialRouter (ExitAddress rid pub status exits) =
          (rid, Router Nothing (Just (TestResults pub exits)) False status)

-- | Should a router be added to the test queue?
isTestable :: (ExitPolicy -> Bool) -> Router -> Bool
isTestable allowsExit r =
  case (rtrDescriptor r, rtrTestResults r) of
    (Nothing,_)      -> False
    (Just d,Nothing) -> allowsExit (descExitPolicy d)
    (Just d,Just t)  -> allowsExit (descExitPolicy d) &&
                     -- have we already done a test for this descriptor version?
                        tstPublished t < posixSecondsToUTCTime (descPublished d)

-- | A router is eligible for periodic testing if we have its descriptor and it
-- hasn't been tested in the last @minTestInterval@ seconds.
isPeriodicTestable :: (ExitPolicy -> Bool) -> UTCTime -> Router -> Bool
isPeriodicTestable allowsExit now r
  | Nothing <- rtrDescriptor r                                       = False
  | Just d <- rtrDescriptor r, not . allowsExit . descExitPolicy $ d = False
  | Just t <- rtrTestResults r
  = now `diffUTCTime` (maximum . M.elems . tstAddresses $ t) > minTestInterval
  | otherwise                                                        = True
  where minTestInterval = 60 * 60

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
    results test = (id &&& s') r { rtrTestResults = Just test }
    s' r' = s { nsAddrs   = insertAddress addr rid (nsAddrs s)
              , nsRouters = M.insert rid r' (nsRouters s) }

-- | Update the network state with a new router descriptor.
newDescriptor :: UTCTime -> NetworkState -> Descriptor -> NetworkState
newDescriptor now s newD
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
      M.adjust (\r -> r { rtrDescriptor = Just newD }) rid (nsRouters s)
    updateRoutersTests oldAddr =
      M.adjust (\r -> r { rtrDescriptor = Just newD
                        , rtrTestResults = updateTests oldAddr r })
               rid (nsRouters s)
    updateTests oldAddr (Router _ (Just test) _ _)
      | not (M.null addrs') = Just test { tstAddresses = addrs' }
      where addrs' = M.delete oldAddr (tstAddresses test)
    updateTests _ _ = Nothing
    insertRouters =
      M.insert rid (Router (Just newD) Nothing False now) (nsRouters s)
    insertAddr d = insertAddress (descListenAddr d) rid
    deleteAddr d = deleteAddress (descListenAddr d) rid
    rid = descRouterID newD

-- | Update the network state with a new router status entry.
newRouterStatus :: UTCTime -> NetworkState -> RouterStatus -> NetworkState
newRouterStatus now s rs =
  s { nsRouters = M.alter (Just . maybe newRouter updateRouter)
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
      | otherwise          = update $ Just test { tstAddresses = recentExits }
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
    maxRouterAge = 48 * 60 * 60
    maxExitTestAge = 48 * 60 * 60

-- | Add a new router associated with an address to the address map.
insertAddress :: HostAddress -> RouterID -> Map HostAddress (Set RouterID)
              -> Map HostAddress (Set RouterID)
insertAddress addr rid =
  M.alter (Just . maybe (S.singleton rid) (S.insert rid)) addr

-- | Remove a router associated with an address from the address map.
deleteAddress :: HostAddress -> RouterID -> Map HostAddress (Set RouterID)
              -> Map HostAddress (Set RouterID)
deleteAddress addr rid = M.update deleteRouterID addr
  where
    deleteRouterID set
      | S.null set' = Nothing
      | otherwise   = Just set'
      where set' = S.delete rid set

--------------------------------------------------------------------------------
-- Exit list queries

-- | Queries asking whether there's a Tor exit node at a specific IP address.
data ExitListQuery
  -- |  Query type 1 from
  -- <https://tor.eff.org/svn/trunk/doc/contrib/torel-design.txt>.
  = IPPort
  { -- | The address of the candidate exit node.
    queryAddr :: {-# UNPACK #-} !HostAddress,
    -- | The destination address.
    destAddr  :: {-# UNPACK #-} !HostAddress,
    -- | The destination port.
    destPort  :: {-# UNPACK #-} !Port
  } deriving Eq

instance Show ExitListQuery where
  showsPrec _ (IPPort a c d) = ("query ip: " ++) . (inet_htoa a ++) .
    (" dest ip: " ++) . (inet_htoa c ++) . (" dest port: " ++) . shows d

-- | Does a query represent a Tor exit node cabable of exiting to a particular
-- network service in our current view of the Tor network?
isExitNode :: POSIXTime -> NetworkState -> ExitListQuery -> Bool
{-# INLINE isExitNode #-}
isExitNode now s q = maybe False (any isExit . mapMaybe lookupDesc . S.elems) ns
  where
    ns = queryAddr q `M.lookup` nsAddrs s
    lookupDesc rid = rtrDescriptor =<< rid `M.lookup` nsRouters s
    isExit d = isRunning now d &&
               exitPolicyAccepts (destAddr q) (destPort q) (descExitPolicy d)

-- | We consider a router to be running if it last published a descriptor less
-- than 48 hours ago. Descriptors hold an unboxed 'POSIXTime' instead of a
-- 'UTCTime' to prevent this function from showing up in profiles.
isRunning :: POSIXTime -> Descriptor -> Bool
{-# INLINE isRunning #-}
isRunning now d = now - descPublished d < maxRouterAge
  where maxRouterAge = 60 * 60 * 48

--------------------------------------------------------------------------------
-- Exit tests

-- | The exit test channel.
data ExitTestChan = ExitTestChan (Chan (RouterID, Maybe Port)) (MVar ())

-- | Create a new exit test channel to be passed to 'newNetwork'.
newExitTestChan :: IO ExitTestChan
newExitTestChan = liftM2 ExitTestChan newChan (newMVar ())

-- | Schedule an exit test through a router.
addExitTest :: ExitTestChan -> Maybe Port -> RouterID -> IO ()
addExitTest (ExitTestChan chan _) port rid = writeChan chan (rid, port)

-- | Is any thread reading from an exit test channel?
isReadingExitTestChan :: ExitTestChan -> IO Bool
isReadingExitTestChan (ExitTestChan _ reading) = isEmptyMVar reading

-- | Bind a listening socket we're going to use for incoming exit tests. This
-- action exists so we can listen on privileged ports prior to dropping
-- privileges. The address and port should be in host order.
bindListeningSocket :: HostAddress -> Port -> IO Socket
bindListeningSocket listenAddr listenPort = do
  sock <- socket AF_INET Stream tcpProtoNum
  setSocketOption sock ReuseAddr 1
  bindSocket sock (SockAddrInet (fromIntegral listenPort) (htonl listenAddr))
  listen sock sOMAXCONN
  return sock

-- | Configuration for exit tests.
data ExitTestConfig = ExitTestConfig
  { etChan        :: ExitTestChan
  , etNetwork     :: Network
  , etConcTests   :: Integer
  , etSocksServer :: SockAddr
  , etListenSocks :: [Socket]
  , etTestAddr    :: HostAddress
  , etTestPorts   :: [Port]
  , etRandom      :: Handle }

-- | Fork all our exit test listeners.
startTestListeners :: Network -> [Socket] -> Integer -> IO ()
startTestListeners net listenSockets concTests = do
  -- We need to keep the number of open FDs below FD_SETSIZE as long as GHC uses
  -- select instead of epoll or kqueue. Client sockets waiting in this channel
  -- count against that limit. We use a bounded channel so incoming connections
  -- can't crash the runtime by exceeding the limit.
  clients <- atomically $ newBoundedTChan 64

  forM_ listenSockets $ \sock -> forkIO . forever $ do
    (client,SockAddrInet _ addr) <- accept sock
    atomically $ writeBoundedTChan clients (client, ntohl addr)

  replicateM_ (fromInteger concTests) . forkIO . forever $ do
    (client,addr) <- atomically $ readBoundedTChan clients
    handle <- socketToHandle client ReadWriteMode
    timeout (30 * 10^6) . ignoreJust E.ioErrors $ do
      r <- (parseRequest . L.take 2048) `fmap` L.hGetContents handle
      case r of
        Just cookie -> do
          now <- getCurrentTime
          updateExitAddress net now cookie addr
          B.hPut handle $ b 46 "HTTP/1.0 204 No Content\r\n\
                               \Connection: close\r\n\r\n"#
        _ ->
          B.hPut handle $ b 47 "HTTP/1.0 400 Bad Request\r\n\
                               \Connection: close\r\n\r\n"#
    ignoreJust E.ioErrors $ hClose handle

-- | Fork all our exit test listeners and initiators.
startExitTests :: ExitTestConfig -> IO ()
startExitTests conf@ExitTestConfig { etChan = ExitTestChan chan reading } = do
  startTestListeners (etNetwork conf) (etListenSocks conf) (etConcTests conf)

  replicateM_ (fromInteger $ etConcTests conf) . forkIO . forever $ do
    (rid,mbPort) <- withMVar reading (const $ readChan chan)
    s <- readNetworkState . etNetwork $ conf
    let mbTest = do
          rtr <- rid `M.lookup` nsRouters s
          d <- rtrDescriptor rtr
          ports@(_:_) <- return $ allowedPorts d
          return (rtr, posixSecondsToUTCTime (descPublished d), ports)

    -- Skip the test if this router isn't marked running, we don't have its
    -- descriptor yet, or its exit policy doesn't allow connections to any of
    -- our listening ports.
    whenJust mbTest $ \(rtr, published, ports) ->
      case mbPort of
        Nothing
          | rtrIsRunning rtr ->
              -- perform one test for each port
              mapM_ (writeChan chan . (,) rid . Just) ports
          | otherwise ->
              -- Tests through non-running routers will almost always time out.
              -- Only test one port so we don't tie up all the testing threads.
              writeChan chan (rid, Just $ head ports)
        Just port | port `elem` ports ->
          withCookie (etNetwork conf) (etRandom conf) rid published port $
            \cookie -> do
              -- try to connect twice before giving up
              attempt . replicate 2 $ testConnection cookie rid port
              -- XXX log failure
              return ()
        _ -> return ()

  where
    testConnection cookie rid port =
      E.handleJust connExceptions (const $ return False) .
        fmap (maybe False (const True)) .
          timeout (2 * 60 * 10^6) $ do
            handle <- repeatConnectSocks
            withSocksConnection handle (Addr exitHost) port $ do
              B.hPut handle $ createRequest testHost port cookie
              B.hGet handle 1024 -- ignore response
              return ()
      where
        exitHost = B.concat [ testHost, b 2 ".$"#, encodeBase16RouterID rid
                            , b 5 ".exit"# ]
        testHost = B.pack . inet_htoa . etTestAddr $ conf

    allowedPorts desc =
      [ p | p <- etTestPorts conf
          , exitPolicyAccepts (etTestAddr conf) p (descExitPolicy desc) ]

    repeatConnectSocks = do
      r <- E.tryJust E.ioErrors $
        E.bracketOnError (socket AF_INET Stream tcpProtoNum) sClose $ \sock ->
          connect sock (etSocksServer conf) >> socketToHandle sock ReadWriteMode
      -- When connecting to Tor's socks port fails, wait five seconds
      -- and try again.
      -- XXX this should be logged
      either (const $ threadDelay (5 * 10^6) >> repeatConnectSocks) return r

    attempt (io:ios) = do
      p <- io
      if p then return True
           else attempt ios
    attempt [] = return False

    connExceptions e@(E.IOException _)           = Just e
    connExceptions e@(E.DynException e')
      | Just (_ :: SocksError) <- fromDynamic e' = Just e
    connExceptions _                             = Nothing

--------------------------------------------------------------------------------
-- HTTP requests

-- | Create an HTTP request that POSTs a cookie to one of our listening ports.
createRequest :: B.ByteString -> Port -> Cookie -> B.ByteString
createRequest host port cookie =
  B.join (b 2 "\r\n"#)
  -- POST should force caching proxies to forward the request.
  [ b 15 "POST / HTTP/1.0"#
  -- Host doesn't exist in HTTP 1.0. We'll use it anyway to help the request
  -- traverse transparent proxies.
  , b 6 "Host: "# `B.append` hostValue
  , b 38 "Content-Type: application/octet-stream"#
  , b 16 "Content-Length: "# `B.append` B.pack (show cookieLen)
  , b 17 "Connection: close"#
  , b 2 "\r\n"# `B.append` unCookie cookie ]
  where
    hostValue
      | port == 80 = host
      | otherwise  = B.concat [host, b 1 ":"#, B.pack $ show port]

-- | Given an HTTP request, return the cookie contained in the body if it's
-- well-formatted, otherwise return 'Nothing'.
parseRequest :: L.ByteString -> Maybe Cookie
parseRequest req = do
  (reqLine:headerLines,body) <- return $ breakHeaders req
  return $! length headerLines -- read all headers before parsing them
  [method,_,http] <- return $ L.split ' ' reqLine
  [prot,ver]      <- return $ L.split '/' http
  guard $ and [ method == l 4 "POST"#, prot == l 4 "HTTP"#
              , ver `elem` [l 3 "1.0"#, l 3 "1.1"#] ]

  let headers = M.fromList $ map parseHeader headerLines
  typ <- l 12 "content-type"# `M.lookup` headers
  len <- (readInt . B.concat . L.toChunks)
      =<< l 14 "content-length"# `M.lookup` headers
  guard $ typ == l 24 "application/octet-stream"# && len == cookieLen

  return $! Cookie . B.concat . L.toChunks . L.take cookieLen' $ body

  where
    parseHeader line = (L.map toLower name, L.dropWhile isSpace $ L.drop 1 rest)
      where (name,rest) = L.break (==':') line

    breakHeaders bs
      | L.null x  = ([], L.drop 2 rest)
      | otherwise = (x:xs, rest')
      where
        (x,rest)   = L.break (=='\r') bs
        (xs,rest') = breakHeaders (L.drop 2 rest)

    cookieLen' = fromIntegral cookieLen

    l len addr = L.fromChunks [B.unsafePackAddress len addr]

--------------------------------------------------------------------------------
-- Cookies

-- | A cookie containing pseudo-random data that we send in an HTTP request. We
-- associate it with the exit node we're testing through and use it look up that
-- exit node when we receive it on a listening port.
newtype Cookie = Cookie { unCookie :: B.ByteString }
  deriving (Eq, Ord)

-- | Create a new cookie from pseudo-random data.
newCookie :: Handle -> IO Cookie
newCookie random = Cookie `fmap` randBytes random cookieLen

-- | The cookie length in bytes.
cookieLen :: Int
cookieLen = 32

--------------------------------------------------------------------------------
-- Exit test result storage

-- | An exit address entry stored in our state directory. The design here is the
-- same as Tor uses for storing router descriptors.
data ExitAddress = ExitAddress
  { -- | The identity of the exit node we tested through.
    eaRouterID   :: {-# UNPACK #-} !RouterID,
    -- | The current descriptor published time when the test was initiated. We
    -- don't perform another test until a newer descriptor arrives.
    eaPublished  :: {-# UNPACK #-} !UTCTime,
    -- | When we last received a network status update for this router. This
    -- helps us decide when to discard a router.
    eaLastStatus :: {-# UNPACK #-} !UTCTime,
    -- | A map from exit address to when the address was last seen.
    eaAddresses  :: {-# UNPACK #-} !(Map HostAddress UTCTime) }

-- | Exit test results are represented using the same document meta-format Tor
-- uses for router descriptors and network status documents.
renderExitAddress :: ExitAddress -> B.ByteString
renderExitAddress x = B.unlines $
  [ b 9 "ExitNode "# `B.append` renderID (eaRouterID x)
  , b 10 "Published "# `B.append` renderTime (eaPublished x)
  , b 11 "LastStatus "# `B.append` renderTime (eaLastStatus x) ] ++
  (map renderTest . sortBy (compare `on` snd) . M.assocs . eaAddresses $ x)
  where
    renderID = B.map toUpper . encodeBase16RouterID
    renderTest (addr,time) =
      B.unwords [b 11 "ExitAddress"#, B.pack $ inet_htoa addr, renderTime time]
    renderTime = B.pack . take 19 . show

-- | Parse a single exit address entry, 'fail'ing in the monad if parsing fails.
parseExitAddress :: MonadError String m => Document -> m ExitAddress
parseExitAddress items = do
  rid         <- decodeBase16RouterID
                             =<< findArg (b 8  "ExitNode"#   ==) items
  published  <- parseUTCTime =<< findArg (b 9  "Published"#  ==) items
  lastStatus <- parseUTCTime =<< findArg (b 10 "LastStatus"# ==) items
  addrs <- mapM parseAddr . filter ((b 11 "ExitAddress"# ==) . iKey) $ items
  return $! ExitAddress rid published lastStatus (M.fromList addrs)
  where
    parseAddr item = do
      (addr,tested) <- B.break isSpace `liftM` liftArg (iArg item)
      liftM2 (,) (inet_atoh addr) (parseUTCTime $ B.dropWhile isSpace tested)
    liftArg (Just arg) = return arg
    liftArg _          = throwError "no argument"

-- | On startup, read the exit test results from the state directory. Return the
-- results in ascending order of their fingerprints.
readExitAddresses :: FilePath -> IO [ExitAddress]
readExitAddresses stateDir =
  M.elems `fmap`
    liftM2 (M.unionWith merge)
           (M.fromListWith merge `fmap` addrs "/exit-addresses.new")
           (M.fromDistinctAscList `fmap` addrs "/exit-addresses")
  where
    merge new old = new { eaAddresses = (M.union `on` eaAddresses) new old }
    addrs fp = (map (eaRouterID &&& id) . filterRight .
                 parseSubDocs (b 8 "ExitNode"#) parseExitAddress .
                 parseDocument . B.lines) `fmap`
               E.catchJust E.ioErrors (B.readFile (stateDir ++ fp))
                                      (const $ return B.empty)

-- | On startup, and when the journal becomes too large, replace the
-- exit-addresses file with our most current test results and clear the journal.
-- Return the new exit-addresses file's size in bytes.
replaceExitAddresses :: Integral a => FilePath -> Map RouterID Router -> IO a
replaceExitAddresses stateDir routers = do
  L.writeFile (dir "/exit-addresses.tmp") (L.fromChunks $ addrs routers)
  renameFile (dir "/exit-addresses.tmp") (dir "/exit-addresses")
  writeFile (dir "/exit-addresses.new") ""
  (fromIntegral . fileSize) `fmap` getFileStatus (dir "/exit-addresses")
  where
    addrs = mapMaybe (fmap renderExitAddress . mkExitAddress) . M.toList
    dir = (stateDir ++)

-- | Return an exit address entry if we have enough information to create one.
mkExitAddress :: (RouterID, Router) -> Maybe ExitAddress
mkExitAddress (rid,r) = do
  t <- rtrTestResults r
  return $! ExitAddress rid (tstPublished t) (rtrLastStatus r) (tstAddresses t)

-- | Add an exit address entry to the journal. Return the entry's length in
-- bytes.
appendExitAddressToJournal :: Integral a => Handle -> RouterID -> Router -> IO a
appendExitAddressToJournal journal rid r
  | Just addr <- renderExitAddress `fmap` mkExitAddress (rid,r) = do
      B.hPut journal addr >> hFlush journal
      return $! fromIntegral . B.length $ addr
  | otherwise = return 0

-- | Is the exit address journal large enough that it should be cleared?
isJournalTooLarge :: Integral a => a -> a -> Bool
isJournalTooLarge addrLen journalLen
  | addrLen > 65536 = journalLen > addrLen
  | otherwise       = journalLen > 65536

--------------------------------------------------------------------------------
-- Helpers

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
