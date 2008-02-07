{-# LANGUAGE PatternGuards #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Internals
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
  , emptyNetworkState

  -- * State events
  , updateDescriptors
  , updateNetworkStatus
  , withCookie
  , updateExitAddress
  , readNetworkState
  , StateEvent(..)
  , stateEventHandler
  , eventHandler
  , testingEventHandler
  , newExitAddress
  , newDescriptor
  , newRouterStatus
  , expireOldInfo
  , insertAddress
  , deleteAddress

  -- * Exit test server
  , bindListeningSocket
  , startExitTestListeners

  -- * Aliases
  , b
  ) where

import Prelude hiding (log)
import Control.Arrow ((&&&))
import Control.Monad (liftM2, forM_, replicateM_, when)
import Control.Monad.Fix (fix)
import Control.Concurrent (threadDelay)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newMVar, readMVar, swapMVar)
import Control.Concurrent.STM (atomically)
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import Data.List (foldl')
import Data.Maybe (mapMaybe)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Set as S
import Data.Set (Set)
import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import Network.Socket
  ( Socket, HostAddress, SockAddr(SockAddrInet), Family(AF_INET)
  , SocketOption(ReuseAddr), SocketType(Stream), socket, bindSocket, listen
  , accept, setSocketOption, sOMAXCONN, socketToHandle )
import System.IO (Handle, hClose, IOMode(ReadWriteMode))

import GHC.Prim (Addr#)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Directory
import TorDNSEL.ExitTest.Initiator
import TorDNSEL.ExitTest.Request
import TorDNSEL.Log
import TorDNSEL.NetworkState.Storage
import TorDNSEL.NetworkState.Types
import TorDNSEL.System.Timeout
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Network state

-- | An abstract type supporting the interface to reading and updating the
-- network state.
data Network = Network
  { -- | A channel over which state changes are sent.
    nChan  :: {-# UNPACK #-} !(Chan StateEvent),
    -- | The network state shared with an 'MVar'. This 'MVar' is read-only from
    -- the point of view of other threads. It exists to overcome a performance
    -- problem with pure message passing.
    nState :: {-# UNPACK #-} !(MVar NetworkState) }

-- | Create a new network event handler given the exit initiator config and the
-- path to our state directory. This should only be called once.
newNetwork :: Maybe (Handle, Integer, SockAddr, HostAddress, [Port], FilePath)
           -> IO Network
newNetwork testConf = do
  net <- liftM2 Network newChan (newMVar emptyNetworkState)
  forkIO $ stateEventHandler net testConf
  return net

-- | The empty network state.
emptyNetworkState :: NetworkState
emptyNetworkState = NetworkState M.empty M.empty

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

-- | Receive and carry out state update events.
stateEventHandler
  :: Network -> Maybe (Handle, Integer, SockAddr, HostAddress, [Port], FilePath)
  -> IO ()
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
        _ -> log Warn "Bug: TorDNSEL.NetworkState.Internals.eventHandler: \
                      \Unexpected message"

-- | Handle testing events.
testingEventHandler
  :: Network -> (Handle, Integer, SockAddr, HostAddress, [Port], FilePath)
  -> IO ()
testingEventHandler net
                   (random,concLimit,socksAddr,testAddr,testPorts,stateDir) = do
  storage <- startStorageManager StorageConfig { stcfStateDir = stateDir }

  -- initialize network state with test results from state directory
  exitAddrs <- readExitAddressesFromStorage storage
  initNS <- flip expireOldInfo (initialNetState exitAddrs) `fmap` getCurrentTime
  swapMVar (nState net) initNS

  -- remove old info and merge journal into exit-addresses
  rebuildExitAddressStorage (nsRouters initNS) storage

  testInitiator <- startExitTestInitiator ExitTestInitiatorConfig
    { eticfGetNetworkState = readNetworkState net
    , eticfWithCookie = withCookie net random
    , eticfConcClientLimit = concLimit
    , eticfSocksServer = socksAddr
    , eticfTestAddr = testAddr
    , eticfTestPorts = testPorts }

  forkIO . forever $ do
    -- rebuild exit-addresses every 15 minutes so LastStatus entries
    -- stay up to date
    threadDelay (15 * 60 * 10^6)
    writeChan (nChan net) ReplaceExitAddresses

  flip fix (initNS, M.empty) $ \loop s@(ns, cookies) -> do
    event <- readChan $ nChan net
    now <- getCurrentTime
    case event of
      NewDesc ds -> do
        let ns' = foldl' (newDescriptor now) ns ds
        ns' `seq` swapMVar (nState net) ns'
        notifyNewDirInfo (lookupRouters ns' descRouterID ds) testInitiator
        loop (ns', cookies)

      NewNS rss -> do
        let ns' = foldl' (newRouterStatus now) ns rss
        ns' `seq` swapMVar (nState net) ns'
        notifyNewDirInfo (lookupRouters ns' rsRouterID rss) testInitiator
        loop (ns', cookies)

      ExpireOldInfo ->
        let ns' = expireOldInfo now ns
        in ns' `seq` swapMVar (nState net) ns' >> loop (ns', cookies)

      AddCookie c rid published port ->
        loop (ns, M.insert c (rid, published, port) cookies)

      DeleteCookie c -> loop (ns, M.delete c cookies)

      NewExitAddress tested c addr
        | Just (rid,published,port) <- c  `M.lookup` cookies ->
          case rid `M.lookup` nsRouters ns of
            Nothing -> do
              log Info "Received cookie for unrecognized router " rid
                       "; discarding."
              loop s
            Just r -> do
              log Info "Exit test through router " rid " port " port
                       " accepted from " (inet_htoa addr) '.'
              let (r',ns') = newExitAddress tested published r rid addr ns
              ns' `seq` swapMVar (nState net) ns'

              when ((M.member addr . tstAddresses) `fmap` rtrTestResults r ==
                    Just False) $
                -- If we haven't seen this address before, test through this
                -- router again in case the router is rotating exit addresses.
                scheduleNextExitTest rid testInitiator

              storeNewExitAddress rid r' (nsRouters ns') storage
              loop (ns', cookies)
      NewExitAddress _tested _c addr -> do
        log Info "Received unrecognized cookie from " (inet_htoa addr)
                 "; discarding."
        loop s

      ReplaceExitAddresses ->
        rebuildExitAddressStorage (nsRouters ns) storage >> loop s
  where
    lookupRouters ns f =
      mapMaybe $ \x -> let rid = f x
                       in (,) rid `fmap` M.lookup rid (nsRouters ns)

    initialNetState exitAddrs =
      NetworkState (foldl' insertExits M.empty exitAddrs)
                   (M.fromDistinctAscList $ map initialRouter exitAddrs)
      where
        insertExits addrs (ExitAddress rid _ _ exits) =
          foldl' (\addrs' addr -> insertAddress addr rid addrs') addrs
                 (M.keys exits)
        initialRouter (ExitAddress rid pub status exits) =
          (rid, Router Nothing (Just (TestResults pub exits)) False status)

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
-- Exit tests

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

-- | Fork all our exit test listeners.
startExitTestListeners :: Network -> [Socket] -> Integer -> IO ()
startExitTestListeners net listenSockets concTests = do
  -- We need to keep the number of open FDs below FD_SETSIZE as long as GHC uses
  -- select instead of epoll or kqueue. Client sockets waiting in this channel
  -- count against that limit. We use a bounded channel so incoming connections
  -- can't crash the runtime by exceeding the limit.
  clients <- atomically $ newBoundedTChan 64

  forM_ listenSockets $ \sock -> forkIO . forever $ do
    (client,SockAddrInet _ addr) <- accept sock
    let addr' = ntohl addr
    log Debug "Accepted exit test client from " (inet_htoa addr') '.'
    atomically $ writeBoundedTChan clients (client, addr')

  replicateM_ (fromInteger concTests) . forkIO . forever $ do
    (client,addr) <- atomically $ readBoundedTChan clients
    handle <- socketToHandle client ReadWriteMode
    r <- timeout (30 * 10^6) . E.tryJust E.ioErrors $ do
      r <- runMaybeT $ getRequest handle
      case r of
        Just cookie -> do
          now <- getCurrentTime
          updateExitAddress net now cookie addr
          B.hPut handle $ b 46 "HTTP/1.0 204 No Content\r\n\
                               \Connection: close\r\n\r\n"#
        _ -> do
          log Info "Received invalid HTTP request from " (inet_htoa addr)
                   "; discarding."
          B.hPut handle $ b 47 "HTTP/1.0 400 Bad Request\r\n\
                               \Connection: close\r\n\r\n"#
    case r of
      Just (Left e) -> log Info "Error reading HTTP request from "
                                (inet_htoa addr) ": " e
      Nothing -> log Info "Reading HTTP request from " (inet_htoa addr)
                          " timed out."
      _ -> return ()
    ignoreJust E.ioErrors $ hClose handle

--------------------------------------------------------------------------------
-- Aliases

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
