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
-- changes as we receive new router descriptors and router status entries
-- from Tor.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.NetworkState.Internals (
  -- * Network state
    NetworkState(..)
  , Addrs
  , Routers
  , Router(..)
  , RunningStatus(..)
  , newNetworkState

  -- * State events
  , updateDescriptors
  , updateNetworkStatus
  , StateEvent(..)
  , stateEventHandler
  , updateDescs
  , updateStatuses
  , discardOldRouters
  , updateDesc
  , updateStatus
  , insertAddress
  , deleteAddress

  -- * Exit list queries
  , ExitListQuery(..)
  , isExitNode
  , isRunning
  ) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.STM
  (STM, atomically, TVar, newTVarIO, readTVar, writeTVar)
import Control.Monad (liftM3)
import Data.List (foldl')
import Data.Maybe (catMaybes)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Set as S
import Data.Set (Set)
import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word16)
import Network.Socket (HostAddress)

import TorDNSEL.Directory
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Network state

-- | Our current view of the Tor network.
data NetworkState = NetworkState
  { -- | A map from listen address to routers.
    nsAddrs   :: {-# UNPACK #-} !(TVar Addrs),
    -- | All the routers we know about.
    nsRouters :: {-# UNPACK #-} !(TVar Routers),
    -- | A channel over which state changes are sent.
    nsChan    :: {-# UNPACK #-} !(Chan StateEvent) }

-- | A map from listen address to routers.
type Addrs = Map HostAddress (Set Fingerprint)

-- | All the routers we know about.
type Routers = Map Fingerprint Router

-- | A Tor router.
data Router = Router
  { -- | This router's descriptor, if we have it yet.
    rtrDescriptor :: {-# UNPACK #-} !(Maybe Descriptor),
    -- | Whether we think this router is running.
    rtrRunning    :: {-# UNPACK #-} !RunningStatus,
    -- | The last time we received a router status entry for this router.
    rtrLastStatus :: {-# UNPACK #-} !UTCTime }

-- | Whether a router is running.
data RunningStatus
  -- | A router is running.
  = Running
  -- | The time a router's status changed to not running.
  | NotRunning {-# UNPACK #-} !UTCTime

-- | Create a new network state. This should only be called once.
newNetworkState :: IO NetworkState
newNetworkState = do
  state <- liftM3 NetworkState (newTVarIO M.empty) (newTVarIO M.empty) newChan
  forkIO $ stateEventHandler state
  return state

--------------------------------------------------------------------------------
-- State events

-- | Update the network state with new router descriptors.
updateDescriptors :: NetworkState -> [Descriptor] -> IO ()
updateDescriptors ns = writeChan (nsChan ns) . NewDesc

-- | Update the network state with new router status entries.
updateNetworkStatus :: NetworkState -> [RouterStatus] -> IO ()
updateNetworkStatus ns = writeChan (nsChan ns) . NewNS

-- | A message sent to update the network state.
data StateEvent
  -- | New descriptors are available.
  = NewDesc {-# UNPACK #-} ![Descriptor]
  -- | New router status entries are available.
  | NewNS {-# UNPACK #-} ![RouterStatus]
  -- | Discard routers that haven't received status updates for a long time.
  | DiscardOldRouters

-- | Receives and carries out state update events.
stateEventHandler :: NetworkState -> IO ()
stateEventHandler state = do
  forkIO . forever $ do
    -- check for and discard old routers every 30 minutes
    threadDelay (60 * 30 * 10^6)
    writeChan (nsChan state) DiscardOldRouters
  forever $ do
    event <- readChan $ nsChan state
    now <- getCurrentTime
    atomically $
      case event of
        NewDesc descs     -> updateDescs now state descs
        NewNS ns          -> updateStatuses now state ns
        DiscardOldRouters -> discardOldRouters now state

-- | Update our current view of router descriptors.
updateDescs :: UTCTime -> NetworkState -> [Descriptor] -> STM ()
updateDescs now state descs = do
  routers <- readTVar $ nsRouters state
  addrs   <- readTVar $ nsAddrs state
  let (routers',addrs') = foldl' (updateDesc now) (routers, addrs) descs
  writeTVar (nsRouters state) routers'
  writeTVar (nsAddrs state) addrs'

-- | Update our current view of router status entries.
updateStatuses :: UTCTime -> NetworkState -> [RouterStatus] -> STM ()
updateStatuses now state ns = do
  routers <- readTVar $ nsRouters state
  writeTVar (nsRouters state) $ foldl' (updateStatus now) routers ns

-- | Discard routers whose last status update was received more than
-- @routerMaxAge@ seconds ago.
discardOldRouters :: UTCTime -> NetworkState -> STM ()
discardOldRouters now state = do
  routers <- readTVar $ nsRouters state
  addrs   <- readTVar $ nsAddrs state
  let (oldRouters,routers') = M.partition isOld routers
      addrs' = foldl' deleteAddr addrs $ M.toList oldRouters
  writeTVar (nsRouters state) routers'
  writeTVar (nsAddrs state) addrs'
  where
    routerMaxAge = 60 * 60 * 48
    isOld r = now `diffUTCTime` rtrLastStatus r > routerMaxAge
    deleteAddr addrs (fp,r)
      | Just desc <- rtrDescriptor r
      = deleteAddress (descListenAddr desc) fp addrs
      | otherwise = addrs

-- | Given a new router descriptor, return an updated network state.
updateDesc :: UTCTime -> (Routers, Addrs) -> Descriptor -> (Routers, Addrs)
updateDesc now state@(routers,addrs) newD
  -- we know about this router already, but we might not have its descriptor
  | Just router <- M.lookup fp routers
  = case rtrDescriptor router of
      -- we have a descriptor, and therefore a possibly outdated address
      Just oldD
        -- the descriptor we already have is newer than this one, so ignore it
        | descPublished oldD > descPublished newD
                    -> state
        -- address changed: delete old address, insert new address
        | descListenAddr newD /= descListenAddr oldD
                    -> (updateRouters, insertAddr newD $ deleteAddr oldD addrs)
        -- address hasn't changed: don't update addrs
        | otherwise -> (updateRouters, addrs)
      -- we didn't have an address before: insert new address
      _             -> (updateRouters, insertAddr newD addrs)
  -- this is a new router: insert into routers and addrs
  | otherwise        = (insertRouters, insertAddr newD addrs)
  where
    fp = descFingerprint newD
    updateRouters = M.adjust (\r -> r { rtrDescriptor = Just newD }) fp routers
    insertRouters = M.insert fp (Router (Just newD) Running now) routers
    insertAddr d = insertAddress (descListenAddr d) fp
    deleteAddr d = deleteAddress (descListenAddr d) fp

-- | Given a new router status entry, return an updated network state.
updateStatus :: UTCTime -> Routers -> RouterStatus -> Routers
updateStatus now routers ns =
  M.alter (Just . maybe newRouter updateRouter) (rsFingerprint ns) routers
  where
    newRouter = Router Nothing newRunning now
    updateRouter r = r { rtrRunning = updateRunning r, rtrLastStatus = now }
    newRunning = if rsIsRunning ns then Running else NotRunning now
    updateRunning rtr
      | rsIsRunning ns                     = Running
      -- preserve original time of running state change
      | r@(NotRunning _) <- rtrRunning rtr = r
      -- running state just changed to not running
      | otherwise                          = NotRunning now

-- | Add a new router associated with a listen address to the network state.
insertAddress :: HostAddress -> Fingerprint -> Addrs -> Addrs
insertAddress addr fp =
-- if address is in map, add fingerprint to set
-- else create new set with this fingerprint as its only element
-- and add it to map
  M.alter (Just . maybe (S.singleton fp) (S.insert fp)) addr

-- | Remove a router associated with a listen address from the network state.
deleteAddress :: HostAddress -> Fingerprint -> Addrs -> Addrs
-- if address is in map, delete fingerprint from set
-- if set is now empty, delete address from map
deleteAddress addr fp = M.update deleteFingerprint addr
  where
    deleteFingerprint set
      | S.null set' = Nothing
      | otherwise   = Just set'
      where set' = S.delete fp set

--------------------------------------------------------------------------------
-- Exit list queries

-- | Queries asking whether there's a Tor exit node at a specific IP address.
data ExitListQuery
  -- |  Query type 1 from
  -- <http://tor.eff.org/svn/trunk/doc/contrib/torbl-design.txt>.
  = IPPort
  { -- | The address of the candidate exit node.
    queryAddr :: {-# UNPACK #-} !HostAddress,
    -- | The destination address.
    destAddr  :: {-# UNPACK #-} !HostAddress,
    -- | The destination port.
    destPort  :: {-# UNPACK #-} !Word16
  } deriving Eq

instance Show ExitListQuery where
  showsPrec _ (IPPort a b c) = ("query ip: " ++) . (inet_htoa a ++) .
    (" dest ip: " ++) . (inet_htoa b ++) . (" dest port: " ++) . shows c

-- | Does a query represent a Tor exit node cabable of exiting to a particular
-- network service in our current view of the Tor network?
isExitNode :: NetworkState -> ExitListQuery -> IO Bool
{-# INLINE isExitNode #-}
isExitNode state q = do
  now <- getPOSIXTime
  atomically $ do
    addrs <- readTVar $ nsAddrs state
    case M.lookup (queryAddr q) addrs of
      Nothing  -> return False
      Just set -> do
        routers <- readTVar $ nsRouters state
        let addrRtrs = catMaybes . map (flip M.lookup routers) . S.elems $ set
            descs = catMaybes . map rtrDescriptor $ addrRtrs
            policies = map descExitPolicy . filter (isRunning now) $ descs
        return $! any (exitPolicyAccepts (destAddr q) (destPort q)) policies

-- | We consider a router to be running if it last published a descriptor less
-- than 48 hours ago. Descriptors hold an unboxed 'POSIXTime' instead of a
-- 'UTCTime' to prevent this function from showing up in profiles.
isRunning :: POSIXTime -> Descriptor -> Bool
{-# INLINE isRunning #-}
isRunning now d = now - descPublished d < routerMaxAge
  where routerMaxAge = 60 * 60 * 48
