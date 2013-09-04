-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Types
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- Common network state types.
--
-----------------------------------------------------------------------------

module TorDNSEL.NetworkState.Types where

import Data.Map (Map)
import qualified Data.Map as M
import Data.Time (UTCTime)
import Data.Set (Set)
import Network.Socket (HostAddress)

import TorDNSEL.Directory

-- | A Tor router.
data Router = Router
  { -- | This router's descriptor, if we have it yet.
    rtrDescriptor  :: !(Maybe Descriptor),
    -- | This router's exit test results, if one has been completed.
    rtrTestResults :: !(Maybe TestResults),
    -- | Whether we think this router is running.
    rtrIsRunning   :: !Bool,
    -- | The last time we received a router status entry for this router.
    rtrLastStatus  :: !UTCTime }

-- | The results of exit tests.
data TestResults = TestResults
  { -- | The descriptor's published time when the last exit test was initiated.
    tstPublished :: !UTCTime,
    -- | A map from exit address to when the address was last seen.
    tstAddresses :: !(Map HostAddress UTCTime) }

-- | Our current view of the Tor network.
data NetworkState = NetworkState
  { -- | A map from listen address to routers.
    nsAddrs   :: !(Map HostAddress (Set RouterID)),
    -- | All the routers we know about.
    nsRouters :: !(Map RouterID Router) }

-- | The empty network state.
emptyNetworkState :: NetworkState
emptyNetworkState = NetworkState M.empty M.empty
