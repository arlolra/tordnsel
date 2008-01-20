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
import Data.Time (UTCTime)
import Network.Socket (HostAddress)

import TorDNSEL.Directory

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
