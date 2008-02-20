-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, pattern guards, bang patterns)
--
-- Manages our current view of the Tor network, initiating test connections
-- through exit nodes when necessary and storing results of those tests in
-- the file system.
--
-----------------------------------------------------------------------------

module TorDNSEL.NetworkState (
    NetworkStateManager
  , NetworkStateManagerConfig(..)
  , ExitTestConfig(..)
  , startNetworkStateManager
  , readNetworkState
  , reconfigureNetworkStateManager
  , terminateNetworkStateManager
  ) where

import TorDNSEL.NetworkState.Internals
