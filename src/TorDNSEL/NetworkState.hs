-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, STM, pattern guards)
--
-- Managing our current view of the Tor network. The network state constantly
-- changes as we receive new router descriptors and router status entries
-- from Tor.
--
-----------------------------------------------------------------------------

module TorDNSEL.NetworkState (
  -- * Network state
    NetworkState
  , newNetworkState

  -- * State events
  , updateDescriptors
  , updateNetworkStatus

  -- * Exit list queries
  , ExitListQuery(..)
  , isExitNode
  ) where

import TorDNSEL.NetworkState.Internals
