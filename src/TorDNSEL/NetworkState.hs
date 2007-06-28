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
-- changes as we receive new router information from Tor and new exit test
-- results.
--
-----------------------------------------------------------------------------

module TorDNSEL.NetworkState (
  -- * Network state
    Network
  , newNetwork
  , NetworkState
  , readNetworkState

  -- * State events
  , updateDescriptors
  , updateNetworkStatus

  -- * Exit list queries
  , ExitListQuery(..)
  , isExitNode

  -- * Exit tests
  , ExitTestConfig(..)
  , ExitTestChan
  , newExitTestChan
  , bindListeningSockets
  , startExitTests
  ) where

import TorDNSEL.NetworkState.Internals
