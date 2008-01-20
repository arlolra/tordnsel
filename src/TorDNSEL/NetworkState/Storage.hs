-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Storage
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, pattern guards, GHC primitives)
--
-- Implements a thread that manages the storage of exit test results in the
-- file system.
--
-----------------------------------------------------------------------------

module TorDNSEL.NetworkState.Storage (
    StorageConfig(..)
  , StorageManager
  , ExitAddress(..)
  , startStorageManager
  , readExitAddressesFromStorage
  , rebuildExitAddressStorage
  , storeNewExitAddress
  , reconfigureStorageManager
  , terminateStorageManager
  ) where

import TorDNSEL.NetworkState.Storage.Internals
