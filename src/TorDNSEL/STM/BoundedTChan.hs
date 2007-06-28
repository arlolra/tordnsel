-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.STM.BoundedTChan
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (STM)
--
-- Bounded transactional FIFO channels.
--
-----------------------------------------------------------------------------

module TorDNSEL.STM.BoundedTChan (
    BoundedTChan
  , newBoundedTChan
  , readBoundedTChan
  , writeBoundedTChan
  ) where

import Control.Concurrent.STM
  ( STM, check, TVar, newTVar, readTVar, writeTVar
  , TChan, newTChan, readTChan, writeTChan )

-- | An abstract type representing a transactional FIFO channel of bounded size.
data BoundedTChan a = BTChan (TChan a) (TVar Int) Int

-- | Create a new bounded channel of a given size.
newBoundedTChan :: Int -> STM (BoundedTChan a)
newBoundedTChan maxSize = do
  currentSize <- newTVar 0
  chan <- newTChan
  return (BTChan chan currentSize maxSize)

-- | Read from a bounded channel, blocking until an item is available.
readBoundedTChan :: BoundedTChan a -> STM a
readBoundedTChan (BTChan chan currentSize _) = do
  size <- readTVar currentSize
  writeTVar currentSize (size - 1)
  readTChan chan

-- | Write to a bounded channel, blocking until the channel is smaller than its
-- maximum size.
writeBoundedTChan :: BoundedTChan a -> a -> STM ()
writeBoundedTChan (BTChan chan currentSize maxSize) x = do
  size <- readTVar currentSize
  check (size < maxSize)
  writeTVar currentSize (size + 1)
  writeTChan chan x
