-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Control.Concurrent.Future
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions)
--
-- Implements concurrent futures.
--
-----------------------------------------------------------------------------

module TorDNSEL.Control.Concurrent.Future (
    Future
  , spawn
  , resolve
  ) where

import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, withMVar)
import qualified Control.Exception as E

import TorDNSEL.Control.Concurrent.Link

-- | An abstract type representing a value being evaluated concurrently in
-- another thread of execution.
newtype Future a = Future (MVar (Either ExitReason a))

-- | Evaluate the given 'IO' action in a separate thread and return a future of
-- its result immediately. The future thread is linked to the calling thread so
-- the future can receive an exit signal if the calling thread exits, but an
-- exit signal from the future thread won't be delivered to the calling thread.
spawn :: IO a -> IO (Future a)
spawn io = do
  mv <- newEmptyMVar
  callingThread <- myThreadId
  forkLinkIO . E.mask $ \restore -> do
    r <- either (Left . extractReason) (Right . id) `fmap` E.try (restore io)
    putMVar mv r
    unlinkThread callingThread
    either exit (const $ return ()) r
  return $ Future mv

-- | Explicitly unwrap the value contained within a future. Block until the
-- value has been evaluated, exiting with the future's exit reason if the future
-- failed.
resolve :: Future a -> IO a
resolve (Future mv) = withMVar mv (either exit return)
