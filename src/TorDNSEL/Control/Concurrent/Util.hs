-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Control.Concurrent.Util
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions)
--
-- Common concurrency utilities.
--
-----------------------------------------------------------------------------
module TorDNSEL.Control.Concurrent.Util where

import Control.Concurrent.MVar (newEmptyMVar, takeMVar, putMVar)
import Data.Maybe (isJust)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.System.Timeout

-- | Terminate the thread @tid@ by calling @terminate@. @mbWait@ specifies the
-- amount of time in microseconds to wait for the thread to terminate. If the
-- thread hasn't terminated by the timeout, an uncatchable exit signal will be
-- sent.
terminateThread :: Maybe Int -> ThreadId -> IO () -> IO ()
terminateThread mbWait tid terminate = do
  dead <- newEmptyMVar
  withMonitor tid (const $ putMVar dead ()) $ do
    terminate
    case mbWait of
      Nothing -> takeMVar dead
      Just wait -> do
        r <- timeout wait (takeMVar dead)
        if isJust r then return () else do
        killThread tid
        takeMVar dead
