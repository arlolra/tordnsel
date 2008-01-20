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

import qualified Control.Exception as E
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, putMVar, tryPutMVar)
import Data.Maybe (isJust)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.System.Timeout
import TorDNSEL.Util

-- | A type representing a handle to a thread.
class Thread a where
  threadId :: a -> ThreadId -- ^ The 'ThreadId' contained within a handle.

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

-- | Send a message to @tid@ by invoking @sendMsg@ with a synchronizing action.
-- If the thread exits abnormally before synchronizing, throw its exit signal in
-- the calling thread.
sendSyncMessage :: (IO () -> IO ()) -> ThreadId -> IO ()
sendSyncMessage sendMsg tid = do
  err <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar err
  withMonitor tid putResponse $ do
    sendMsg $ putResponse Nothing
    takeMVar err >>= flip whenJust E.throwIO

-- | Send a message parameterized by a reply action to @tid@, returning the
-- response value. If the thread exits before responding to the message, throw
-- its exit signal or 'NonexistentThread' in the calling thread.
call :: ((a -> IO ()) -> IO ()) -> ThreadId -> IO a
call sendMsg tid = do
  mv <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar mv
  withMonitor tid (putResponse . Left) $ do
    sendMsg $ putResponse . Right
    response <- takeMVar mv
    case response of
      Left Nothing  -> E.throwDyn NonexistentThread
      Left (Just e) -> E.throwIO e
      Right r       -> return r
