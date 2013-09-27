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
import Data.Functor ( (<$) )
import Control.Concurrent.MVar (MVar, newEmptyMVar, takeMVar, putMVar, tryPutMVar)
import Data.Maybe (isJust)
import System.Timeout

import TorDNSEL.Control.Concurrent.Link

-- | A type representing a handle to a thread.
class Thread a where
  threadId :: a -> ThreadId -- ^ The 'ThreadId' contained within a handle.

instance Thread ThreadId where
  threadId = id

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
  withMonitor tid (tryPutMVar_ err) $ do
    sendMsg $ tryPutMVar_ err NormalExit
    takeMVar err >>= throwAbnormal

-- | Send a message parameterized by a reply action to @tid@, returning the
-- response value. If the thread exits before responding to the message, throw
-- its exit signal or 'NonexistentThread' in the calling thread.
call :: ((a -> IO ()) -> IO ()) -> ThreadId -> IO a
call sendMsg tid = do
  mv <- newEmptyMVar
  withMonitor tid (tryPutMVar_ mv . Left) $ do
    sendMsg $ tryPutMVar_ mv . Right
    response <- takeMVar mv
    case response of
      Left NormalExit       -> E.throwIO NonexistentThread
      Left (AbnormalExit e) -> E.throwIO e
      Right r               -> return r

-- | Invoke the given 'IO' action in a new thread, passing it an action to
-- invoke when it has successfully started. Link the new thread to the calling
-- thread. If the thread exits before signaling that it has successfully
-- started, throw its exit signal in the calling thread.
startLink :: (IO () -> IO a) -> IO ThreadId
startLink io = do
  sync <- newEmptyMVar
  err  <- newEmptyMVar
  tid <- forkLinkIO $ do
    takeMVar sync
    io $ tryPutMVar_ err NormalExit
  withMonitor tid (tryPutMVar_ err) $ do
    putMVar sync ()
    takeMVar err >>= throwAbnormal
  return tid

-- | Invoke the given 'IO' action in a temporary thread (linked to the calling
-- thread), returning either its exit signal or the thread returned by it. If
-- the 'IO' action successfully returns a thread, link it to the calling thread.
-- Also return the 'ThreadId' of the temporary thread.
tryForkLinkIO :: Thread a => IO a -> IO (Either ExitReason a, ThreadId)
tryForkLinkIO io = do
  sync <- newEmptyMVar
  resp <- newEmptyMVar
  intermediate <- forkLinkIO $ do
    takeMVar sync
    io >>= tryPutMVar_ resp . Right
  r <- withMonitor intermediate (tryPutMVar_ resp . Left) $ do
    putMVar sync ()
    E.block $ do
      r <- takeMVar resp
      either (const $ return ()) (linkThread . threadId) r
      return r
  return (r, intermediate)

tryPutMVar_ :: MVar a -> a -> IO ()
tryPutMVar_ = ((() <$) .) . tryPutMVar
