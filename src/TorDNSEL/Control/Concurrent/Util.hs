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

import qualified TorDNSEL.Compat.Exception as E
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, putMVar, tryPutMVar)
import Data.Dynamic (Dynamic)
import Data.Maybe (isJust)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.System.Timeout
import TorDNSEL.Util

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

-- | A wrapper for using 'showException' with 'ExitReason's.
showExitReason :: [Dynamic -> Maybe String] -> ExitReason -> String
showExitReason _ Nothing   = "Normal exit"
showExitReason fs (Just e) = showException (showLinkException:fs) e

-- | Invoke the given 'IO' action in a new thread, passing it an action to
-- invoke when it has successfully started. Link the new thread to the calling
-- thread. If the thread exits before signaling that it has successfully
-- started, throw its exit signal in the calling thread.
startLink :: (IO () -> IO a) -> IO ThreadId
startLink io = do
  sync <- newEmptyMVar
  err <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar err
  tid <- forkLinkIO $ do
    takeMVar sync
    io (putResponse Nothing)
  withMonitor tid putResponse $ do
    putMVar sync ()
    takeMVar err >>= flip whenJust E.throwIO
  return tid

-- | Invoke the given 'IO' action in a temporary thread (linked to the calling
-- thread), returning either its exit signal or the thread returned by it. If
-- the 'IO' action successfully returns a thread, link it to the calling thread.
-- Also return the 'ThreadId' of the temporary thread.
tryForkLinkIO :: Thread a => IO a -> IO (Either ExitReason a, ThreadId)
tryForkLinkIO io = do
  sync <- newEmptyMVar
  response <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar response
  intermediate <- forkLinkIO $ do
    takeMVar sync
    io >>= putResponse . Right
  r <- withMonitor intermediate (putResponse . Left) $ do
    putMVar sync ()
    E.block $ do
      r <- takeMVar response
      either (const $ return ()) (linkThread . threadId) r
      return r
  return (r, intermediate)
