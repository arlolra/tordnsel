-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Log.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Implements a logger thread and functions to log messages, reconfigure the
-- logger, and terminate the logger.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Log.Internals where

import Prelude hiding (log)
import Control.Concurrent.Chan (Chan, newChan, writeChan, readChan)
import Control.Concurrent.MVar
  (MVar, newEmptyMVar, newMVar, takeMVar, putMVar, withMVar, readMVar, swapMVar)
import qualified Control.Exception as E
import Control.Monad (when, liftM2)
import Data.Time (UTCTime, getCurrentTime)
import System.IO (stdout, stderr, openFile, IOMode(AppendMode), hFlush, hClose)
import System.IO.Unsafe (unsafePerformIO)
import Text.Printf (hPrintf)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Util

-- | The logging configuration.
data LogConfig = LogConfig
  { minSeverity :: !Severity  -- ^ Minimum severity level to log
  , logTarget   :: !LogTarget -- ^ Where to send log messages
  , logEnabled  :: !Bool      -- ^ Is logging enabled?
  } deriving Show

-- | Where log messages should be sent.
data LogTarget = ToStdOut | ToStdErr | ToFile FilePath

instance Show LogTarget where
  show ToStdErr    = "stderr"
  show ToStdOut    = "stdout"
  show (ToFile fp) = show fp

-- | An internal type for messages sent to the logger.
data LogMessage
  = Log UTCTime Severity String          -- ^ A log message
  | Reconfigure (LogConfig -> LogConfig) -- ^ Reconfigure the logger
  | Terminate ExitReason                 -- ^ Terminate the logger gracefully

-- | Logging severities.
data Severity = Debug | Info | Notice | Warn | Error
  deriving (Eq, Ord, Show)

-- | The logger's 'ThreadId' and channel, if it is running.
logger :: MVar (Maybe (ThreadId, Chan LogMessage))
{-# NOINLINE logger #-}
logger = unsafePerformIO $ newMVar Nothing

-- | Write a message to the log channel, if the logger is currently running.
writeLogChan :: LogMessage -> IO ()
writeLogChan msg = do
  mbLogger <- readMVar logger
  whenJust mbLogger $ flip writeChan msg . snd

-- | Start the global logger with an initial 'LogConfig', returning its
-- 'ThreadId'. Link the logger to the calling thread.
startLogger :: LogConfig -> IO ThreadId
startLogger config =
  forkLinkIO $ do
    (loggerId,logChan) <- liftM2 (,) myThreadId newChan
    setTrapExit . const $ writeChan logChan . Terminate
    sync <- newEmptyMVar
    forkLinkIO $ do
      loggerDead <- newEmptyMVar
      setTrapExit . const $ putMVar loggerDead
      putMVar sync ()
      takeMVar loggerDead
      withMVar logger $ \mbLogger ->
        case mbLogger of
          Just (loggerId',_) | loggerId == loggerId' -> return Nothing
          _                                          -> return mbLogger
    takeMVar sync
    swapMVar logger $ Just (loggerId, logChan)
    openLogHandle config >>= loop logChan config
  where
    loop logChan c h = do
      msg <- readChan logChan
      case msg of
        Log time severity logMsg -> do
          when (logEnabled c && severity >= minSeverity c) $
            hPrintf h "%s [%s] %s\n" (show time) (show severity) logMsg
              `E.catch` \e -> when (isFileTarget c) (hClose h) >> E.throwIO e
          loop logChan c h

        Reconfigure reconf -> do
          (if isFileTarget c then hClose else hFlush) h
          let c' = reconf c in openLogHandle c' >>= loop logChan c'

        Terminate reason -> do
          (if isFileTarget c then hClose else hFlush) h
          whenJust reason E.throwIO

    openLogHandle c = case logTarget c of
      ToStdErr    -> return stderr
      ToStdOut    -> return stdout
      ToFile file -> openFile file AppendMode

    isFileTarget LogConfig { logTarget = ToFile _ } = True
    isFileTarget _                                  = False

-- | Log a message asynchronously.
log :: Severity -> String -> IO ()
log severity msg = do
  now <- getCurrentTime
  writeLogChan $ Log now severity msg

-- | Reconfigure the logger with the given function.
reconfigureLogger :: (LogConfig -> LogConfig) -> IO ()
reconfigureLogger = writeLogChan . Reconfigure

-- | Terminate the logger gracefully: process any pending messages, flush the
-- log handle, and close the handle when logging to a file.
terminateLogger :: IO ()
terminateLogger = writeLogChan $ Terminate Nothing
