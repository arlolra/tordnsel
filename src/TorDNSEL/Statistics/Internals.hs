{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fglasgow-exts -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Statistics.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (bang patterns, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Making load information available external to the process.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Statistics.Internals where

import Prelude hiding (log)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newMVar, modifyMVar_, readMVar)
import Control.Concurrent.QSem (QSem, newQSem, waitQSem, signalQSem)
import qualified TorDNSEL.Compat.Exception as E
import Control.Monad.Fix (fix)
import qualified Data.ByteString.Char8 as B
import Data.Maybe (isJust, isNothing)
import qualified Data.Set as S
import Network.Socket (accept, socketToHandle, Socket)
import System.IO (hClose, IOMode(ReadWriteMode))
import System.IO.Unsafe (unsafePerformIO)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS.Server
import TorDNSEL.Log
import TorDNSEL.System.Timeout
import TorDNSEL.Util

-- | Cumulative counts of bytes transferred, datagrams received, and responses
-- sent.
data Stats = Stats
  { bytesRecv, bytesSent, dgramsRecv, positives
  , negatives, others :: {-# UNPACK #-} !Integer }

-- | The current statistics state.
statsState :: MVar Stats
{-# NOINLINE statsState #-}
statsState = unsafePerformIO . newMVar $ Stats 0 0 0 0 0 0

-- | An internal type for messages sent to the stats server thread.
data StatsMessage
  = NewClient Socket -- ^ A new client has connected.
  | Terminate ExitReason -- ^ Terminate the stats server gracefully.
  | Exit ThreadId ExitReason -- ^ An exit signal sent to the stats server.

-- | A handle to a stats server.
data StatsServer = StatsServer (StatsMessage -> IO ()) ThreadId

instance Thread StatsServer where
  threadId (StatsServer _ tid) = tid

-- | An internal type representing the current stats server state.
data StatsState = StatsState
  { listenerTid     :: !(ThreadId)
  , handlers        :: !(S.Set ThreadId)
  , terminateReason :: !(Maybe ExitReason) }

-- | Given the runtime directory, bind and return the listening statistics
-- socket.
bindStatsSocket :: FilePath -> IO Socket
bindStatsSocket runtimeDir =
  bindListeningUnixDomainStreamSocket (statsSocketPath runtimeDir) 0o666

-- | Given a listening socket, start a server offering access to load statistics
-- through a Unix domain stream socket in our runtime directory. Link the server
-- thread to the calling thread.
startStatsServer :: Socket -> IO StatsServer
startStatsServer listenSock = do
  log Info "Starting statistics server."
  statsChan <- newChan
  statsServerTid <- forkLinkIO $ do
    setTrapExit $ (writeChan statsChan .) . Exit
    handlerQSem <- newQSem maxStatsHandlers
    initListenerTid <- forkListener statsChan listenSock handlerQSem

    flip fix (StatsState initListenerTid S.empty Nothing) $ \loop (!s) -> do
      message <- readChan statsChan
      case message of
        NewClient client -> do
          handlerTid <- forkLinkIO . (`E.finally` signalQSem handlerQSem) .
            E.bracket (socketToHandle client ReadWriteMode) hClose $ \handle ->
              timeout handlerTimeout $
                B.hPut handle . renderStats =<< readMVar statsState
          loop s { handlers = S.insert handlerTid (handlers s) }

        Terminate reason -> do
          log Info "Terminating statistics server."
          terminateThread Nothing (listenerTid s) (killThread $ listenerTid s)
          if S.null (handlers s)
            then exit reason
            else loop s { terminateReason = Just reason }

        Exit tid reason
          | tid == listenerTid s ->
              if isNothing $ terminateReason s
                then do
                  log Warn "The statistics listener thread exited unexpectedly:\
                           \ " (showExitReason [] reason) "; restarting."
                  newListenerTid <- forkListener statsChan listenSock handlerQSem
                  loop s { listenerTid = newListenerTid }
                else loop s
          | tid `S.member` handlers s -> do
              whenJust reason $
                log Warn "Bug: A statistics client handler exited abnormally: "
              let newHandlers = S.delete tid (handlers s)
              case terminateReason s of
                -- all the handlers have finished, so let's exit
                Just exitReason | S.null newHandlers -> exit exitReason
                _ -> loop s { handlers = newHandlers }
          | isJust reason -> exit reason
          | otherwise -> loop s

  return $ StatsServer (writeChan statsChan) statsServerTid
  where
    maxStatsHandlers = 32
    handlerTimeout = 10 * 10^6

-- | Fork the listener thread.
forkListener :: Chan StatsMessage -> Socket -> QSem -> IO ThreadId
forkListener statsChan listenSock sem =
  forkLinkIO . E.block . forever $ do
    waitQSem sem
    (client,_) <- E.unblock $ accept listenSock
      `E.catch` \e -> signalQSem sem >> E.throwIO e
    writeChan statsChan $ NewClient client

-- | Terminate the stats server gracefully. The optional parameter specifies the
-- amount of time in microseconds to wait for the thread to terminate. If the
-- thread hasn't terminated by the timeout, an uncatchable exit signal will be
-- sent.
terminateStatsServer :: Maybe Int -> StatsServer -> IO ()
terminateStatsServer mbWait (StatsServer tellStatsServer statsServerTid) =
  terminateThread mbWait statsServerTid (tellStatsServer $ Terminate Nothing)

-- | Render 'Stats' to text as a sequence of CRLF-terminated lines.
renderStats :: Stats -> B.ByteString
renderStats s = B.concat . map line $
  [ B.pack "BytesReceived "     ~> bytesRecv
  , B.pack "BytesSent "         ~> bytesSent
  , B.pack "DatagramsReceived " ~> dgramsRecv
  , B.pack "PositivesSent "     ~> positives
  , B.pack "NegativesSent "     ~> negatives
  , B.pack "OthersSent "        ~> others ]
  where
    line (x,f) = x `B.append` (B.pack . show $ f s) `B.append` B.pack "\r\n"
    (~>) = (,)

-- | Generate the statistics socket path from the runtime directory path.
statsSocketPath :: FilePath -> FilePath
statsSocketPath = (++ "/statistics.socket")

-- | Increment the count of bytes transferred.
incrementBytes :: Int -> Int -> IO ()
incrementBytes received sent =
  modifyMVar_ statsState $ \s -> return $!
    s { bytesRecv  = bytesRecv s + fromIntegral received
      , bytesSent  = bytesSent s + fromIntegral sent
      , dgramsRecv = dgramsRecv s + 1 }

-- | Increment the count of DNSEL responses.
incrementResponses :: ResponseType -> IO ()
incrementResponses resp =
  modifyMVar_ statsState $ \s -> return $!
    case resp of
      Negative -> s { negatives = negatives s + 1 }
      Positive -> s { positives = positives s + 1 }
      Other    -> s { others    = others    s + 1 }
