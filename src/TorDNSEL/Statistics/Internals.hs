{-# OPTIONS_GHC -fglasgow-exts -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Statistics.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Making load information available external to the process.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Statistics.Internals where

import Control.Concurrent.Chan (newChan, readChan, writeChan, isEmptyChan)
import Control.Concurrent.MVar (MVar, newMVar, modifyMVar_, readMVar)
import Control.Concurrent.QSem (newQSem, waitQSem, signalQSem)
import qualified Control.Exception as E
import Control.Monad.Fix (fix)
import qualified Data.ByteString.Char8 as B
import qualified Data.Foldable as F
import Data.Maybe (isJust)
import qualified Data.Set as S
import Network.Socket
  ( socket, bindSocket, listen, accept, sClose, setSocketOption, socketToHandle
  , Socket, SockAddr(SockAddrUnix), Family(AF_UNIX), SocketType(Stream)
  , SocketOption(ReuseAddr), sOMAXCONN )
import System.Directory (removeFile)
import System.IO (hClose, IOMode(ReadWriteMode))
import System.IO.Unsafe (unsafePerformIO)
import System.Posix.Files (setFileMode)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS.Server
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

-- | The stats server configuration.
newtype StatsConfig = StatsConfig
  { scfStateDir :: FilePath -- ^ The path to our state directory.
  }

-- | An internal type for messages sent to the stats server thread.
data StatsMessage
  = NewClient Socket -- ^ A new client has connected.
  -- | Reconfigure the stats server.
  | Reconfigure (StatsConfig -> StatsConfig) (IO ())
  | Terminate ExitReason -- ^ Terminate the stats server gracefully.
  | Exit ThreadId ExitReason -- ^ An exit signal sent to the stats server.

-- | A handle to a stats server.
data StatsServer = StatsServer (StatsMessage -> IO ()) ThreadId

-- | An internal type representing the current stats server state.
data StatsState = StatsState
  { statsConf :: StatsConfig
  , listenerTid :: ThreadId
  , deadListeners :: S.Set ThreadId
  , handlers :: S.Set ThreadId }

-- | Given an initial 'StatsConfig', start a server offering access to load
-- statistics through a Unix domain stream socket in our state directory.
-- Link the server thread to the calling thread.
startStatsServer :: StatsConfig -> IO (StatsServer, ThreadId)
startStatsServer initConf = do
  initListenSock <- bindStatsSocket $ scfStateDir initConf
  statsChan <- newChan
  statsServerTid <- forkLinkIO $ do
    setTrapExit ((writeChan statsChan .) . Exit)
    handlerQSem <- newQSem maxStatsHandlers

    let startListenerThread listenSock stateDir  =
          forkLinkIO . E.block $
            (forever $ do
              waitQSem handlerQSem
              (client,_) <- E.unblock (accept listenSock)
                `E.catch` \e -> signalQSem handlerQSem >> E.throwIO e
              writeChan statsChan $ NewClient client)
            `E.finally` sClose listenSock
            `E.finally` removeFile (statsSocket stateDir)

    initListenerTid <- startListenerThread initListenSock (scfStateDir initConf)

    let runStatsServer = flip fix $ StatsState initConf initListenerTid S.empty
                                               S.empty
    runStatsServer $ \loop s -> do
      message <- readChan statsChan

      case message of
        NewClient client -> do
          handlerTid <- forkLinkIO . (`E.finally` signalQSem handlerQSem) .
            E.bracket (socketToHandle client ReadWriteMode) hClose $ \handle ->
              timeout handlerTimeout $
                B.hPut handle . renderStats =<< readMVar statsState
          loop s { handlers = S.insert handlerTid (handlers s) }

        Reconfigure reconf signal -> do
          let newConf = reconf (statsConf s)
          if scfStateDir newConf /= scfStateDir (statsConf s)
            then do
              terminateThread Nothing (listenerTid s)
                              (killThread $ listenerTid s)
              listenSock <- bindStatsSocket $ scfStateDir newConf
              newListenerTid <- startListenerThread listenSock
                                                    (scfStateDir newConf)
              signal
              loop s { statsConf = newConf
                     , listenerTid = newListenerTid
                     , deadListeners = S.insert (listenerTid s)
                                                (deadListeners s) }
            else signal >> loop s { statsConf = newConf }

        Terminate reason -> do
          terminateThread Nothing (listenerTid s) (killThread $ listenerTid s)
          msgs <- untilM (isEmptyChan statsChan) (readChan statsChan)
          ignoreJust E.ioErrors . foldl E.finally (return ()) $
            [sClose client | NewClient client <- msgs]
          F.mapM_ (\tid -> terminateThread Nothing tid (return ())) (handlers s)
          exit reason

        Exit tid reason
          | tid == listenerTid s -> do
              -- XXX this should be logged
              listenSock <- bindStatsSocket . scfStateDir . statsConf $ s
              newListenerTid <- startListenerThread listenSock
                                  (statsSocket . scfStateDir . statsConf $ s)
              loop s { listenerTid = newListenerTid }
          | tid `S.member` handlers s -> do
              whenJust reason $ \_ -> do
                -- XXX this should be logged
                return ()
              loop s { handlers = S.delete tid (handlers s) }
          | tid `S.member` deadListeners s ->
              loop s { deadListeners = S.delete tid (deadListeners s) }
          | isJust reason -> exit reason
          | otherwise -> loop s

  return (StatsServer (writeChan statsChan) statsServerTid, statsServerTid)
  where
    maxStatsHandlers = 32
    handlerTimeout = 10 * 10^6

    bindStatsSocket stateDir =
      E.bracketOnError (socket AF_UNIX Stream 0) sClose $ \sock -> do
        setSocketOption sock ReuseAddr 1
        ignoreJust E.ioErrors . removeFile . statsSocket $ stateDir
        bindSocket sock . SockAddrUnix . statsSocket $ stateDir
        setFileMode (statsSocket stateDir) 0o777
        listen sock sOMAXCONN
        return sock

-- | Reconfigure the stats server synchronously with the given function. If the
-- server exits abnormally before reconfiguring itself, throw its exit signal in
-- the calling thread.
reconfigureStatsServer :: (StatsConfig -> StatsConfig) -> StatsServer -> IO ()
reconfigureStatsServer reconf (StatsServer tellStatsServer statsServerTid) =
  sendSyncMessage (tellStatsServer . Reconfigure reconf) statsServerTid

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
  [ b 14 "BytesReceived "#     ~> bytesRecv
  , b 10 "BytesSent "#         ~> bytesSent
  , b 18 "DatagramsReceived "# ~> dgramsRecv
  , b 14 "PositivesSent "#     ~> positives
  , b 14 "NegativesSent "#     ~> negatives
  , b 11 "OthersSent "#        ~> others ]
  where
    line (x,f) = x `B.append` (B.pack . show $ f s) `B.append` b 2 "\r\n"#
    b = B.unsafePackAddress
    (~>) = (,)

-- | Generate the statistics socket path from the state directory path.
statsSocket :: FilePath -> FilePath
statsSocket = (++ "/statistics")

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
