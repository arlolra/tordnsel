{-# OPTIONS_GHC -fglasgow-exts -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Statistics.Internals
-- Copyright   : (c) tup 2007
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
module TorDNSEL.Statistics.Internals (
    Stats(..)
  , StatsHandle(..)
  , openStatsListener
  , renderStats
  , statsSocket
  , unlinkStatsSocket
  , incrementBytes
  , incrementResponses
  ) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (MVar, newMVar, modifyMVar_, readMVar)
import Control.Concurrent.STM (atomically)
import qualified Control.Exception as E
import Control.Monad (replicateM_)
import qualified Data.ByteString.Char8 as B
import Network.Socket
  ( socket, bindSocket, listen, accept, sClose, setSocketOption, socketToHandle
  , SockAddr(SockAddrUnix), Family(AF_UNIX), SocketType(Stream)
  , SocketOption(ReuseAddr), sOMAXCONN )
import System.Directory (removeFile)
import System.IO (hClose, IOMode(ReadWriteMode))
import System.Posix.Files (setFileMode)

import TorDNSEL.DNS.Server
import TorDNSEL.System.Timeout
import TorDNSEL.Util

-- | Cumulative counts of bytes transferred, datagrams received, and responses
-- sent.
data Stats = Stats
  { bytesRecv, bytesSent, dgramsRecv, positives
  , negatives, others :: {-# UNPACK #-} !Integer }

-- | The current statistics state.
newtype StatsHandle = SH (MVar Stats)

-- | Open a listening stream socket in our state directory. When we accept a
-- connection, dump the current statistics counts and close the client socket.
openStatsListener :: FilePath -> IO StatsHandle
openStatsListener stateDir = do
  listener <- E.bracketOnError (socket AF_UNIX Stream 0) sClose $ \sock -> do
    setSocketOption sock ReuseAddr 1
    ignoreJust E.ioErrors . removeFile . statsSocket $ stateDir
    bindSocket sock . SockAddrUnix . statsSocket $ stateDir
    setFileMode (statsSocket stateDir) 0o777
    listen sock sOMAXCONN
    return sock

  clients <- atomically $ newBoundedTChan 8
  forkIO . forever $
    accept listener >>= atomically . writeBoundedTChan clients . fst

  stats <- newMVar $ Stats 0 0 0 0 0 0

  replicateM_ 32 . forkIO . forever $ do
    client <- atomically $ readBoundedTChan clients
    handle <- socketToHandle client ReadWriteMode
    timeout (30 * 10^6) . ignoreJust E.ioErrors $
      B.hPut handle . renderStats =<< readMVar stats
    ignoreJust E.ioErrors $ hClose handle

  return $ SH stats

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

-- | Remove the statistics socket from the file system.
unlinkStatsSocket :: FilePath -> IO ()
unlinkStatsSocket = ignoreJust E.ioErrors . removeFile . statsSocket

-- | Increment the count of bytes transferred.
incrementBytes :: StatsHandle -> Int -> Int -> IO ()
incrementBytes (SH stats) received sent =
  modifyMVar_ stats $ \s -> return $!
    s { bytesRecv  = bytesRecv s + fromIntegral received
      , bytesSent  = bytesSent s + fromIntegral sent
      , dgramsRecv = dgramsRecv s + 1 }

-- | Increment the count of DNSEL responses.
incrementResponses :: StatsHandle -> ResponseType -> IO ()
incrementResponses (SH stats) resp =
  modifyMVar_ stats $ \s -> return $!
    case resp of
      Negative -> s { negatives = negatives s + 1 }
      Positive -> s { positives = positives s + 1 }
      Other    -> s { others    = others    s + 1 }
