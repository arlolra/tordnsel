{-# LANGUAGE PatternGuards, BangPatterns #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitTest.Server.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions, pattern guards,
--                             bang patterns, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- A thread that accepts test connections we have initiated through exit nodes
-- to determine the IP addresses exit nodes make connections through.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.ExitTest.Server.Internals where

import Prelude hiding (log)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan, isEmptyChan)
import Control.Concurrent.MVar (newEmptyMVar, tryPutMVar, takeMVar)
import Control.Concurrent.QSemN (QSemN, newQSemN, waitQSemN, signalQSemN)
import qualified Control.Exception as E
import Control.Monad (when, forM, foldM)
import Control.Monad.Fix (fix)
import Control.Monad.Trans (lift)
import qualified Data.ByteString.Char8 as B
import qualified Data.Foldable as F
import qualified Data.Map as M
import Data.Map (Map)
import Data.Maybe (catMaybes, fromJust, isJust)
import qualified Data.Set as S
import Data.Set (Set)
import Data.Time (UTCTime, getCurrentTime)
import Network.Socket
  ( HostAddress, Socket, SockAddr(SockAddrInet), accept, sClose, getSocketName
  , socketToHandle )
import System.IO (hClose, IOMode(ReadWriteMode))
import System.IO.Error (isEOFError)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.ExitTest.Request
import TorDNSEL.Log
import TorDNSEL.System.Timeout
import TorDNSEL.Util

-- | A handle to the exit test server thread.
data ExitTestServer = ExitTestServer (ServerMessage -> IO ()) ThreadId

instance Thread ExitTestServer where
  threadId (ExitTestServer _ tid) = tid

-- | The exit test server configuration.
data ExitTestServerConfig = ExitTestServerConfig
  { -- | Notify the network state manager of a received exit test request.
    etscfNotifyNewExitAddress :: !(UTCTime -> Cookie -> HostAddress -> IO ()),
    -- | The maximum number of exit test clients to serve concurrently.
    etscfConcClientLimit      :: !Integer,
    -- | The addresses on which the server should listen for connections.
    etscfListenAddrs          :: !(Set SockAddr) }

-- | An internal type representing the current exit test server state.
data ServerState = ServerState
  { serverChan      :: !(Chan ServerMessage)
  , handlerSem      :: !QSemN
  , handlers        :: !(Set ThreadId)
  , listenerThreads :: !(Map ThreadId Listener)
  , deadListeners   :: !(Set ThreadId) }

-- | An exit test listener.
data Listener = Listener
  { listenAddr  :: !SockAddr    -- ^ The address to which the listener is bound.
  , listenSock  :: !Socket      -- ^ The listening socket.
  , socketOwner :: !SocketOwner -- ^ The listening socket's owner thread.
  }

-- | The thread responsible for a given listening socket. If a socket is owned
-- by the supervisor, we won't attempt to 'sClose' it. The idea is to prevent
-- unnecessarily closing a socket that requires root privileges to open.
data SocketOwner
  = SupervisorOwned -- ^ Owned by the supervisor thread.
  | ExitTestServerOwned -- ^ Owned by the exit test server thread.
  deriving Eq

-- | An internal type for messages sent to the exit test server.
data ServerMessage
  = NewClient Socket HostAddress -- ^ A new client accepted by a listener.
  -- | Reconfigure the exit test server.
  | Reconfigure (ExitTestServerConfig -> ExitTestServerConfig) (IO ())
  | Terminate ExitReason -- ^ Terminate the exit test server gracefully.
  | Exit ThreadId ExitReason -- ^ An exit signal sent to the exit test server.

-- | Start the exit test server thread, given an initial config and a list of
-- listeners, returning a handle to the thread. If the exit test server exits
-- abnormally before initializing itself, throw its exit signal in the calling
-- thread. Link the exit test server thread to the calling thread. If the exit
-- test server exits before completely starting, throw its exit signal in the
-- calling thread.
startExitTestServer
  :: [(SockAddr, Maybe Socket)] -> ExitTestServerConfig -> IO ExitTestServer
startExitTestServer socks initConf = do
  log Notice "Starting exit test server."
  chan <- newChan
  err <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar err
  tid <- forkLinkIO $ do
    setTrapExit $ (writeChan chan .) . Exit
    sem <- newQSemN . fromIntegral . etscfConcClientLimit $ initConf
    listeners <- fmap catMaybes . forM socks $ \(addr,mbSock) -> runMaybeT $ do
      sock <- reopenSocketIfClosed addr mbSock
      let owner | mbSock == Just sock = SupervisorOwned
                | otherwise           = ExitTestServerOwned
      tid <- lift $ startListenerThread ((writeChan chan .) . NewClient) sem
                                        owner sock
      return (tid, Listener addr sock owner)

    putResponse Nothing

    let initConf' = initConf { etscfListenAddrs =
                                 S.fromList $ map (listenAddr . snd) listeners }
        initState = ServerState chan sem S.empty (M.fromList listeners) S.empty
    fix (\loop (!conf,!s) -> readChan chan >>= handleMessage conf s >>= loop)
        (initConf', initState)

  withMonitor tid putResponse $
    takeMVar err >>= flip whenJust E.throwIO
  return $ ExitTestServer (writeChan chan) tid

-- | Start a listener thread, returning its 'ThreadId'.
startListenerThread :: (Socket -> HostAddress -> IO ()) -> QSemN -> SocketOwner
                    -> Socket -> IO ThreadId
startListenerThread notifyServerNewClient sem owner listener =
  forkLinkIO . E.block . finallyCloseSocket . forever $ do
    waitQSemN sem 1
    (client,SockAddrInet _ addr) <- E.unblock (accept listener)
      `E.catch` \e -> signalQSemN sem 1 >> E.throwIO e
    let addr' = ntohl addr
    log Debug "Accepted exit test client from " (inet_htoa addr') '.'
    notifyServerNewClient client addr'
  where
    finallyCloseSocket = case owner of
      ExitTestServerOwned -> (`E.finally` sClose listener)
      SupervisorOwned -> id

-- | Given an optional listening socket, return it if it's open. Otherwise,
-- attempt to reopen it, returning the new socket if successful.
reopenSocketIfClosed :: SockAddr -> Maybe Socket -> MaybeT IO Socket
reopenSocketIfClosed addr mbSock = MaybeT $ do
  isOpen <- isListeningSocketOpen mbSock
  if isOpen
    then return mbSock
    else do
      whenJust mbSock sClose
      r <- E.tryJust E.ioErrors $ bindListeningTCPSocket addr
      case r of
        Left e -> do
          log Warn "Opening exit test listener on " addr " failed: " e "; \
                   \skipping listener."
          return Nothing
        Right sock -> do
          log Info "Opened exit test listener on " addr '.'
          return $ Just sock
  where
    isListeningSocketOpen Nothing = return False
    isListeningSocketOpen (Just sock) =
      getSocketName sock >> return True `catch` const (return False)

-- | Process a 'ServerMessage' and return the new config and state, given the
-- current config and state.
handleMessage :: ExitTestServerConfig -> ServerState -> ServerMessage
              -> IO (ExitTestServerConfig, ServerState)
handleMessage conf s (NewClient sock addr) = do
  tid <- forkLinkIO . (`E.finally` signalQSemN (handlerSem s) 1) .
    E.bracket (socketToHandle sock ReadWriteMode) hClose $ \client -> do
      r <- timeout readTimeout . E.tryJust E.ioErrors $ do
        r <- runMaybeT $ getRequest client
        case r of
          Just cookie -> do
            now <- getCurrentTime
            etscfNotifyNewExitAddress conf now cookie addr
            B.hPut client $ b 46 "HTTP/1.0 204 No Content\r\n\
                                 \Connection: close\r\n\r\n"#
          _ -> do
            log Info "Received invalid HTTP request from " (inet_htoa addr)
                     "; discarding."
            B.hPut client $ b 47 "HTTP/1.0 400 Bad Request\r\n\
                                 \Connection: close\r\n\r\n"#
      case r of
        Just (Left e) -> do
          let msg | isEOFError e = "Connection closed by other side"
                  | otherwise    = show e
          log Info "Error reading HTTP request from " (inet_htoa addr) ": " msg
        Nothing -> log Info "Reading HTTP request from " (inet_htoa addr)
                            " timed out."
        _ -> return ()
  return (conf, s { handlers = S.insert tid (handlers s) })
  where
    readTimeout = 30 * 10^6
    b = B.unsafePackAddress

handleMessage conf s (Reconfigure reconf signal) = do
  when (limitDiff /= 0) $
    signalQSemN (handlerSem s) (fromIntegral limitDiff)
  if etscfListenAddrs conf == etscfListenAddrs newConf
    then signal >> return (newConf, s)
    else do
      deadListeners' <- foldM killListener (deadListeners s)
                              (M.assocs closeListeners)
      listeners' <- (M.union unchangedListeners . M.fromList . catMaybes)
                      `fmap` mapM openListener (S.elems open)
      signal
      return ( newConf { etscfListenAddrs = S.fromList . map listenAddr .
                                              M.elems $ listeners' }
             , s { listenerThreads = listeners'
                 , deadListeners = deadListeners' } )
  where
    killListener dead (tid,listener) = do
      closeListener tid listener
      return $! S.insert tid dead
    openListener addr = runMaybeT $ do
      sock <- reopenSocketIfClosed addr Nothing
      tid <- lift $ startListenerThread
                      ((writeChan (serverChan s) .) . NewClient) (handlerSem s)
                      ExitTestServerOwned sock
      return (tid, Listener addr sock ExitTestServerOwned)
    (closeListeners,unchangedListeners) =
      M.partition ((`S.member` close) . listenAddr) (listenerThreads s)
    (close,open) = S.partition (`S.member` etscfListenAddrs conf) changed
    changed = S.difference
      (etscfListenAddrs conf `S.union` etscfListenAddrs newConf)
      (etscfListenAddrs conf `S.intersection` etscfListenAddrs newConf)
    limitDiff = etscfConcClientLimit newConf - etscfConcClientLimit conf
    newConf = reconf conf

handleMessage _conf s (Terminate reason) = do
  log Notice "Terminating exit test server."
  mapM_ (uncurry closeListener) (M.assocs $ listenerThreads s)
  F.mapM_ (\tid -> terminateThread Nothing tid (killThread tid))
          (handlers s)
  msgs <- untilM (isEmptyChan $ serverChan s) (readChan $ serverChan s)
  sequence_ [sClose client | NewClient client _ <- msgs]
  exit reason

handleMessage conf s (Exit tid reason)
  | tid `S.member` handlers s = do
      whenJust reason $ \e ->
        log Warn "Bug: An exit test client handler exited abnormally: " e
      return (conf, s { handlers = S.delete tid (handlers s) })
  | tid `S.member` deadListeners s
  = return (conf, s { deadListeners = S.delete tid (deadListeners s) })
  | Just (Listener addr sock owner) <- tid `M.lookup` listenerThreads s = do
      log Warn "An exit test listener thread for " addr " exited unexpectedly: "
               (fromJust reason) "; restarting."
      mbSock <- runMaybeT $ reopenSocketIfClosed addr (Just sock)
      case mbSock of
        -- The socket couldn't be reopened, so drop the listener.
        Nothing ->
          return ( conf { etscfListenAddrs =
                            S.delete addr (etscfListenAddrs conf) }
                 , s { listenerThreads = M.delete tid (listenerThreads s) } )
        Just sock' -> do
          -- If the socket was reopened, we own it now.
          let owner' | sock /= sock' = ExitTestServerOwned
                     | otherwise     = owner
              listener' = Listener addr sock' owner'
          tid' <- startListenerThread ((writeChan (serverChan s) .) . NewClient)
                                      (handlerSem s) owner sock
          listener' `seq` return
            (conf, s { listenerThreads = M.insert tid' listener' .
                                           M.delete tid $ listenerThreads s })
  | isJust reason = exit reason
  | otherwise = return (conf, s)

-- | Close an exit test listener.
closeListener :: ThreadId -> Listener -> IO ()
closeListener tid listener = do
  terminateThread Nothing tid (killThread tid)
  when (socketOwner listener == ExitTestServerOwned) $
    log Info "Closed exit test listener on " (listenAddr listener) '.'

-- | Reconfigure the exit test server synchronously with the given function. If
-- the server exits abnormally before reconfiguring itself, throw its exit
-- signal in the calling thread.
reconfigureExitTestServer
  :: (ExitTestServerConfig -> ExitTestServerConfig) -> ExitTestServer -> IO ()
reconfigureExitTestServer reconf (ExitTestServer send tid) =
  sendSyncMessage (send . Reconfigure reconf) tid

-- | Terminate the exit test server gracefully. The optional parameter specifies
-- the amount of time in microseconds to wait for the thread to terminate. If
-- the thread hasn't terminated by the timeout, an uncatchable exit signal will
-- be sent.
terminateExitTestServer :: Maybe Int -> ExitTestServer -> IO ()
terminateExitTestServer mbWait (ExitTestServer send tid) =
  terminateThread mbWait tid (send $ Terminate Nothing)
