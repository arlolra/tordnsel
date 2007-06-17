{-# LANGUAGE PatternGuards #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, STM, pattern guards)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Managing our current view of the Tor network. The network state constantly
-- changes as we receive new router information from Tor and new exit test
-- results.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.NetworkState.Internals (
  -- * Network state
    NetworkState(..)
  , Addrs
  , Routers
  , Router(..)
  , RunningStatus(..)
  , newNetworkState

  -- * State events
  , updateDescriptors
  , updateNetworkStatus
  , addCookie
  , deleteCookie
  , updateExitAddress
  , testComplete
  , readRouters
  , StateEvent(..)
  , TestState(..)
  , stateEventHandler
  , testableRouters
  , newExitAddress
  , updateDescs
  , updateStatuses
  , discardOldRouters
  , insertAddress
  , deleteAddress

  -- * Exit list queries
  , ExitListQuery(..)
  , isExitNode
  , isRunning

  -- * Exit tests
  , ExitTestState(..)
  , newExitTestState
  , addExitTest
  , ExitTestConfig(..)
  , bindListeningSockets
  , startTestListeners
  , startExitTests

  -- ** HTTP requests
  , createRequest
  , parseRequest

  -- ** Cookies
  , Cookie(..)
  , newCookie
  , cookieLen

  -- ** Exit test result storage
  , ExitAddress(..)
  , renderExitAddress
  , parseExitAddress
  , readExitAddresses
  , replaceExitAddresses
  , mkExitAddress
  , appendExitAddressToJournal
  , isJournalTooLarge

  -- ** Bounded transactional channels
  , BoundedTChan(..)
  , newBoundedTChan
  , readBoundedTChan
  , writeBoundedTChan

  -- * Helpers
  , b
  ) where

import Control.Arrow ((&&&))
import Control.Monad
  (liftM2, liftM3, forM, forM_, replicateM, replicateM_, guard)
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.STM
  ( STM, atomically, check, TVar, newTVar, newTVarIO, readTVar, writeTVar
  , TChan, newTChan, newTChanIO, readTChan, writeTChan )
import qualified Control.Exception as E
import qualified Data.ByteString as W
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (toLower, toUpper, isSpace)
import Data.Dynamic (fromDynamic)
import Data.List (foldl')
import Data.Maybe (mapMaybe, isNothing)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Set as S
import Data.Set (Set)
import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime, posixSecondsToUTCTime)
import Data.Word (Word16)
import Network.Socket
  ( Socket, ProtocolNumber, HostAddress, SockAddr(SockAddrInet), Family(AF_INET)
  , SocketOption(ReuseAddr), SocketType(Stream), socket, connect, bindSocket
  , listen, accept, setSocketOption, sOMAXCONN, socketToHandle, sClose )
import System.Directory (renameFile)
import System.IO
  (Handle, hClose, IOMode(ReadWriteMode, WriteMode), hFlush, openFile)
import System.Random (randomIO)
import System.Posix.Files (getFileStatus, fileSize)

import GHC.Prim (Addr#)

import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Socks
import TorDNSEL.System.Timeout
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Network state

-- | Our current view of the Tor network.
data NetworkState = NetworkState
  { -- | A map from listen address to routers.
    nsAddrs   :: {-# UNPACK #-} !(TVar Addrs),
    -- | All the routers we know about.
    nsRouters :: {-# UNPACK #-} !(TVar Routers),
    -- | A channel over which state changes are sent.
    nsChan    :: {-# UNPACK #-} !(Chan StateEvent) }

-- | A map from listen address to routers.
type Addrs = Map HostAddress (Set Fingerprint)

-- | All the routers we know about.
type Routers = Map Fingerprint Router

-- | A Tor router.
data Router = Router
  { -- | This router's descriptor, if we have it yet.
    rtrDescriptor    :: {-# UNPACK #-} !(Maybe Descriptor),
    -- | The address from which our last exit test originated.
    rtrExitAddr      :: {-# UNPACK #-} !(Maybe HostAddress),
    -- | The descriptor's published time when the last exit test was completed.
    rtrExitPublished :: {-# UNPACK #-} !(Maybe UTCTime),
    -- | Whether we think this router is running.
    rtrRunning       :: {-# UNPACK #-} !RunningStatus,
    -- | The last time we received a router status entry for this router.
    rtrLastStatus    :: {-# UNPACK #-} !UTCTime }

-- | Whether a router is running.
data RunningStatus
  = Running    -- ^ A router is running.
  | NotRunning -- ^ A router isn't Running.
  deriving Eq

-- | Create a new network state given the exit test state and the path to our
-- state directory. This should only be called once.
newNetworkState :: Maybe (ExitTestState, FilePath) -> IO NetworkState
newNetworkState exitTests = do
  state <- liftM3 NetworkState (newTVarIO M.empty) (newTVarIO M.empty) newChan
  forkIO $ stateEventHandler state exitTests
  return state

--------------------------------------------------------------------------------
-- State events

-- | Update the network state with new router descriptors.
updateDescriptors :: NetworkState -> [Descriptor] -> IO ()
updateDescriptors ns = writeChan (nsChan ns) . NewDesc

-- | Update the network state with new router status entries.
updateNetworkStatus :: NetworkState -> [RouterStatus] -> IO ()
updateNetworkStatus ns = writeChan (nsChan ns) . NewNS

-- | Register a cookie to router mapping.
addCookie :: NetworkState -> Cookie -> Fingerprint -> IO ()
addCookie ns = (writeChan (nsChan ns) .) . AddCookie

-- | Delete a cookie to router mapping.
deleteCookie :: NetworkState -> Cookie -> IO ()
deleteCookie ns = writeChan (nsChan ns) . DeleteCookie

-- | Update our known exit address from an incoming test connection.
updateExitAddress :: NetworkState -> Cookie -> HostAddress -> IO ()
updateExitAddress ns = (writeChan (nsChan ns) .) . NewExitAddress

-- | Signal that an exit test has finished.
testComplete :: NetworkState -> Fingerprint -> IO ()
testComplete ns = writeChan (nsChan ns) . TestComplete

-- | Extract the routers we know about from the network state.
readRouters :: NetworkState -> STM Routers
readRouters = readTVar . nsRouters

-- | A message sent to update the network state.
data StateEvent
  -- | New descriptors are available.
  = NewDesc {-# UNPACK #-} ![Descriptor]
  -- | New router status entries are available.
  | NewNS {-# UNPACK #-} ![RouterStatus]
  -- | Discard routers that haven't received status updates for a long time.
  | DiscardOldRouters
  -- | Map a new cookie to an exit node identity.
  | AddCookie {-# UNPACK #-} !Cookie  {-# UNPACK #-} !Fingerprint
  -- | Remove a cookie to exit node identity mapping.
  | DeleteCookie {-# UNPACK #-} !Cookie
  -- | We've received a cookie from an incoming test connection.
  | NewExitAddress {-# UNPACK #-} !Cookie  {-# UNPACK #-} !HostAddress
  -- | A test is finished, so remove it from the set of pending tests.
  | TestComplete {-# UNPACK #-} !Fingerprint

-- | An internal type representing the current exit test state.
data TestState = TestState
  { tsExitTests :: ExitTestState
  , tsStateDir  :: FilePath
  , tsCookies   :: Map Cookie Fingerprint
  , tsPending   :: Set Fingerprint
  , tsAddrLen, tsJournalLen :: Int
  , tsJournal   :: Handle }

-- | Receives and carries out state update events.
stateEventHandler :: NetworkState -> Maybe (ExitTestState, FilePath) -> IO ()
stateEventHandler state mbExitTests = do
  forkIO . forever $ do
    -- check for and discard old routers every 30 minutes
    threadDelay (30 * 60 * 10^6)
    writeChan (nsChan state) DiscardOldRouters

  testState <- case mbExitTests of
    Just (exitTests,stateDir) -> do
      exitAddrs <- readExitAddresses stateDir
      let routers = M.fromList $ map initialRouter exitAddrs
      atomically $ do
        writeTVar (nsRouters state) routers
        writeTVar (nsAddrs state) (foldl' insertExit M.empty exitAddrs)
      addrLen <- replaceExitAddresses stateDir routers
      journal <- openFile (stateDir ++ "/exit-addresses.new") WriteMode
      return . Just $
        TestState exitTests stateDir M.empty S.empty addrLen 0 journal
    _ -> return Nothing

  loop testState

  where
    insertExit addrs (ExitAddress fp addr _ _) = insertAddress addr fp addrs

    initialRouter (ExitAddress fp addr pub status) =
      (fp, Router Nothing (Just addr) (Just pub) NotRunning status)

    loop testState = do
      let loop' = loop testState
      event <- readChan $ nsChan state
      now <- getCurrentTime

      case event of
        NewDesc ds | Just s <- testState -> do
          testable <- atomically $ testableRouters state (tsPending s) ds
          atomically $ updateDescs now state ds
          atomically $ mapM_ (addExitTest (tsExitTests s)) testable
          loop $ Just s
            { tsPending = tsPending s `S.union` S.fromList testable }

        NewDesc ds -> atomically (updateDescs now state ds) >> loop'

        NewNS ns -> atomically (updateStatuses now state ns) >> loop'

        DiscardOldRouters -> atomically (discardOldRouters now state) >> loop'

        AddCookie c fp | Just s <- testState ->
          loop $ Just s { tsCookies = M.insert c fp (tsCookies s) }

        DeleteCookie c | Just s <- testState ->
          loop $ Just s { tsCookies = M.delete c (tsCookies s) }

        TestComplete fp | Just s <- testState ->
          loop $ Just s { tsPending = S.delete fp (tsPending s) }

        NewExitAddress c addr
          | Just s <- testState
          , Just fp <- c `M.lookup` tsCookies s -> do

          newRouter <- atomically $ newExitAddress state fp addr
          if isNothing newRouter then loop' else let Just r = newRouter in do

          len <- appendExitAddressToJournal (tsJournal s) fp r
          if not $ isJournalTooLarge (tsAddrLen s) (tsJournalLen s + len)
            then loop $ Just s { tsJournalLen = tsJournalLen s + len }
            else do
              hClose $ tsJournal s
              routers <- atomically . readTVar . nsRouters $ state
              newAddrLen <- replaceExitAddresses (tsStateDir s) routers
              h <- openFile (tsStateDir s ++ "/exit-addresses.new") WriteMode
              loop $ Just s
                { tsAddrLen = newAddrLen, tsJournalLen = 0, tsJournal = h }

        _ -> loop'

-- | Given a list of new descriptors and the set of currently pending tests,
-- return the fingerprints of routers we should add to the test queue.
testableRouters
  :: NetworkState -> Set Fingerprint -> [Descriptor] -> STM [Fingerprint]
testableRouters state pending ds = do
  routers <- readTVar $ nsRouters state
  return [fp d | d <- notPending, isTestable d (M.lookup (fp d) routers)]
  where
    isTestable d (Just r)
      | Just testPublished <- rtrExitPublished r
      , testPublished >= posixSecondsToUTCTime (descPublished d) = False
      | NotRunning <- rtrRunning r                               = False
    isTestable _ _                                               = True
    notPending = filter ((`S.notMember` pending) . descFingerprint) ds
    fp = descFingerprint

-- | Update the network state with the results of an exit test. Return the
-- updated router information.
newExitAddress
  :: NetworkState -> Fingerprint -> HostAddress -> STM (Maybe Router)
newExitAddress state fp addr = do
  routers <- readTVar $ nsRouters state
  case M.lookup fp routers of
    Just r | rtrExitAddr r /= Just addr -> do
      addrs <- readTVar $ nsAddrs state
      let addrs' = maybe id (\a -> deleteAddress a fp) (rtrExitAddr r) addrs
          newRouter = r { rtrExitAddr = Just addr
                        , rtrExitPublished = descPub r }
      writeTVar (nsAddrs state) $ insertAddress addr fp addrs'
      writeTVar (nsRouters state) $ M.insert fp newRouter routers
      return $ Just newRouter

    Just r -> do
      let newRouter = r { rtrExitPublished = descPub r }
      writeTVar (nsRouters state) $ M.insert fp newRouter routers
      return $ Just newRouter

    _ -> return Nothing
  where descPub = fmap (posixSecondsToUTCTime . descPublished) . rtrDescriptor

-- | Update our current view of router descriptors.
updateDescs :: UTCTime -> NetworkState -> [Descriptor] -> STM ()
updateDescs now state descs = do
  routers <- readTVar $ nsRouters state
  addrs   <- readTVar $ nsAddrs state
  let (routers',addrs') = foldl' updateDesc (routers, addrs) descs
  writeTVar (nsRouters state) routers'
  writeTVar (nsAddrs state) addrs'
  where
    updateDesc (routers,addrs) newD
      -- we know about this router already, but we might not have its descriptor
      | Just router <- M.lookup fp routers
      = case rtrDescriptor router of
          -- we have a descriptor, and therefore a possibly outdated address
          Just oldD
            -- the descriptor we already have is newer than this one
            | descPublished oldD > descPublished newD -> (routers ,addrs)
            -- address changed: delete old address, insert new address
            | descListenAddr newD /= descListenAddr oldD ->
                (updateRouters, insertAddr newD . deleteAddr oldD $ addrs)
            -- address hasn't changed: don't update addrs
            | otherwise -> (updateRouters, addrs)
          -- we didn't have an address before: insert new address
          _ -> (updateRouters, insertAddr newD addrs)
      -- this is a new router: insert into routers and addrs
      | otherwise = (insertRouters, insertAddr newD addrs)
      where
        fp = descFingerprint newD
        updateRouters =
          M.adjust (\r -> r { rtrDescriptor = Just newD }) fp routers
        insertRouters =
          M.insert fp (Router (Just newD) Nothing Nothing NotRunning now)
                   routers
        insertAddr d = insertAddress (descListenAddr d) fp
        deleteAddr d = deleteAddress (descListenAddr d) fp

-- | Update our current view of router status entries.
updateStatuses :: UTCTime -> NetworkState -> [RouterStatus] -> STM ()
updateStatuses now state ns = do
  routers <- readTVar $ nsRouters state
  writeTVar (nsRouters state) $ foldl' updateStatus routers ns
  where
    updateStatus routers rs =
      M.alter (Just . maybe newRouter updateRouter) (rsFingerprint rs) routers
      where
        newRouter = Router Nothing Nothing Nothing running now
        updateRouter r = r { rtrRunning = running, rtrLastStatus = now }
        running = if rsIsRunning rs then Running else NotRunning

-- | Discard routers whose last status update was received more than
-- @routerMaxAge@ seconds ago.
discardOldRouters :: UTCTime -> NetworkState -> STM ()
discardOldRouters now state = do
  routers <- readTVar $ nsRouters state
  addrs   <- readTVar $ nsAddrs state
  let (oldRouters,routers') = M.partition isOld routers
      addrs' = foldl' deleteAddr addrs $ M.toList oldRouters
  writeTVar (nsRouters state) routers'
  writeTVar (nsAddrs state) addrs'
  where
    routerMaxAge = 60 * 60 * 48
    isOld r = now `diffUTCTime` rtrLastStatus r > routerMaxAge
    deleteAddr addrs (fp,r) =
      maybe id (\d -> deleteAddress (descListenAddr d) fp) (rtrDescriptor r) .
      maybe id (\a -> deleteAddress a fp) (rtrExitAddr r) $ addrs

-- | Add a new router associated with a listen address to the network state.
insertAddress :: HostAddress -> Fingerprint -> Addrs -> Addrs
insertAddress addr fp =
  M.alter (Just . maybe (S.singleton fp) (S.insert fp)) addr

-- | Remove a router associated with a listen address from the network state.
deleteAddress :: HostAddress -> Fingerprint -> Addrs -> Addrs
deleteAddress addr fp = M.update deleteFingerprint addr
  where
    deleteFingerprint set
      | S.null set' = Nothing
      | otherwise   = Just set'
      where set' = S.delete fp set

--------------------------------------------------------------------------------
-- Exit list queries

-- | Queries asking whether there's a Tor exit node at a specific IP address.
data ExitListQuery
  -- |  Query type 1 from
  -- <https://tor.eff.org/svn/trunk/doc/contrib/torel-design.txt>.
  = IPPort
  { -- | The address of the candidate exit node.
    queryAddr :: {-# UNPACK #-} !HostAddress,
    -- | The destination address.
    destAddr  :: {-# UNPACK #-} !HostAddress,
    -- | The destination port.
    destPort  :: {-# UNPACK #-} !Word16
  } deriving Eq

instance Show ExitListQuery where
  showsPrec _ (IPPort a c d) = ("query ip: " ++) . (inet_htoa a ++) .
    (" dest ip: " ++) . (inet_htoa c ++) . (" dest port: " ++) . shows d

-- | Does a query represent a Tor exit node cabable of exiting to a particular
-- network service in our current view of the Tor network?
isExitNode :: NetworkState -> ExitListQuery -> IO Bool
{-# INLINE isExitNode #-}
isExitNode state q = do
  now <- getPOSIXTime
  atomically $ do
    addrs <- readTVar $ nsAddrs state
    case M.lookup (queryAddr q) addrs of
      Nothing  -> return False
      Just set -> do
        rs <- readTVar $ nsRouters state
        return $! any (isExit now) . mapMaybe (lookupDesc rs) . S.elems $ set
  where
    lookupDesc routers fp = M.lookup fp routers >>= rtrDescriptor
    isExit t d = isRunning t d &&
                 exitPolicyAccepts (destAddr q) (destPort q) (descExitPolicy d)

-- | We consider a router to be running if it last published a descriptor less
-- than 48 hours ago. Descriptors hold an unboxed 'POSIXTime' instead of a
-- 'UTCTime' to prevent this function from showing up in profiles.
isRunning :: POSIXTime -> Descriptor -> Bool
{-# INLINE isRunning #-}
isRunning now d = now - descPublished d < routerMaxAge
  where routerMaxAge = 60 * 60 * 48

--------------------------------------------------------------------------------
-- Exit tests

-- | The exit test state.
newtype ExitTestState = ExitTestState { unETState :: TChan Fingerprint }

-- | Create a new exit test state to be passed to 'newNetworkState'.
newExitTestState :: IO ExitTestState
newExitTestState = ExitTestState `fmap` newTChanIO

-- | Schedule an exit test through a router.
addExitTest :: ExitTestState -> Fingerprint -> STM ()
addExitTest = writeTChan . unETState

-- | Bind the listening sockets we're going to use for incoming exit tests. This
-- action exists so we can listen on privileged ports prior to dropping
-- privileges. The address and ports should be in host order.
bindListeningSockets :: ProtocolNumber -> HostAddress -> [Word16] -> IO [Socket]
bindListeningSockets tcp listenAddr listenPorts =
  forM listenPorts $ \port -> do
    sock <- socket AF_INET Stream tcp
    setSocketOption sock ReuseAddr 1
    bindSocket sock (SockAddrInet (fromIntegral port) (htonl listenAddr))
    listen sock sOMAXCONN
    return sock

-- | Configuration for exit tests.
data ExitTestConfig = ExitTestConfig
  { etState       :: ExitTestState
  , etNetState    :: NetworkState
  , etTcp         :: ProtocolNumber
  , etConcTests   :: Int
  , etSocksServer :: SockAddr
  , etListenSocks :: [Socket]
  , etTestAddr    :: HostAddress
  , etTestPorts   :: [Word16] }

-- | Fork all our exit test listeners.
startTestListeners :: NetworkState -> [Socket] -> Int -> IO ()
startTestListeners netState listenSockets concTests = do
  -- We need to keep the number of open FDs below FD_SETSIZE as long as GHC uses
  -- select instead of epoll or kqueue. Client sockets waiting in this channel
  -- count against that limit. We use a bounded channel so incoming connections
  -- can't lead to unbounded memory use.
  clients <- atomically $ newBoundedTChan 64

  forM_ listenSockets $ \sock -> forkIO . forever $ do
    (client,(SockAddrInet _ addr)) <- accept sock
    atomically $ writeBoundedTChan clients (client, ntohl addr)

  replicateM_ concTests . forkIO . forever $ do
    (client,addr) <- atomically $ readBoundedTChan clients
    handle <- socketToHandle client ReadWriteMode
    timeout (30 * 10^6) . ignoreJust E.ioErrors $ do
      r <- (parseRequest . L.take 2048) `fmap` L.hGetContents handle
      case r of
        Just cookie -> do
          updateExitAddress netState cookie addr
          B.hPut handle $ b 27 "HTTP/1.0 204 No Content\r\n\r\n"#
        _ ->
          B.hPut handle $ b 28 "HTTP/1.0 400 Bad Request\r\n\r\n"#
    ignoreJust E.ioErrors $ hClose handle

  where ignoreJust p = E.handleJust p (const $ return ())

-- | Fork all our exit test listeners and initiators.
startExitTests :: ExitTestConfig -> IO ()
startExitTests conf = do
  startTestListeners (etNetState conf) (etListenSocks conf) (etConcTests conf)

  replicateM_ (etConcTests conf) . forkIO . forever $ do
    fp      <- atomically . readTChan . unETState . etState $ conf
    routers <- atomically . readRouters . etNetState $ conf
    let mbPorts = do
          rtr <- M.lookup fp routers
          guard $ rtrRunning rtr == Running
          ports@(_:_) <- allowedPorts `fmap` rtrDescriptor rtr
          return ports

    -- Skip the test if this router's exit policy doesn't allow connections to
    -- any of our listening ports.
    whenJust mbPorts $ \ports -> do
      cookie <- newCookie
      addCookie (etNetState conf) cookie fp
      -- try to connect eight times before giving up
      attempt . take 8 . map (testConnection cookie fp testHost) . cycle $ ports
      deleteCookie (etNetState conf) cookie

    testComplete (etNetState conf) fp

  where
    testConnection cookie fp host port =
      E.handleJust connExceptions (const $ return False) .
        fmap (maybe False (const True)) .
          timeout (2 * 60 * 10^6) $ do
            sock <- repeatConnectSocks
            withSocksConnection sock exitHost port $ \handle -> do
              B.hPut handle $ createRequest host port cookie
              B.hGet handle 1024 -- ignore response
              return ()
      where
        exitHost = B.concat
          [host, b 2 ".$"#, encodeBase16Fingerprint fp, b 5 ".exit"#]

    allowedPorts desc =
      [ p | p <- etTestPorts conf
          , exitPolicyAccepts (etTestAddr conf) p (descExitPolicy desc) ]

    testHost = B.pack . inet_htoa . etTestAddr $ conf

    repeatConnectSocks = do
      r <- E.tryJust E.ioErrors $ do
        sock <- socket AF_INET Stream (etTcp conf)
        connect sock (etSocksServer conf)
          `E.catch` \e -> sClose sock >> E.throwIO e
        return sock
      -- When connecting to Tor's socks port fails, wait five seconds
      -- and try again.
      -- XXX this should be logged
      either (const $ threadDelay (5 * 10^6) >> repeatConnectSocks) return r

    attempt (io:ios) = do
      p <- io
      if p then return True
           else attempt ios
    attempt [] = return False

    connExceptions e@(E.IOException _)           = Just e
    connExceptions e@(E.DynException e')
      | Just (_ :: SocksError) <- fromDynamic e' = Just e
    connExceptions _                             = Nothing

--------------------------------------------------------------------------------
-- HTTP requests

-- | Create an HTTP request that POSTs a cookie to one of our listening ports.
createRequest :: B.ByteString -> Word16 -> Cookie -> B.ByteString
createRequest host port cookie =
  B.join (b 2 "\r\n"#)
  -- POST should force caching proxies to forward the request.
  [ b 15 "POST / HTTP/1.0"#
  -- Host doesn't exist in HTTP 1.0. We'll use it anyway to help the request
  -- traverse transparent proxies.
  , b 6 "Host: "# `B.append` hostValue
  , b 38 "Content-Type: application/octet-stream"#
  , b 16 "Content-Length: "# `B.append` B.pack (show cookieLen)
  , b 2 "\r\n"# `B.append` unCookie cookie ]
  where
    hostValue
      | port == 80 = host
      | otherwise  = B.concat [host, b 1 ":"#, B.pack $ show port]

-- | Given an HTTP request, return the cookie contained in the body if it's
-- well-formatted, otherwise return 'Nothing'.
parseRequest :: L.ByteString -> Maybe Cookie
parseRequest req = do
  (reqLine:headerLines,body) <- return $ breakHeaders req
  [method,_,http] <- return $ L.split ' ' reqLine
  [prot,ver]      <- return $ L.split '/' http
  guard $ and [ method == l 4 "POST"#, prot == l 4 "HTTP"#
              , ver `elem` [l 3 "1.0"#, l 3 "1.1"#] ]

  let headers = M.fromList $ map parseHeader headerLines
  typ <- l 12 "content-type"# `M.lookup` headers
  len <- (readInt . B.concat . L.toChunks)
      =<< l 14 "content-length"# `M.lookup` headers
  guard $ typ == l 24 "application/octet-stream"# && len == cookieLen

  return $! Cookie . B.concat . L.toChunks . L.take cookieLen' $ body

  where
    parseHeader line = (L.map toLower name, L.dropWhile isSpace $ L.drop 1 rest)
      where (name,rest) = L.break (==':') line

    breakHeaders bs
      | L.null x  = ([], L.drop 2 rest)
      | otherwise = (x:xs, rest')
      where
        (x,rest)   = L.break (=='\r') bs
        (xs,rest') = breakHeaders (L.drop 2 rest)

    cookieLen' = fromIntegral cookieLen

    l len addr = L.fromChunks [B.unsafePackAddress len addr]

--------------------------------------------------------------------------------
-- Cookies

-- | A cookie containing pseudo-random data that we send in an HTTP request. We
-- associate it with the exit node we're testing through and use it look up that
-- exit node when we receive it on a listening port.
newtype Cookie = Cookie { unCookie :: B.ByteString }
  deriving (Eq, Ord)

-- | Create a new cookie from pseudo-random data.
newCookie :: IO Cookie
newCookie = do
  rs <- replicateM cookieLen randomIO :: IO [Int]
  return . Cookie . W.pack . map fromIntegral $ rs

-- | The cookie length.
cookieLen :: Int
cookieLen = 32

--------------------------------------------------------------------------------
-- Exit test result storage

-- | An exit address entry stored in our state directory. The design here is the
-- same as Tor uses for storing router descriptors.
data ExitAddress = ExitAddress
  { -- | The fingerprint of the exit node we tested through.
    eaFingerprint :: {-# UNPACK #-} !Fingerprint,
    -- | The address from which our test connection originated.
    eaExitAddress :: {-# UNPACK #-} !HostAddress,
    -- | The current descriptor published time during the test. We don't perform
    -- another test until a newer descriptor arrives.
    eaPublished   :: {-# UNPACK #-} !UTCTime,
    -- | The last time we received a network status update for this router, set
    -- during the test. This helps us decide when to discard a router.
    eaLastStatus  :: {-# UNPACK #-} !UTCTime
  }

-- | Exit test results are represented using the same document meta-format Tor
-- uses for router descriptors and network status documents.
renderExitAddress :: ExitAddress -> B.ByteString
renderExitAddress x =
  B.unlines
  [ b 9 "ExitNode "# `B.append` renderFP (eaFingerprint x)
  , b 12 "ExitAddress "# `B.append` (B.pack . inet_htoa . eaExitAddress $ x)
  , b 10 "Published "# `B.append` renderTime (eaPublished x)
  , b 11 "LastStatus "# `B.append` renderTime (eaLastStatus x) ]
  where
    renderFP = B.unwords . split 4 . B.map toUpper . encodeBase16Fingerprint
    renderTime = B.pack . take 19 . show

-- | Parse a single exit address entry, 'fail'ing in the monad if parsing fails.
parseExitAddress :: Monad m => Document -> m ExitAddress
parseExitAddress items = do
  fp         <- decodeBase16Fingerprint . B.filter (/= ' ')
                          =<< findArg (b 8  "ExitNode"#    ==) items
  addr       <- inet_atoh =<< findArg (b 11 "ExitAddress"# ==) items
  published  <- parseTime =<< findArg (b 9  "Published"#   ==) items
  lastStatus <- parseTime =<< findArg (b 10 "LastStatus"#  ==) items
  return $! ExitAddress fp addr published lastStatus

-- | On startup, read the exit test results from the state directory.
readExitAddresses :: FilePath -> IO [ExitAddress]
readExitAddresses stateDir =
  fmap (M.elems . M.fromList . map (eaFingerprint &&& id))
       (liftM2 (++) (addrs "/exit-addresses") (addrs "/exit-addresses.new"))
  where
    addrs = fmap parseAddrs . readAddrs
    parseAddrs =
      parseSubDocs (b 8 "ExitNode"#) parseExitAddress . parseDocument . B.lines
    readAddrs fp = B.readFile (stateDir ++ fp) `E.catch` const (return B.empty)

-- | On startup, and when the journal becomes too large, replace the
-- exit-addresses file with our most current test results and clear the journal.
-- Return the new exit-addresses file's size in bytes.
replaceExitAddresses :: FilePath -> Routers -> IO Int
replaceExitAddresses stateDir routers = do
  L.writeFile (dir "/exit-addresses.tmp") (L.fromChunks $ addrs routers)
  renameFile (dir "/exit-addresses.tmp") (dir "/exit-addresses")
  writeFile (dir "/exit-addresses.new") ""
  (fromIntegral . fileSize) `fmap` getFileStatus (dir "/exit-addresses")
  where
    addrs = mapMaybe (fmap renderExitAddress . mkExitAddress) . M.toList
    dir = (stateDir ++)

-- | Return an exit address entry if we have enough information to create one.
mkExitAddress :: (Fingerprint, Router) -> Maybe ExitAddress
mkExitAddress (fp,r) = do
  addr <- rtrExitAddr r
  published <- rtrExitPublished r
  return $! ExitAddress fp addr published (rtrLastStatus r)

-- | Add an exit address entry to the journal. Return the entry's length in
-- bytes.
appendExitAddressToJournal :: Handle -> Fingerprint -> Router -> IO Int
appendExitAddressToJournal journal fp r
  | Just addr <- renderExitAddress `fmap` mkExitAddress (fp,r) = do
      B.hPut journal addr >> hFlush journal
      return $ B.length addr
  | otherwise = return 0

-- | Is the exit address journal large enough that it should be cleared?
isJournalTooLarge :: Int -> Int -> Bool
isJournalTooLarge addrLen journalLen
  | addrLen > 16384 = journalLen > addrLen `div` 2
  | otherwise       = journalLen > 8192

--------------------------------------------------------------------------------
-- Bounded transactional channels

-- | An abstract type representing a transactional channel of bounded size.
data BoundedTChan a = BTChan (TChan a) (TVar Int) Int

-- | Create a new bounded channel of a given size.
newBoundedTChan :: Int -> STM (BoundedTChan a)
newBoundedTChan maxSize = do
  currentSize <- newTVar 0
  chan <- newTChan
  return (BTChan chan currentSize maxSize)

-- | Read from a bounded channel, blocking until an item is available.
readBoundedTChan :: BoundedTChan a -> STM a
readBoundedTChan (BTChan chan currentSize _) = do
  size <- readTVar currentSize
  writeTVar currentSize (size - 1)
  readTChan chan

-- | Write to a bounded channel, blocking until the channel is smaller than its
-- maximum size.
writeBoundedTChan :: BoundedTChan a -> a -> STM ()
writeBoundedTChan (BTChan chan currentSize maxSize) x = do
  size <- readTVar currentSize
  check (size < maxSize)
  writeTVar currentSize (size + 1)
  writeTChan chan x

--------------------------------------------------------------------------------
-- Helpers

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
