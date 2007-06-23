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
    Network(..)
  , newNetwork
  , NetworkState(..)
  , emptyNetworkState
  , Router(..)
  , TestResults(..)

  -- * State events
  , updateDescriptors
  , updateNetworkStatus
  , withCookie
  , updateExitAddress
  , testComplete
  , readNetworkState
  , StateEvent(..)
  , TestState(..)
  , stateEventHandler
  , eventHandler
  , testingEventHandler
  , isTestable
  , newExitAddress
  , newDescriptor
  , newRouterStatus
  , discardOldRouters
  , insertAddress
  , deleteAddress

  -- * Exit list queries
  , ExitListQuery(..)
  , isExitNode
  , isRunning

  -- * Exit tests
  , ExitTestChan(..)
  , newExitTestChan
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
import Control.Monad (liftM2, forM, forM_, replicateM_, guard)
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newMVar, readMVar, swapMVar)
import Control.Concurrent.STM
  ( STM, atomically, check, TVar, newTVar, readTVar, writeTVar
  , TChan, newTChan, readTChan, writeTChan )
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (toLower, toUpper, isSpace)
import Data.Dynamic (fromDynamic)
import Data.List (foldl')
import Data.Maybe (mapMaybe)
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
import System.Posix.Files (getFileStatus, fileSize)

import GHC.Prim (Addr#)

import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Random
import TorDNSEL.Socks
import TorDNSEL.System.Timeout
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Network state

-- | An abstract type supporting the interface to reading and updating the
-- network state.
data Network = Network
  { -- | A channel over which state changes are sent.
    nChan  :: {-# UNPACK #-} !(Chan StateEvent)
    -- | The network state shared with an 'MVar'. This 'MVar' is read-only from
    -- the point of view of other threads. It exists to overcome a performance
    -- problem with pure message-passing.
  , nState :: {-# UNPACK #-} !(MVar NetworkState) }

-- | Create a new network event handler given the exit test chan and the path to
-- our state directory. This should only be called once.
newNetwork :: Maybe (ExitTestChan, FilePath) -> IO Network
newNetwork exitTests = do
  net <- liftM2 Network newChan (newMVar emptyNetworkState)
  forkIO $ stateEventHandler net exitTests
  return net

-- | Our current view of the Tor network.
data NetworkState = NetworkState
  { -- | A map from listen address to routers.
    nsAddrs   :: {-# UNPACK #-} !(Map HostAddress (Set Fingerprint)),
    -- | All the routers we know about.
    nsRouters :: {-# UNPACK #-} !(Map Fingerprint Router) }

-- | The empty network state.
emptyNetworkState :: NetworkState
emptyNetworkState = NetworkState M.empty M.empty

-- | A Tor router.
data Router = Router
  { -- | This router's descriptor, if we have it yet.
    rtrDescriptor    :: {-# UNPACK #-} !(Maybe Descriptor),
    -- | This router's exit test results, if one has been completed.
    rtrTest          :: {-# UNPACK #-} !(Maybe TestResults),
    -- | Whether we think this router is running.
    rtrIsRunning     :: {-# UNPACK #-} !Bool,
    -- | The last time we received a router status entry for this router.
    rtrLastStatus    :: {-# UNPACK #-} !UTCTime }

-- | The results of an exit test.
data TestResults = TestResults
  { -- | The address from which our exit test originated.
    trAddr      :: {-# UNPACK #-} !HostAddress,
    -- | The descriptor's published time when the exit test was initiated.
    trPublished :: {-# UNPACK #-} !UTCTime,
    -- | When the exit test completed.
    trTested    :: {-# UNPACK #-} !UTCTime }

--------------------------------------------------------------------------------
-- State events

-- | Update the network state with new router descriptors.
updateDescriptors :: Network -> [Descriptor] -> IO ()
updateDescriptors net = writeChan (nChan net) . NewDesc

-- | Update the network state with new router status entries.
updateNetworkStatus :: Network -> [RouterStatus] -> IO ()
updateNetworkStatus net = writeChan (nChan net) . NewNS

-- | Register a mapping from cookie to fingerprint and descriptor published
-- time, passing the cookie to the given 'IO' action. The cookie is guaranteed
-- to be released when the action terminates.
withCookie
  :: Network -> Handle -> Fingerprint -> UTCTime -> (Cookie -> IO a) -> IO a
withCookie net random fp published =
  E.bracket addNewCookie (writeChan (nChan net) . DeleteCookie)
  where
    addNewCookie = do
      cookie <- newCookie random
      writeChan (nChan net) (AddCookie cookie fp published)
      return cookie

-- | Update our known exit address from an incoming test connection.
updateExitAddress :: Network -> UTCTime -> Cookie -> HostAddress -> IO ()
updateExitAddress net tested c = writeChan (nChan net) . NewExitAddress tested c

-- | Signal that an exit test has finished.
testComplete :: Network -> Fingerprint -> IO ()
testComplete net = writeChan (nChan net) . TestComplete

-- | Read the current network state.
readNetworkState :: Network -> IO NetworkState
readNetworkState = readMVar . nState

-- | A message sent to update the network state.
data StateEvent
  -- | New descriptors are available.
  = NewDesc {-# UNPACK #-} ![Descriptor]
  -- | New router status entries are available.
  | NewNS {-# UNPACK #-} ![RouterStatus]
  -- | Discard routers that haven't received status updates for a long time.
  | DiscardOldRouters
  -- | Map a new cookie to an exit node identity and descriptor published time.
  | AddCookie {-# UNPACK #-} !Cookie  {-# UNPACK #-} !Fingerprint
              {-# UNPACK #-} !UTCTime
  -- | Remove a cookie to exit node identity mapping.
  | DeleteCookie {-# UNPACK #-} !Cookie
  -- | We've received a cookie from an incoming test connection.
  | NewExitAddress {-# UNPACK #-} !UTCTime {-# UNPACK #-} !Cookie
                   {-# UNPACK #-} !HostAddress
  -- | A test is finished, so remove it from the set of pending tests.
  | TestComplete {-# UNPACK #-} !Fingerprint
  -- | Rebuild the exit addresses storage.
  | ReplaceExitAddresses

-- | An internal type representing the current exit test state.
data TestState = TestState
  { tsCookies    :: !(Map Cookie (Fingerprint, UTCTime))
  , tsPending    :: !(Set Fingerprint)
  , tsAddrLen
  , tsJournalLen :: !Integer
  , tsJournal    :: !Handle }

-- | Receive and carry out state update events.
stateEventHandler :: Network -> Maybe (ExitTestChan, FilePath) -> IO ()
stateEventHandler net testConf = do
  forkIO . forever $ do
    -- check for and discard old routers every 30 minutes
    threadDelay (30 * 60 * 10^6)
    writeChan (nChan net) DiscardOldRouters

  maybe (eventHandler net) (testingEventHandler net) testConf

-- | Handle non-testing events.
eventHandler :: Network -> IO ()
eventHandler net = loop emptyNetworkState
  where
    loop s = do
      event <- readChan $ nChan net
      now <- getCurrentTime
      case event of
        NewDesc ds ->
          let s' = foldl' (newDescriptor now) s ds
          in s' `seq` swapMVar (nState net) s' >> loop s'
        NewNS rss ->
          let s' =  foldl' (newRouterStatus now) s rss
          in s' `seq` swapMVar (nState net) s' >> loop s'
        DiscardOldRouters ->
          let s' = discardOldRouters now s
          in s' `seq` swapMVar (nState net) s' >> loop s'
        _ -> error "unexpected message" -- XXX log this

-- | Handle testing events.
testingEventHandler :: Network -> (ExitTestChan, FilePath) -> IO ()
testingEventHandler net (testChan,stateDir) = do
  -- initialize network state with test results from state directory
  exitAddrs <- readExitAddresses stateDir
  s <- flip discardOldRouters (initialNetState exitAddrs) `fmap` getCurrentTime
  swapMVar (nState net) s

  -- remove old routers and merge journal into exit-addresses
  addrLen <- replaceExitAddresses stateDir (nsRouters s)
  journal <- openFile (stateDir ++ "/exit-addresses.new") WriteMode

  forkIO . forever $ do
    -- rebuild exit-addresses every 15 minutes so LastStatus entries
    -- stay up to date
    threadDelay (15 * 60 * 10^6)
    writeChan (nChan net) ReplaceExitAddresses

  loop s (TestState M.empty S.empty addrLen 0 journal)
  where
    loop ns ts = do
      event <- readChan $ nChan net
      now <- getCurrentTime
      case event of
        NewDesc ds -> do
          let ns' = foldl' (newDescriptor now) ns ds
          ns' `seq` swapMVar (nState net) ns'
          addExitTests (tsPending ts) (map descFingerprint ds) ns' ts
            >>= loop ns'

        NewNS rss -> do
          let ns' = foldl' (newRouterStatus now) ns rss
          ns' `seq` swapMVar (nState net) ns'
          addExitTests (tsPending ts) (map rsFingerprint rss) ns' ts
            >>= loop ns'

        DiscardOldRouters ->
          let ns' = discardOldRouters now ns
          in ns' `seq` swapMVar (nState net) ns' >> loop ns' ts

        AddCookie c fp published ->
          loop ns ts { tsCookies = M.insert c (fp, published) (tsCookies ts) }

        DeleteCookie c -> loop ns ts { tsCookies = M.delete c (tsCookies ts) }

        TestComplete fp -> loop ns ts { tsPending = S.delete fp (tsPending ts) }

        NewExitAddress tested c addr
          | Just (fp, published) <- c  `M.lookup` tsCookies ts
          , Just r               <- fp `M.lookup` nsRouters ns -> do

          let (r',ns') = newExitAddress tested published r fp addr ns
          ns' `seq` swapMVar (nState net) ns'

          len <- appendExitAddressToJournal (tsJournal ts) fp r'
          if isJournalTooLarge (tsAddrLen ts) (tsJournalLen ts + len)
            then rebuildExitStorage ns' ts >>= loop ns'
            else loop ns' ts { tsJournalLen = tsJournalLen ts + len }

          | otherwise -> loop ns ts -- XXX log this

        ReplaceExitAddresses -> rebuildExitStorage ns ts >>= loop ns

    addExitTests pending fps ns ts = do
      mapM_ (addExitTest testChan) testable
      return $! ts { tsPending = tsPending ts `S.union` S.fromList testable }
      where testable = filter (isTestable pending ns) fps

    rebuildExitStorage ns ts = do
      hClose $ tsJournal ts
      addrLen <- replaceExitAddresses stateDir (nsRouters ns)
      h <- openFile (stateDir ++ "/exit-addresses.new") WriteMode
      return $! ts { tsAddrLen = addrLen, tsJournalLen = 0, tsJournal = h }

    initialNetState exitAddrs =
      NetworkState (foldl' (flip insertExit) M.empty exitAddrs)
                   (M.fromDistinctAscList $ map initialRouter exitAddrs)
      where
        insertExit (ExitAddress fp addr _ _ _) = insertAddress addr fp
        initialRouter (ExitAddress fp addr pub tested status) =
          (fp, Router Nothing (Just (TestResults addr pub tested)) False status)

-- | Given the set of currently pending tests and the network state, should a
-- router be added to the test queue?
isTestable :: Set Fingerprint -> NetworkState -> Fingerprint -> Bool
isTestable pending s fp
  | fp `S.member` pending = False
  | Just r <- fp `M.lookup` nsRouters s
  = case (rtrDescriptor r, rtrTest r) of
      (Nothing, _)     -> False
      (_, Nothing)     -> True
      -- have we already done a test for this descriptor version?
      (Just d, Just t) -> trPublished t < descPublished' d
  | otherwise = False
  where descPublished' = posixSecondsToUTCTime . descPublished

-- | Update the network state with the results of an exit test. Return the
-- updated router information.
newExitAddress
  :: UTCTime -> UTCTime -> Router -> Fingerprint -> HostAddress -> NetworkState
  -> (Router, NetworkState)
newExitAddress tested published r fp addr s
  | trAddr `fmap` rtrTest r /= Just addr
  = (r', s' { nsAddrs = insertAddress addr fp . deleteOldExit . nsAddrs $ s })
  | otherwise = (r', s')
  where
    r' = r { rtrTest = Just (TestResults addr published tested) }
    s' = s { nsRouters = M.insert fp r' (nsRouters s) }
    deleteOldExit = maybe id (\t -> deleteAddress (trAddr t) fp) (rtrTest r)

-- | Update the network state with a new router descriptor.
newDescriptor :: UTCTime -> NetworkState -> Descriptor -> NetworkState
newDescriptor now s newD
  -- we know about this router already, but we might not have its descriptor
  | Just router <- M.lookup fp (nsRouters s)
  = case rtrDescriptor router of
      -- we have a descriptor, and therefore a possibly outdated address
      Just oldD
        -- the descriptor we already have is newer than this one
        | descPublished oldD > descPublished newD -> s
        -- address changed: delete old address, insert new address
        | descListenAddr newD /= descListenAddr oldD ->
            s { nsAddrs   = insertAddr newD . deleteAddr oldD . nsAddrs $ s
              , nsRouters = updateRouters }
        -- address hasn't changed: don't update addrs
        | otherwise -> s { nsRouters = updateRouters }
      -- we didn't have an address before: insert new address
      _ -> s { nsAddrs   = insertAddr newD (nsAddrs s)
             , nsRouters = updateRouters }
  -- this is a new router: insert into routers and addrs
  | otherwise = s { nsAddrs   = insertAddr newD (nsAddrs s)
                  , nsRouters = insertRouters }
  where
    updateRouters =
      M.adjust (\r -> r { rtrDescriptor = Just newD }) fp (nsRouters s)
    insertRouters =
      M.insert fp (Router (Just newD) Nothing False now) (nsRouters s)
    insertAddr d = insertAddress (descListenAddr d) fp
    deleteAddr d = deleteAddress (descListenAddr d) fp
    fp = descFingerprint newD

-- | Update the network state with a new router status entry.
newRouterStatus :: UTCTime -> NetworkState -> RouterStatus -> NetworkState
newRouterStatus now s rs =
  s { nsRouters = M.alter (Just . maybe newRouter updateRouter)
                          (rsFingerprint rs) (nsRouters s) }
  where
    newRouter = Router Nothing Nothing (rsIsRunning rs) now
    updateRouter r = r { rtrIsRunning = rsIsRunning rs, rtrLastStatus = now }

-- | Discard routers whose last status update was received more than
-- @routerMaxAge@ seconds ago.
discardOldRouters :: UTCTime -> NetworkState -> NetworkState
discardOldRouters now s = s { nsAddrs = addrs', nsRouters = routers' }
  where
    (oldRouters,routers') = M.partition isOld (nsRouters s)
    addrs' = foldl' deleteAddrs (nsAddrs s) (M.toList oldRouters)
    isOld r = now `diffUTCTime` rtrLastStatus r > routerMaxAge
    deleteAddrs addrs (fp,r) =
      maybe id (\d -> deleteAddress (descListenAddr d) fp) (rtrDescriptor r) .
      maybe id (\t -> deleteAddress (trAddr t) fp) (rtrTest r) $ addrs
    routerMaxAge = 60 * 60 * 48

-- | Add a new router associated with an address to the address map.
insertAddress :: HostAddress -> Fingerprint -> Map HostAddress (Set Fingerprint)
              -> Map HostAddress (Set Fingerprint)
insertAddress addr fp =
  M.alter (Just . maybe (S.singleton fp) (S.insert fp)) addr

-- | Remove a router associated with an address from the address map.
deleteAddress :: HostAddress -> Fingerprint -> Map HostAddress (Set Fingerprint)
              -> Map HostAddress (Set Fingerprint)
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
isExitNode :: Network -> ExitListQuery -> IO Bool
{-# INLINE isExitNode #-}
isExitNode net q = do
  s <- readNetworkState net
  now <- getPOSIXTime
  return $! maybe False (anyExit now s) $ queryAddr q `M.lookup` nsAddrs s
  where
    anyExit t s = any (isExit t) . mapMaybe (lookupDesc $ nsRouters s) . S.elems
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

-- | The exit test channel.
newtype ExitTestChan = ExitTestChan { unETChan :: Chan Fingerprint }

-- | Create a new exit test channel to be passed to 'newNetwork'.
newExitTestChan :: IO ExitTestChan
newExitTestChan = ExitTestChan `fmap` newChan

-- | Schedule an exit test through a router.
addExitTest :: ExitTestChan -> Fingerprint -> IO ()
addExitTest = writeChan . unETChan

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
  { etChan        :: ExitTestChan
  , etNetwork     :: Network
  , etTcp         :: ProtocolNumber
  , etConcTests   :: Int
  , etSocksServer :: SockAddr
  , etListenSocks :: [Socket]
  , etTestAddr    :: HostAddress
  , etTestPorts   :: [Word16]
  , etRandom      :: Handle }

-- | Fork all our exit test listeners.
startTestListeners :: Network -> [Socket] -> Int -> IO ()
startTestListeners net listenSockets concTests = do
  -- We need to keep the number of open FDs below FD_SETSIZE as long as GHC uses
  -- select instead of epoll or kqueue. Client sockets waiting in this channel
  -- count against that limit. We use a bounded channel so incoming connections
  -- can't crash the runtime by exceeding the limit.
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
          now <- getCurrentTime
          updateExitAddress net now cookie addr
          B.hPut handle $ b 46 "HTTP/1.0 204 No Content\r\n\
                               \Connection: close\r\n\r\n"#
        _ ->
          B.hPut handle $ b 47 "HTTP/1.0 400 Bad Request\r\n\
                               \Connection: close\r\n\r\n"#
    ignoreJust E.ioErrors $ hClose handle

  where ignoreJust p = E.handleJust p (const $ return ())

-- | Fork all our exit test listeners and initiators.
startExitTests :: ExitTestConfig -> IO ()
startExitTests conf = do
  startTestListeners (etNetwork conf) (etListenSocks conf) (etConcTests conf)

  replicateM_ (etConcTests conf) . forkIO . forever $ do
    fp <- readChan . unETChan . etChan $ conf
    s  <- readNetworkState . etNetwork $ conf
    let mbTest = do
          rtr <- fp `M.lookup` nsRouters s
          guard $ rtrIsRunning rtr
          d <- rtrDescriptor rtr
          ports@(_:_) <- return $ allowedPorts d
          return (posixSecondsToUTCTime (descPublished d), ports)

    -- Skip the test if this router isn't marked running, we don't have its
    -- descriptor yet, or its exit policy doesn't allow connections to any of
    -- our listening ports.
    whenJust mbTest $ \(published, ports) ->
      withCookie (etNetwork conf) (etRandom conf) fp published $ \cookie -> do
        -- try to connect eight times before giving up
        attempt . take 8 . map (testConnection cookie fp testHost) $ cycle ports
        -- XXX log failure
        return ()

    testComplete (etNetwork conf) fp

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
        exitHost =
          B.concat [host, b 2 ".$"#, encodeBase16Fingerprint fp, b 5 ".exit"#]

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
  , b 17 "Connection: close"#
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
  return $! length headerLines -- read all headers before parsing them
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
newCookie :: Handle -> IO Cookie
newCookie random = Cookie `fmap` randBytes random cookieLen

-- | The cookie length in bytes.
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
    -- | The current descriptor published time when the test was initiated. We
    -- don't perform another test until a newer descriptor arrives.
    eaPublished   :: {-# UNPACK #-} !UTCTime,
    -- | When the test completed.
    eaTested      :: {-# UNPACK #-} !UTCTime,
    -- | When we last received a network status update for this router. This
    -- helps us decide when to discard a router.
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
  , b 7 "Tested "# `B.append` renderTime (eaTested x)
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
  tested     <- parseTime =<< findArg (b 6  "Tested"#      ==) items
  lastStatus <- parseTime =<< findArg (b 10 "LastStatus"#  ==) items
  return $! ExitAddress fp addr published tested lastStatus

-- | On startup, read the exit test results from the state directory. Return the
-- results in ascending order of their fingerprints.
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
replaceExitAddresses :: Integral a => FilePath -> Map Fingerprint Router -> IO a
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
  t <- rtrTest r
  return $! ExitAddress fp (trAddr t) (trPublished t) (trTested t)
                        (rtrLastStatus r)

-- | Add an exit address entry to the journal. Return the entry's length in
-- bytes.
appendExitAddressToJournal
  :: Integral a => Handle -> Fingerprint -> Router -> IO a
appendExitAddressToJournal journal fp r
  | Just addr <- renderExitAddress `fmap` mkExitAddress (fp,r) = do
      B.hPut journal addr >> hFlush journal
      return $! fromIntegral . B.length $ addr
  | otherwise = return 0

-- | Is the exit address journal large enough that it should be cleared?
isJournalTooLarge :: Integral a => a -> a -> Bool
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
