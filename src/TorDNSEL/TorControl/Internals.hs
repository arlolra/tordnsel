{-# LANGUAGE PatternGuards, CPP #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.TorControl.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, concurrency, extended exceptions,
--                             GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Interfacing with Tor using the Tor control protocol, version 1. We support
-- fetching router descriptors and router status entries, including those sent
-- in asynchronous events that Tor generates when it receives new directory
-- information.
--
-- See <https://tor.eff.org/svn/trunk/doc/spec/control-spec.txt> for details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.TorControl.Internals (
  -- * Connections
    Connection(..)
  , withConnection
  , openConnection
  , waitForConnection
  , closeConnection

  -- * Commands
  , Command(..)
  , Reply(..)
  , authenticate
  , Feature(..)
  , useFeature
  , getDescriptor
  , getAllDescriptors
  , getRouterStatus
  , getNetworkStatus
  , getDocument
  , getCircuitStatus
  , getStreamStatus
  , getStatus
  , setFetchUselessDescriptors
  , CircuitPurpose(..)
  , createCircuit
  , extendCircuit
  , extendCircuit'
  , attachStream
  , cedeStream
  , attachStream'
  , redirectStream
  , CloseCircuitFlags(..)
  , emptyCloseCircuitFlags
  , closeCircuit
  , setConf
  , sendCommand

  -- * Asynchronous events
  , EventHandler(..)
  , registerEventHandlers
  , newDescriptorsEvent
  , networkStatusEvent
  , streamEvent
  , circuitEvent
  , lineEvent
  , addressMapEvent

  -- * Backend connection manager
  , IOMessage(..)
  , ioManager
  , ReplyType(..)
  , socketReader

  -- * Data types
  , CircuitID(..)
  , nullCircuitID
  , parseID
  , CircuitStatus(..)
  , parseCircuitStatus
  , CircuitState(..)
  , parseCircuitState
  , StreamID(..)
  , StreamStatus(..)
  , parseStreamStatus
  , StreamState(..)
  , parseStreamState
  , AddressMap(..)
  , parseAddressMap
  , Expiry(..)

  -- * Errors
  , ReplyCode
  , replyLine
  , TorControlError(..)
  , replyToError
  , parseReplyCode
  , throwIfNotPositive
  , throwIfNothing
  , isPositive

  -- * Aliases
  , b
  ) where

import Control.Arrow (second)
import Control.Concurrent (forkIO, killThread, myThreadId)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan, isEmptyChan)
import Control.Concurrent.MVar
  (MVar, newEmptyMVar, newMVar, takeMVar, putMVar, withMVar, swapMVar)
import qualified Control.Exception as E
import Control.Monad (unless, liftM)
import Control.Monad.Error (MonadError(..))
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (isSpace, isAlphaNum, isDigit)
import Data.Foldable (traverse_)
import qualified Data.Map as M
import Data.Maybe (fromMaybe, catMaybes, maybeToList, listToMaybe, mapMaybe)
import qualified Data.Sequence as S
import Data.Sequence ((<|), ViewR((:>)), viewr)
import Data.Time (UTCTime, TimeZone, localTimeToUTC, getCurrentTimeZone)
import Data.Typeable (Typeable)
import System.IO (Handle, hClose, hSetBuffering, BufferMode(..), hFlush)

import GHC.Prim (Addr#)

import TorDNSEL.Control.Concurrent.Future
import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Util

#define protocolError(msg) \
  (E.throwDyn (ProtocolError (escape (msg)) \
              ((__FILE__ ++) . (':':) . shows __LINE__)))

--------------------------------------------------------------------------------
-- Connections

-- | A Tor control connection.
data Connection
  = Conn {-# UNPACK #-}
         !(MVar (IOMessage -> IO ())) -- send a message to the 'ioManager'
         {-# UNPACK #-} !(MVar ())    -- signals a terminated connection

-- | Open a connection with a handle and pass it to an IO action. If the IO
-- action throws an exception or an I\/O error occurs during the connection, the
-- connection will be terminated and the exception re-thrown in the current
-- thread.
withConnection :: Handle -> (Connection -> IO a) -> IO a
withConnection handle io = do
  tid <- myThreadId
  E.bracket (openConnection handle (flip whenJust (E.throwTo tid)))
            closeConnection io

-- | Open a connection with a handle, installing a handler to be invoked when
-- the connection terminates. If the connection is terminated by an I\/O or
-- protocol error we pass an 'Exception' to the handler. Otherwise, it was
-- terminated by 'closeConnection', so it will be passed 'Nothing'.
openConnection :: Handle -> (Maybe E.Exception -> IO ()) -> IO Connection
openConnection handle closeHandler = do
  hSetBuffering handle LineBuffering
  chan <- newChan
  send <- newMVar $ writeChan chan
  mv <- newEmptyMVar
  -- closeHandler should be called before putMVar so the async exception can
  -- interrupt waitForConnection inside withConnection. Otherwise, the async
  -- exception will be delivered outside withConnection, creating a race
  -- condition for external exception handlers.
  forkIO $
    ioManager handle chan
              (swapMVar send (const $ E.throwDyn ConnectionClosed) >> return ())
              (\e -> closeHandler e `E.finally` putMVar mv ())
  return (Conn send mv)

-- | Block the current thread until a connection terminates. This can happen
-- when an I\/O error occurs or another thread calls 'closeConnection'.
waitForConnection :: Connection -> IO ()
waitForConnection (Conn _ mv) = withMVar mv return

-- | Close a connection, blocking the current thread until the connection has
-- terminated.
closeConnection :: Connection -> IO ()
closeConnection (Conn send mv) = do
  withMVar send $ ignoreJust Just . ($ CloseConnection)
  withMVar mv return

--------------------------------------------------------------------------------
-- Commands

-- | A command to send to Tor.
data Command = Command
  { -- | A command keyword.
    comKey  :: {-# UNPACK #-} !ByteString,
    -- | Command arguments.
    comArgs :: {-# UNPACK #-} ![ByteString],
    -- | A list of lines sent in the data section.
    comData :: {-# UNPACK #-} ![ByteString]
  } deriving Show

-- | A reply sent by Tor in response to a command.
data Reply = Reply
  { -- | A reply code.
    repCode :: {-# UNPACK #-} !(Char, Char, Char)
    -- | Reply text.
  , repText :: {-# UNPACK #-} !ByteString
    -- | A list of lines from the data section.
  , repData :: {-# UNPACK #-} ![ByteString]
  } deriving Show

-- | Authenticate with Tor using a password or cookie, then enable required
-- protocol extensions. Throw a 'TorControlError' if either reply code indicates
-- failure.
authenticate :: Maybe ByteString -> Connection -> IO ()
authenticate secret conn = do
  sendCommand command conn >>= throwIfNotPositive . head
  useFeature [VerboseNames] conn
  where command = Command (b 12 "authenticate"#) (maybeToList secret) []

-- | Control protocol extensions
data Feature = ExtendedEvents -- ^ Extended event syntax
             | VerboseNames   -- ^ Identify routers by long name

-- | Enable control protocol extensions. Throw a 'TorControlError' if the reply
-- code indicates failure.
useFeature :: [Feature] -> Connection -> IO ()
useFeature features conn =
  sendCommand command conn >>= throwIfNotPositive . head
  where
    command = Command (b 10 "usefeature"#) (map renderFeature features) []
    renderFeature ExtendedEvents = b 15 "extended_events"#
    renderFeature VerboseNames   = b 13 "verbose_names"#

-- | Fetch the most recent descriptor for a given router. Throw a
-- 'TorControlError' if the reply code isn't 250 or parsing the descriptor
-- fails.
getDescriptor :: RouterID -> Connection -> IO Descriptor
getDescriptor rid =
  throwIfNothing ParseError . getDocument key parseDescriptor
  where key = b 8 "desc/id/"# `B.append` encodeBase16RouterID rid

-- | Fetch the most recent descriptor for every router Tor knows about. Throw a
-- 'TorControlError' if the reply code isn't 250.
getAllDescriptors :: Connection -> IO [Descriptor]
getAllDescriptors = fmap filterRight . getDocument key parseDescriptors
  where key = b 15 "desc/all-recent"#

-- | Fetch the current status entry for a given router. Throw a
-- 'TorControlError' if the reply code isn't 250 or parsing the router status
-- entry fails.
getRouterStatus :: RouterID -> Connection -> IO RouterStatus
getRouterStatus rid =
  throwIfNothing ParseError . getDocument arg parseRouterStatus
  where arg = b 6 "ns/id/"# `B.append` encodeBase16RouterID rid

-- | Fetch the current status entries for every router Tor has an opinion about.
-- Throw a 'TorControlError' if the reply code isn't 250.
getNetworkStatus :: Connection -> IO [RouterStatus]
getNetworkStatus = fmap filterRight . getDocument arg parseRouterStatuses
  where arg = b 6 "ns/all"#

-- | Send a GETINFO command using @key@ as a single keyword. If the reply code
-- is 250, pass the document contained in data from the first reply to @parse@
-- and return the parsed document. Otherwise, throw a 'TorControlError'.
getDocument :: ByteString -> (Document -> a) -> Connection -> IO a
getDocument key parse conn = do
  reply:_ <- sendCommand (Command (b 7 "getinfo"#) [key] []) conn
  case reply of
    Reply ('2','5','0') text doc@(_:_)
      | text == B.snoc key '=' -> return . parse . parseDocument $ doc
    Reply ('2',_,_) _ _        -> protocolError(replyLine reply)
    _                          -> E.throwDyn $ replyToError reply

-- | Get the current status of all open circuits. Throw a 'TorControlError' if
-- the reply code isn't 250.
getCircuitStatus :: Connection -> IO [CircuitStatus]
getCircuitStatus = getStatus (b 14 "circuit-status"#) parseCircuitStatus

-- | Get the current status of all open streams. Throw a 'TorControlError' if
-- the reply code isn't 250.
getStreamStatus :: Connection -> IO [StreamStatus]
getStreamStatus = getStatus (b 13 "stream-status"#) parseStreamStatus

-- | Get the current status of all open circuits or streams. The GETINFO key is
-- specified by @key@, and the line-parsing function by @parse@. Throw a
-- 'TorControlError' if the reply code isn't 250.
getStatus :: ByteString -> (ByteString -> Maybe a) -> Connection -> IO [a]
getStatus key parse conn = do
  reply:_ <- sendCommand (Command (b 7 "getinfo"#) [key] []) conn
  let prefix   = B.snoc key '='
      validKey = prefix `B.isPrefixOf` repText reply
  case reply of
    Reply ('2','5','0') text []
      | prefix == text                                             -> return []
      | validKey, Just x <- parse $ B.drop (B.length key + 1) text -> return [x]
      | otherwise        -> protocolError(replyLine reply)
    Reply ('2','5','0') _ status
      | validKey, Just xs <- mapM parse status                     -> return xs
    Reply ('2',_,_) _ _  -> protocolError(replyLine reply)
    _                    -> E.throwDyn $ replyToError reply

-- | Set Tor's config option \"FetchUselessDescriptors\" so we get descriptors
-- for non-running routers. Throw a 'TorControlError' if the reply code isn't
-- 250.
setFetchUselessDescriptors :: Connection -> IO ()
setFetchUselessDescriptors conn =
  setConf [(b 23 "fetchuselessdescriptors"#, Just (b 1 "1"#))] conn

-- | A circuit's purpose
data CircuitPurpose = CrGeneral    -- ^ General
                    | CrController -- ^ Controller

-- | Build a new circuit, setting the @purpose@ if specified. Return the newly
-- created 'CircuitID'. Throw a 'TorControlError' if the reply code isn't 250.
createCircuit
  :: [RouterID] -> Maybe CircuitPurpose -> Connection -> IO CircuitID
createCircuit = extendCircuit' Nothing

-- | Extend an existing circuit according to the specified @path@. Throw a
-- 'TorControlError' if the reply code isn't 250.
extendCircuit :: CircuitID -> [RouterID] -> Connection -> IO ()
extendCircuit cid path = (>> return ()) . extendCircuit' (Just cid) path Nothing

-- | Send an EXTENDCIRCUIT command. Build a new circuit according to the
-- specified @path@ and @purpose@ if @circuit@ is 'Nothing'. Otherwise, extend
-- an existing circuit according to @path@. Return the (possibly new)
-- 'CircuitID'. Throw a 'TorControlError' if the reply code isn't 250.
extendCircuit'
  :: Maybe CircuitID -> [RouterID] -> Maybe CircuitPurpose -> Connection
  -> IO CircuitID
extendCircuit' circuit path purpose conn = do
  reply:_ <- sendCommand command conn
  case reply of
    Reply ('2','5','0') text _
      | msg:cid':_ <- B.split ' ' text, msg == b 8 "EXTENDED"#
      , maybe True (== CircId cid') circuit -> return $ CircId (B.copy cid')
      | otherwise                           -> protocolError(replyLine reply)
    _                                       -> E.throwDyn $ replyToError reply
  where
    command = Command (b 13 "extendcircuit"#) args []
    args = add purpose [cid, B.join (b 1 ","#) $ map encodeBase16RouterID path]
    CircId cid = fromMaybe nullCircuitID circuit
    renderPurpose CrGeneral    = b 7  "general"#
    renderPurpose CrController = b 10 "controller"#
    add = maybe id (\p -> (++ [b 8 "purpose="# `B.append` renderPurpose p]))

-- | Attach an unattached stream to a completed circuit, exiting from @hop@ if
-- specified. Throw a 'TorControlError' if the reply code indicates failure.
attachStream :: StreamID -> CircuitID -> Maybe Integer -> Connection -> IO ()
attachStream sid cid = attachStream' sid (Just cid)

-- | Cede the responsibility for attaching a given unattached stream to Tor. Throw
-- a 'TorControlError' if the reply code indicates failure.
cedeStream :: StreamID -> Connection -> IO ()
cedeStream sid = attachStream' sid Nothing Nothing

-- | Send an ATTACHSTREAM command. Attach an unattached stream to the specified
-- completed circuit, exiting from @hop@ if specified. If the circuit isn't
-- specified, return the responsibility for attaching the stream to Tor. Throw a
-- 'TorControlError' if the reply code indicates failure.
attachStream'
  :: StreamID -> Maybe CircuitID -> Maybe Integer -> Connection -> IO ()
attachStream' (StrmId sid) circuit hop conn =
  sendCommand command conn >>= throwIfNotPositive . head
  where
    command = Command (b 12 "attachstream"#) (add hop [sid,cid]) []
    CircId cid = fromMaybe nullCircuitID circuit
    add = maybe id (flip (++) . (:[]) . B.append (b 4 "HOP="#) . B.pack . show)

-- | Change a stream's destination address and port, if specified. Throw a
-- 'TorControlError' if the reply code indicates failure.
redirectStream :: StreamID -> Address -> Maybe Port -> Connection -> IO ()
redirectStream (StrmId sid) addr port conn =
  sendCommand command conn >>= throwIfNotPositive . head
  where
    command = Command (b 14 "redirectstream"#) args []
    args = [sid, showAddress addr] ++ maybeToList ((B.pack . show) `fmap` port)

-- | Flags to pass to 'closeCircuit'
data CloseCircuitFlags = CloseCircuitFlags
  { -- | Don't close the circuit unless it's unused
    ifUnused :: Bool }

-- | All 'CloseCircuitFlags' unset
emptyCloseCircuitFlags :: CloseCircuitFlags
emptyCloseCircuitFlags = CloseCircuitFlags False

-- | Close the specified circuit. Throw a 'TorControlError' if the reply code
-- indicates failure.
closeCircuit :: CircuitID -> CloseCircuitFlags -> Connection -> IO ()
closeCircuit (CircId cid) flags conn =
  sendCommand command conn >>= throwIfNotPositive . head
  where
    command = Command (b 12 "closecircuit"#) (cid : flagArgs) []
    flagArgs = [flag | (p,flag) <- [(ifUnused, b 8 "IfUnused"#)], p flags]

-- | Send a SETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code isn't 250.
setConf :: [(ByteString, Maybe ByteString)] -> Connection -> IO ()
setConf args conn = sendCommand command conn >>= throwIfNotPositive . head
  where
    command = Command (b 7 "setconf"#) (map renderArg args) []
    renderArg (key, Just val) = B.join (b 1 "="#) [key, val]
    renderArg (key, _)        = key

-- | Send a command using a connection, blocking the current thread until all
-- replies have been received.
sendCommand :: Command -> Connection -> IO [Reply]
sendCommand c (Conn send _) = do
  mv <- newEmptyMVar
  withMVar send ($ SendCommand c (putMVar mv))
  takeMVar mv

--------------------------------------------------------------------------------
-- Asynchronous events

-- | An asynchronous event handler.
data EventHandler = EventHandler
  { evCode    :: {-# UNPACK #-} !ByteString         -- ^ The event code.
  , evHandler :: {-# UNPACK #-} !([Reply] -> IO ()) -- ^ The event handler.
  }

-- | Register a set of handlers for asynchronous events. This deregisters any
-- previously registered event handlers for this connection. Throw a
-- 'TorControlError' if the reply code indicates failure.
registerEventHandlers :: [EventHandler] -> Connection -> IO ()
registerEventHandlers handlers (Conn send _) = do
  mv <- newEmptyMVar
  withMVar send ($ RegisterEvents command (putMVar mv) handlers)
  takeMVar mv >>= throwIfNotPositive . head
  where command = Command (b 9 "setevents"#) (map evCode handlers) []

-- | Create an event handler for new router descriptor events.
newDescriptorsEvent :: ([Descriptor] -> IO ()) -> Connection -> EventHandler
newDescriptorsEvent handler conn = EventHandler (b 7 "NEWDESC"#) handleNewDesc
  where
    safeGetDescriptor rid = Just `fmap` getDescriptor rid conn
      `E.catchDyn` \(_ :: TorControlError) -> return Nothing
    handleNewDesc (Reply _ text _:_)
      | Just rids' <- mapM decodeBase16RouterID rids =
          -- pipeline descriptor requests
          mapM (spawn . safeGetDescriptor) rids' >>= mapM resolve
            >>= handler . catMaybes
      where rids = map (B.take 40 . B.drop 1) . B.split ' ' . B.drop 8 $ text
    handleNewDesc _ = return ()

-- | Create an event handler for network status events.
networkStatusEvent :: ([RouterStatus] -> IO ()) -> EventHandler
networkStatusEvent handler = EventHandler (b 2 "NS"#) handleNS
  where
    handleNS (Reply _ _ doc@(_:_):_) =
      handler . filterRight . parseRouterStatuses . parseDocument $ doc
    handleNS _ = return ()

-- | Create an event handler for stream status change events.
streamEvent :: (StreamStatus -> IO ()) -> EventHandler
streamEvent = lineEvent (b 6 "STREAM"#) parseStreamStatus

-- | Create an event handler for circuit status change events.
circuitEvent :: (CircuitStatus -> IO ()) -> EventHandler
circuitEvent = lineEvent (b 4 "CIRC"#) parseCircuitStatus

-- | Create an event handler for circuit/stream status change events. The event
-- code is specified by @code@, and the line-parsing function by @parse@.
lineEvent
  :: ByteString -> (ByteString -> Maybe a) -> (a -> IO ()) -> EventHandler
lineEvent code parse handler = EventHandler code handleStatus
  where
    handleStatus (Reply _ text _:_)
      | Just x <- parse $ B.drop (B.length code + 1) text = handler x
    handleStatus _                                        = return ()

-- | Create an event handler for new address mapping events.
addressMapEvent :: (AddressMap -> IO ()) -> EventHandler
addressMapEvent handler = EventHandler (b 7 "ADDRMAP"#) handleAddrMap
  where
    handleAddrMap (Reply _ text _:_) = do
      -- XXX Extended events will provide the UTCTime in 0.2.0.x.
      tz <- getCurrentTimeZone
      whenJust (parseAddressMap tz $ B.drop 8 text) handler
    handleAddrMap _ = return ()

--------------------------------------------------------------------------------
-- Backend connection manager

-- | A message sent to 'ioManager'.
data IOMessage
  -- | Send a command to Tor.
  = SendCommand Command               -- the command to send to Tor
                ([Reply] -> IO ())    -- invoke this action with replies
  -- | Register event handlers with Tor.
  | RegisterEvents Command            -- the SETEVENTS command
                   ([Reply] -> IO ()) -- invoke this action with replies
                   [EventHandler]     -- the event handlers to register
  -- | Handle a sequence of replies from Tor.
  | ReceiveReplies [Reply]
  -- | Terminate the connection with Tor.
  | CloseConnection
  -- | The 'socketReader' died due to an I\/O or protocol error.
  | ReaderDied E.Exception

-- | Manage all I\/O associated with a Tor control connection. We receive
-- messages from @chan@ and send the appropriate command to Tor. When we receive
-- replies from Tor, we pass them in a message to the thread that requested the
-- corresponding command. Asynchronous event handlers are maintained as local
-- state, invoked as necessary for incoming events. If an I\/O error occurs or
-- a 'CloseConnection' message is received, we pass the possible error to
-- @closeHandler@ and return.
ioManager
  :: Handle -> Chan IOMessage -> IO () -> (Maybe E.Exception -> IO ()) -> IO ()
ioManager handle ioChan closeChan closeHandler = do
  reader <- forkIO $ socketReader handle (writeChan ioChan)
  handlerChan <- newChan
  forkIO $ handleEvents handlerChan
  ioManager' reader (writeChan handlerChan)
  where
    ioManager' reader invokeHandler = loop S.empty M.empty
      where
        loop responds evHandlers = do
          message <- readChan ioChan
          case message of
            ReaderDied e    -> close (Just e)
            CloseConnection -> close Nothing
            ReceiveReplies replies@(r:_)
              -- if we have a handler, invoke it in the event handler thread
              | ('6',_,_) <- repCode r -> do
                  whenJust (M.lookup (eventCode r) evHandlers) $
                    invokeHandler . Just . ($ replies)
                  loop responds evHandlers
              -- give replies to the oldest respond action
              | responds' :> respond <- viewr responds -> do
                  respond replies
                  loop responds' evHandlers
              -- no respond actions to handle these replies
              | otherwise -> loop responds evHandlers
            SendCommand command respond ->
              (E.try . putBS . renderCommand) command
                >>= either (close . Just)
                           (const $ loop (respond <| responds) evHandlers)
            RegisterEvents command respond handlers ->
              (E.try . putBS . renderCommand) command
                >>= either (close . Just)
                           (const . loop (respond <| responds) . M.fromList .
                             map (\(EventHandler c h) -> (c,h)) $ handlers)
            ReceiveReplies [] -> error "ioManager: empty replies"
          where
            close e = do
              closeChan
              messages <- untilM (isEmptyChan ioChan) $ readChan ioChan
              let responds' = flip mapMaybe messages $ \msg -> case msg of
                    SendCommand    _ respond   -> Just respond
                    RegisterEvents _ respond _ -> Just respond
                    _                          -> Nothing
                  resourceExausted = ($ [Reply ('4','5','1') B.empty []])
              -- send resource exhausted to threads blocked waiting for a reply
              traverse_ resourceExausted responds
              mapM_ resourceExausted responds'
              killThread reader
              invokeHandler Nothing
              hClose handle `E.finally` closeHandler e

    renderCommand (Command key args []) =
      B.join (b 1 " "#) (key : args) `B.append` b 2 "\r\n"#
    renderCommand c@(Command _ _ data') =
      B.cons '+' (renderCommand c { comData = [] }) `B.append` renderData data'
    renderData dataLines =
      B.join (b 2 "\r\n"#) dataLines `B.append` b 5 "\r\n.\r\n"#
    eventCode = B.takeWhile (/= ' ') . repText
    putBS bs = B.hPut handle bs >> hFlush handle

    handleEvents chan = loop
      where loop = readChan chan >>= flip whenJust (>> loop)

-- | Reply types in a single sequence of replies.
data ReplyType
  = MidReply  {-# UNPACK #-} !Reply -- ^ A reply preceding other replies.
  | LastReply {-# UNPACK #-} !Reply -- ^ The last reply.
  deriving Show

-- | In an infinite loop, read replies from @handle@ and pass them to @send@.
-- If an I\/O or protocol error occurs, pass it to @send@ and return.
socketReader :: Handle -> (IOMessage -> IO ()) -> IO ()
socketReader handle send =
  E.catch (forever $ readReplies >>= send . ReceiveReplies) (send . ReaderDied)
  where
    readReplies = do
      line <- parseReplyLine =<< hGetLine handle crlf maxLineLength
      case line of
        MidReply reply  -> fmap (reply :) readReplies
        LastReply reply -> return [reply]

    parseReplyLine line
      | Just code' <- parseReplyCode code = parseReplyLine' code' typ text
      | otherwise                         = protocolError(line)
      where (code,(typ,text)) = second (B.splitAt 1) . B.splitAt 3 $ line

    parseReplyLine' code typ text
      | typ == b 1 "-"# = return . MidReply $ Reply code text []
      | typ == b 1 "+"# = (dataReply . Reply code text) `fmap` readData
      | typ == b 1 " "# = return . LastReply $ Reply code text []
      | otherwise       = protocolError(typ)
      where dataReply = if code == ('6','5','0') then LastReply else MidReply

    readData = do
      line <- hGetLine handle (b 1 "\n"#) maxLineLength
      case (if B.last line == '\r' then B.init else id) line of
        line' | line == b 2 ".\r"#       -> return []
              | any B.null [line, line'] -> readData
              | otherwise                -> fmap (line' :) readData

    crlf = b 2 "\r\n"#
    maxLineLength = 2^20

--------------------------------------------------------------------------------
-- Data types

-- | A circuit identifier.
newtype CircuitID = CircId ByteString
  deriving (Eq, Ord)

instance Show CircuitID where
  showsPrec _ (CircId cid) = cat "(CID " cid ')'

-- | A special 'CircuitID' of "0".
nullCircuitID :: CircuitID
nullCircuitID = CircId (b 1 "0"#)

-- | Parse an identifier using the constructor @con@. 'throwError' in the monad
-- if parsing fails.
parseID :: MonadError ShowS m => (ByteString -> a) -> ByteString -> m a
parseID con bs
  | B.all isAlphaNum bs = return $! con bs
  | otherwise = throwError $ cat "Malformed identifier " (esc maxIDLen bs) '.'
  where maxIDLen = 32

-- | A circuit status entry.
data CircuitStatus = CircStatus CircuitID CircuitState [RouterID]
  deriving Show

-- | Parse a circuit status entry line. 'throwError' in the monad if parsing
-- fails.
parseCircuitStatus :: MonadError ShowS m => ByteString -> m CircuitStatus
parseCircuitStatus line
  | cid:state:rest <- B.split ' ' line =
      prependError ("Failed parsing circuit status: " ++) $ do
        cid'   <- parseID CircId (B.copy cid)
        state' <- parseCircuitState state
        return $! CircStatus cid' state'
                            (fromMaybe [] (parsePath =<< listToMaybe rest))
  | otherwise = throwError $ cat "Malformed circuit status "
                                 (esc maxStatusLen line) '.'
  where
    parsePath = mapM (decodeBase16RouterID . B.take 40 . B.drop 1) . B.split ','
    maxStatusLen = 512

-- | A circuit's current state.
data CircuitState
  = CrLaunched -- ^ Circuit ID assigned to new circuit
  | CrBuilt    -- ^ All hops finished, can now accept streams
  | CrExtended -- ^ One more hop has been completed
  | CrFailed   -- ^ circuit closed (was not built)
  | CrClosed   -- ^ Circuit closed (was built)
  deriving Show

-- | Parse a circuit state. 'throwError' in the monad if parsing fails.
parseCircuitState :: MonadError ShowS m => ByteString -> m CircuitState
parseCircuitState bs
  | bs == b 8 "LAUNCHED"# = return CrLaunched
  | bs == b 5 "BUILT"#    = return CrBuilt
  | bs == b 8 "EXTENDED"# = return CrExtended
  | bs == b 6 "FAILED"#   = return CrFailed
  | bs == b 6 "CLOSED"#   = return CrClosed
  | otherwise = throwError $ cat "Unknown circuit state "
                                 (esc maxStateLen bs) '.'
  where maxStateLen = 32

-- | A stream identifier.
newtype StreamID = StrmId ByteString
  deriving (Eq, Ord)

instance Show StreamID where
  showsPrec _ (StrmId sid) = cat "(SID " sid ')'

-- | A stream status entry.
data StreamStatus
  = StrmStatus StreamID StreamState (Maybe CircuitID) Address Port
  deriving Show

-- | Parse a stream status entry line. 'throwError' in the monad if parsing
-- fails.
parseStreamStatus :: MonadError ShowS m => ByteString -> m StreamStatus
parseStreamStatus line
  | sid:state:cid:target:_ <- B.split ' ' line
  , [addr,port]            <- B.split ':' target =
      prependError ("Failed parsing stream status: " ++) $ do
        sid'   <- parseID StrmId (B.copy sid)
        state' <- parseStreamState state
        cid'   <- parseID CircId (B.copy cid)
        port'  <- parsePort port
        let mbCId = if cid' == nullCircuitID then Nothing else Just cid'
        return $! StrmStatus sid' state' mbCId (readAddress $ B.copy addr) port'
  | otherwise = throwError $ cat "Malformed stream status "
                                 (esc maxStatusLen line) '.'
  where maxStatusLen = 512

-- | A stream's current state.
data StreamState
  = StNew         -- ^ New request to connect
  | StNewResolve  -- ^ New request to resolve an address
  | StRemap       -- ^ Address re-mapped to another
  | StSentConnect -- ^ Sent a connect cell along a circuit
  | StSentResolve -- ^ Sent a resolve cell along a circuit
  | StSucceeded   -- ^ Received a reply; stream established
  | StFailed      -- ^ Stream failed and not retriable
  | StClosed      -- ^ Stream closed
  | StDetached    -- ^ Detached from circuit; still retriable
  deriving Show

-- | Parse a stream state. 'throwError' in the monad if parsing fails.
parseStreamState :: MonadError ShowS m => ByteString -> m StreamState
parseStreamState bs
  | bs == b 3  "NEW"#         = return StNew
  | bs == b 10 "NEWRESOLVE"#  = return StNewResolve
  | bs == b 5  "REMAP"#       = return StRemap
  | bs == b 11 "SENTCONNECT"# = return StSentConnect
  | bs == b 11 "SENTRESOLVE"# = return StSentResolve
  | bs == b 9  "SUCCEEDED"#   = return StSucceeded
  | bs == b 6  "FAILED"#      = return StFailed
  | bs == b 6  "CLOSED"#      = return StClosed
  | bs == b 8  "DETACHED"#    = return StDetached
  | otherwise = throwError $ cat "Unknown stream state "
                                 (esc maxStateLen bs) '.'
  where maxStateLen = 32

-- | An address mapping.
data AddressMap = AddrMap Address -- old address
                          Address -- new address
                          Expiry  -- expiry time
  deriving Show

-- | Parse an address mapping, using the specified time zone to convert an
-- expiry time to UTC. 'throwError' in the monad if parsing fails.
parseAddressMap :: MonadError ShowS m => TimeZone -> ByteString -> m AddressMap
parseAddressMap tz line
  | fst (breakWS rest) == b 5 "NEVER"# = return $! mapping Never
  | b 1 "\""# `B.isPrefixOf` rest, _:time:_ <- B.split '"' rest
  = prependError
      ("Failed parsing address mapping: " ++)
      ((mapping . Expiry . localTimeToUTC tz) `liftM` parseLocalTime time)
  | otherwise = throwError $ cat "Malformed address mapping "
                                 (esc maxMappingLen line) '.'
  where
    mapping = AddrMap (readAddress old) (readAddress new)
    (old,(new,rest)) = second breakWS $ breakWS line
    breakWS = second (B.dropWhile isSpace) . B.break isSpace
    maxMappingLen = 256

-- | An address mapping expiry time.
data Expiry = Expiry UTCTime | Never

instance Show Expiry where
  show (Expiry expiry) = take 19 (show expiry)
  show Never           = "Never"

--------------------------------------------------------------------------------
-- Errors

-- | A reply code designating a status, subsystem, and fine-grained information.
type ReplyCode = (Char, Char, Char)

-- | Reconstruct a reply line from the reply code and reply text.
replyLine :: Reply -> ByteString
replyLine (Reply (x,y,z) text _) = B.pack [x,y,z,' '] `B.append` text

-- | An error type used in dynamic exceptions.
data TorControlError
  -- | A negative reply code and human-readable status message.
  = TCError ReplyCode EscapedString
  -- | Parsing a reply from Tor failed.
  | ParseError
  -- | A reply from Tor didn't follow the protocol.
  | ProtocolError EscapedString -- the invalid reply
                  ShowS         -- file path and line number
  -- | The control connection is closed.
  | ConnectionClosed
  deriving Typeable

instance Show TorControlError where
  showsPrec _ (TCError (x,y,z) text) = cat [x,y,z,' '] (showEscaped 512 text)
  showsPrec _ ParseError = ("Parsing document failed" ++)
  showsPrec _ (ProtocolError reply loc) =
    cat "Protocol error: got " (showEscaped 512 reply) " at " loc
  showsPrec _ ConnectionClosed = ("Connection is already closed" ++)

-- | Convert a negative reply to a 'TorControlError'.
replyToError :: Reply -> TorControlError
replyToError (Reply code text _) = TCError code (escape text)

-- | Parse a reply code. 'throwError' in the monad if parsing fails.
parseReplyCode :: MonadError ShowS m => ByteString -> m ReplyCode
parseReplyCode bs
  | all isDigit cs, [x,y,z] <- cs = return (x, y, z)
  | otherwise = throwError $ cat "Malformed reply code " (esc maxCodeLen bs) '.'
  where cs = B.unpack bs
        maxCodeLen = 16

-- | Throw a 'TorControlError' if the reply indicates failure.
throwIfNotPositive :: Reply -> IO ()
throwIfNotPositive reply =
  unless (isPositive $ repCode reply) . E.throwDyn . replyToError $ reply

-- | Run an IO action, throwing a 'TorControlError' if it returns 'Nothing'.
throwIfNothing :: TorControlError -> IO (Maybe a) -> IO a
throwIfNothing e = (>>= maybe (E.throwDyn e) return)

-- | Is a reply successful?
isPositive :: ReplyCode -> Bool
isPositive ('2',_,_) = True
isPositive _         = False

--------------------------------------------------------------------------------
-- Aliases

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> ByteString
b = B.unsafePackAddress
