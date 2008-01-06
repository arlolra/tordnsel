{-# LANGUAGE PatternGuards, MultiParamTypeClasses #-}
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
--                             multi-parameter type classes, GHC primitives)
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
  , closeConnection
  , connectionThread

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
  , getConf'
  , setConf'
  , resetConf'
  , setConf''
  , sendCommand

  -- ** Config variables
  , ConfVal(..)
  , SameConfVal
  , ConfVar(..)
  , getConf
  , setConf
  , resetConf
  , fetchUselessDescriptors

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
  , startIOManager
  , ReplyType(..)
  , startSocketReader

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
  , commandFailed
  , protocolError
  , parseError
  , TorControlError(..)
  , toTCError
  , parseReplyCode
  , throwIfNotPositive
  , isPositive

  -- * Aliases
  , b
  ) where

import Control.Arrow (second)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, tryPutMVar)
import qualified Control.Exception as E
import Control.Monad (unless, liftM)
import Control.Monad.Error (MonadError(..))
import Control.Monad.Fix (fix)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (isSpace, isAlphaNum, isDigit, isAlpha, toLower)
import Data.Dynamic (fromDynamic)
import qualified Data.Map as M
import Data.Maybe (fromMaybe, maybeToList, listToMaybe, isNothing)
import qualified Data.Sequence as S
import Data.Sequence ((<|), ViewR((:>)), viewr)
import Data.Time (UTCTime, TimeZone, localTimeToUTC, getCurrentTimeZone)
import Data.Typeable (Typeable)
import System.IO (Handle, hClose, hSetBuffering, BufferMode(..), hFlush)
import System.IO.Error (isEOFError)

import GHC.Prim (Addr#)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Future
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Connections

-- | A Tor control connection.
data Connection
  = Conn (IOMessage -> IO ()) -- send a message to the I\/O manager
         ThreadId             -- the I\/O manager's 'ThreadId'

-- | Open a connection with a handle and pass it to an 'IO' action. If an
-- exception interrupts execution, close the connection gracefully before
-- re-throwing the exception.
withConnection :: Handle -> (Connection -> IO a) -> IO a
withConnection handle = E.bracket (openConnection handle) (closeConnection)

-- | Open a connection with a handle.
openConnection :: Handle -> IO Connection
openConnection handle = do
  hSetBuffering handle LineBuffering
  startIOManager handle

-- | Close a connection gracefully, blocking the current thread until the
-- connection has terminated.
closeConnection :: Connection -> IO ()
closeConnection conn@(Conn tellIOManager ioManagerTid) =
  E.finally
    (sendCommand quit True Nothing conn >>= throwIfNotPositive quit . head)
    (terminateThread Nothing ioManagerTid (tellIOManager CloseConnection))
  where quit = Command (b 4 "quit"#) [] []

-- | The 'ThreadId' associated with a 'Connection'. Useful for monitoring or
-- linking to a connection.
connectionThread :: Connection -> ThreadId
connectionThread (Conn _ ioManagerTid) = ioManagerTid

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
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  useFeature [VerboseNames] conn
  where command = Command (b 12 "authenticate"#) (maybeToList secret) []

-- | Control protocol extensions
data Feature = ExtendedEvents -- ^ Extended event syntax
             | VerboseNames   -- ^ Identify routers by long name

-- | Enable control protocol extensions. Throw a 'TorControlError' if the reply
-- code indicates failure.
useFeature :: [Feature] -> Connection -> IO ()
useFeature features conn =
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command (b 10 "usefeature"#) (map renderFeature features) []
    renderFeature ExtendedEvents = b 15 "extended_events"#
    renderFeature VerboseNames   = b 13 "verbose_names"#

-- | Fetch the most recent descriptor for a given router. Throw a
-- 'TorControlError' if the reply code isn't 250 or parsing the descriptor
-- fails.
getDescriptor :: RouterID -> Connection -> IO Descriptor
getDescriptor rid conn = do
  (r,command) <- getDocument arg parseDescriptor conn
  either (parseError command) return r
  where arg = b 8 "desc/id/"# `B.append` encodeBase16RouterID rid

-- | Fetch the most recent descriptor for every router Tor knows about. Throw a
-- 'TorControlError' if the reply code isn't 250. Also return error messages for
-- any descriptors that failed to be parsed.
getAllDescriptors :: Connection -> IO ([Descriptor], [ShowS])
getAllDescriptors conn = do
  (r,command) <- getDocument arg parseDescriptors conn
  return $ map (cat (commandFailed command)) `second` swap (partitionEither r)
  where arg = b 15 "desc/all-recent"#

-- | Fetch the current status entry for a given router. Throw a
-- 'TorControlError' if the reply code isn't 250 or parsing the router status
-- entry fails.
getRouterStatus :: RouterID -> Connection -> IO RouterStatus
getRouterStatus rid conn = do
  (r,command) <- getDocument arg parseRouterStatus conn
  either (parseError command) return r
  where arg = b 6 "ns/id/"# `B.append` encodeBase16RouterID rid

-- | Fetch the current status entries for every router Tor has an opinion about.
-- Throw a 'TorControlError' if the reply code isn't 250. Also return error
-- messages for any router status entries that failed to be parsed.
getNetworkStatus :: Connection -> IO ([RouterStatus], [ShowS])
getNetworkStatus conn = do
  (r,command) <- getDocument arg parseRouterStatuses conn
  return $ map (cat (commandFailed command)) `second` swap (partitionEither r)
  where arg = b 6 "ns/all"#

-- | Send a GETINFO command using @key@ as a single keyword. If the reply code
-- is 250, pass the document contained in data from the first reply to @parse@
-- and return the parsed document. Otherwise, throw a 'TorControlError'. Also
-- return the GETINFO 'Command' itself.
getDocument :: ByteString -> (Document -> a) -> Connection -> IO (a, Command)
getDocument key parse conn = do
  reply:_ <- sendCommand command False Nothing conn
  case reply of
    Reply ('2','5','0') text doc
      | text == B.snoc key '=' -> return (parse $ parseDocument doc, command)
      | otherwise -> protocolError command $ cat "Got " (esc maxRepLen text) '.'
    _             -> E.throwDyn $ toTCError command reply
  where command = Command (b 7 "getinfo"#) [key] []
        maxRepLen = 64

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
getStatus ::
  ByteString -> (ByteString -> Either ShowS a) -> Connection -> IO [a]
getStatus key parse conn = do
  reply:_ <- sendCommand command False Nothing conn
  let prefix   = B.snoc key '='
      validKey = prefix `B.isPrefixOf` repText reply
  case reply of
    Reply ('2','5','0') text dataLines
      | prefix == text
      , null dataLines -> return []
      | not validKey   -> protocolError command $ cat "Got "
                                                      (esc maxRepLen text) '.'
      | null dataLines -> check (:[]) (parse $ B.drop (B.length key + 1) text)
      | otherwise      -> check id $ mapM parse dataLines
    _                  -> E.throwDyn $ toTCError command reply
  where command = Command (b 7 "getinfo"#) [key] []
        check f = either (parseError command) (return . f)
        maxRepLen = 64

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
extendCircuit' :: Maybe CircuitID -> [RouterID] -> Maybe CircuitPurpose
               -> Connection -> IO CircuitID
extendCircuit' circuit path purpose conn = do
  reply:_ <- sendCommand command False Nothing conn
  case reply of
    Reply ('2','5','0') text _
      | msg:cid':_ <- B.split ' ' text, msg == b 8 "EXTENDED"#
      , maybe True (== CircId cid') circuit -> return $ CircId (B.copy cid')
      | otherwise -> protocolError command $ cat "Got " (esc maxRepLen text) '.'
    _             -> E.throwDyn $ toTCError command reply
  where
    command = Command (b 13 "extendcircuit"#) args []
    args = add purpose [cid, B.join (b 1 ","#) $ map encodeBase16RouterID path]
    CircId cid = fromMaybe nullCircuitID circuit
    renderPurpose CrGeneral    = b 7  "general"#
    renderPurpose CrController = b 10 "controller"#
    add = maybe id (\p -> (++ [b 8 "purpose="# `B.append` renderPurpose p]))
    maxRepLen = 64

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
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command (b 12 "attachstream"#) (add hop [sid,cid]) []
    CircId cid = fromMaybe nullCircuitID circuit
    add = maybe id (flip (++) . (:[]) . B.append (b 4 "HOP="#) . B.pack . show)

-- | Change a stream's destination address and port, if specified. Throw a
-- 'TorControlError' if the reply code indicates failure.
redirectStream :: StreamID -> Address -> Maybe Port -> Connection -> IO ()
redirectStream (StrmId sid) addr port conn =
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
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
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command (b 12 "closecircuit"#) (cid : flagArgs) []
    flagArgs = [flag | (p,flag) <- [(ifUnused, b 8 "IfUnused"#)], p flags]

-- | Send a GETCONF command with a set of config variable names, returning
-- a set of key-value pairs. Throw a 'TorControlError' if the reply code
-- indicates failure.
getConf' :: [ByteString] -> Connection -> IO [(ByteString, Maybe ByteString)]
getConf' keys conn = do
  rs@(r:_) <- sendCommand command False Nothing conn
  throwIfNotPositive command r
  either (protocolError command) return (mapM (parseText . repText) rs)
  where
    command = Command (b 7 "getconf"#) keys []
    parseText text
      | B.null eq      = return (key, Nothing)
      | eq == b 1 "="# = return (key, Just val)
      | otherwise      = throwError $ cat "Malformed GETCONF reply "
                                          (esc maxTextLen text) '.'
      where (key,(eq,val)) = B.splitAt 1 `second` B.span isAlpha text
            maxTextLen = 128

-- | Send a SETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code indicates failure.
setConf' :: [(ByteString, Maybe ByteString)] -> Connection -> IO ()
setConf' = setConf'' (b 7 "setconf"#)

-- | Send a RESETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code indicates failure.
resetConf' :: [(ByteString, Maybe ByteString)] -> Connection -> IO ()
resetConf' = setConf'' (b 9 "resetconf"#)

-- | Send a SETCONF or RESETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code indicates failure.
setConf''
  :: ByteString -> [(ByteString, Maybe ByteString)] -> Connection -> IO ()
setConf'' name args conn =
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command name (map renderArg args) []
    renderArg (key, Just val) = B.join (b 1 "="#) [key, val]
    renderArg (key, _)        = key

-- | Send a command using a connection, blocking the current thread until all
-- replies have been received. The optional @mbEvHandlers@ parameter specifies
-- a list of event handlers to replace the currently installed event handlers.
-- @isQuit@ specifies whether this is a QUIT command.
sendCommand
  :: Command -> Bool -> Maybe [EventHandler] -> Connection -> IO [Reply]
sendCommand command isQuit mbEvHandlers (Conn tellIOManager ioManagerTid) = do
  mv <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar mv
  withMonitor ioManagerTid (putResponse . Left) $ do
    tellIOManager $ SendCommand command isQuit mbEvHandlers (putResponse.Right)
    response <- takeMVar mv
    case response of
      Left Nothing                                -> E.throwDyn ConnectionClosed
      Left (Just (E.DynException d))
        | Just NonexistentThread <- fromDynamic d -> E.throwDyn ConnectionClosed
      Left (Just e)                               -> E.throwIO e
      Right replies                               -> return replies

--------------------------------------------------------------------------------
-- Config variables

-- | The type of config values.
class ConfVal a where
  -- | Encode a config value for the control protocol.
  encodeConfVal :: a -> ByteString
  -- | Decode a config value from the control protocol. 'throwError' in the
  -- monad if decoding fails.
  decodeConfVal :: MonadError ShowS m => ByteString -> m a

instance ConfVal Bool where
  encodeConfVal True  = b 1 "1"#
  encodeConfVal False = b 1 "0"#

  decodeConfVal bool
    | bool == b 1 "1"# = return True
    | bool == b 1 "0"# = return False
    | otherwise = throwError $ cat "Malformed boolean conf value "
                                   (esc maxBoolLen bool) '.'
    where maxBoolLen = 32

-- | A constraint requiring 'setConf' and 'resetConf' to take the same type of
-- config value as 'getConf' returns.
class SameConfVal a b

instance SameConfVal a a

instance SameConfVal (Maybe a) a

-- | A functional reference to a config variable.
data (ConfVal b, SameConfVal a b) => ConfVar a b
  = ConfVar { getConf_   :: Connection -> IO a
            , setConf_
            , resetConf_ :: Maybe b -> Connection -> IO () }

-- | Retrieve the value of a config variable, throwing a 'TorControlError'
-- if the command fails.
getConf :: (ConfVal b, SameConfVal a b) => ConfVar a b -> Connection -> IO a
getConf = getConf_

-- | Set the value of a config variable, throwing a 'TorControlError' if the
-- command fails.
setConf :: (ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Maybe b -> Connection -> IO ()
setConf = setConf_

-- | Reset the value of a config variable, throwing a 'TorControlError' if
-- the command fails.
resetConf :: (ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Maybe b -> Connection -> IO ()
resetConf = resetConf_

-- | Enables fetching descriptors for non-running routers.
fetchUselessDescriptors :: ConfVar Bool Bool
fetchUselessDescriptors = ConfVar get (set setConf') (set resetConf') where
  get conn = do
    (key,val):_ <- getConf' [var] conn
    case fmap decodeConfVal val of
      Nothing       -> psErr $ cat "Unexpected empty value for \"" var "\"."
      Just (Left e) -> psErr $ cat "Failed parsing value for \"" var "\": " e
      Just (Right val')
        | B.map toLower key /= var -> psErr $ cat "Received conf value "
            (esc maxVarLen key) ", expecting \"" var "\"."
        | otherwise                -> return val'
  set f val = f [(var, fmap encodeConfVal val)]
  var = b 23 "fetchuselessdescriptors"#
  psErr = E.throwDyn . ParseError
  maxVarLen = 64

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
registerEventHandlers handlers conn =
  sendCommand command False (Just handlers) conn
    >>= throwIfNotPositive command . head
  where command = Command (b 9 "setevents"#) (map evCode handlers) []

-- | Create an event handler for new router descriptor events.
newDescriptorsEvent ::
  ([TorControlError] -> [Descriptor] -> IO ()) -> Connection -> EventHandler
newDescriptorsEvent handler conn = EventHandler (b 7 "NEWDESC"#) handleNewDesc
  where
    safeGetDescriptor rid = Right `fmap` getDescriptor rid conn
      `E.catchDyn` \(e :: TorControlError) -> return (Left e)
    handleNewDesc (Reply _ text _:_) = do
      -- pipeline descriptor requests
      (es',ds) <- fmap partitionEither . mapM resolve
                    =<< mapM (spawn . safeGetDescriptor) rids
      handler (map ParseError es ++ es') ds
      where (es,rids) = partitionEither . map decodeBase16RouterID .
              map (B.take 40 . B.drop 1) . B.split ' ' . B.drop 8 $ text
    handleNewDesc _ = return ()

-- | Create an event handler for network status events.
networkStatusEvent ::
  ([TorControlError] -> [RouterStatus] -> IO ()) -> EventHandler
networkStatusEvent handler = EventHandler (b 2 "NS"#) handleNS
  where
    handleNS (Reply _ _ doc@(_:_):_) = handler (map ParseError es) rs
      where (es,rs) = partitionEither . parseRouterStatuses $ parseDocument doc
    handleNS _ = return ()

-- | Create an event handler for stream status change events.
streamEvent :: (Either TorControlError StreamStatus -> IO ()) -> EventHandler
streamEvent = lineEvent (b 6 "STREAM"#) parseStreamStatus

-- | Create an event handler for circuit status change events.
circuitEvent :: (Either TorControlError CircuitStatus -> IO ()) -> EventHandler
circuitEvent = lineEvent (b 4 "CIRC"#) parseCircuitStatus

-- | Create an event handler for circuit/stream status change events. The event
-- code is specified by @code@, and the line-parsing function by @parse@.
lineEvent :: ByteString -> (ByteString -> Either ShowS a)
          -> (Either TorControlError a -> IO ()) -> EventHandler
lineEvent code parse handler = EventHandler code handleStatus
  where
    handleStatus (Reply _ text _:_) =
      handler . either (Left . ParseError) Right .
        parse . B.drop (B.length code + 1) $ text
    handleStatus _ = return ()

-- | Create an event handler for new address mapping events.
addressMapEvent :: (Either TorControlError AddressMap -> IO ()) -> EventHandler
addressMapEvent handler = EventHandler (b 7 "ADDRMAP"#) handleAddrMap
  where
    handleAddrMap (Reply _ text _:_) = do
      -- XXX Extended events will provide the UTCTime in 0.2.0.x.
      tz <- getCurrentTimeZone
      handler . either (Left . ParseError) Right .
        parseAddressMap tz . B.drop 8 $ text
    handleAddrMap _ = return ()

--------------------------------------------------------------------------------
-- Backend connection manager

-- | A message sent to the I\/O manager.
data IOMessage
  -- | Send a command to Tor.
  = SendCommand Command                -- the command to send to Tor
                Bool                   -- is this a QUIT command?
                (Maybe [EventHandler]) -- event handlers to register
                ([Reply] -> IO ())     -- invoke this action with replies
  -- | Handle a sequence of replies from Tor.
  | Replies [Reply]
  -- | Terminate the connection with Tor.
  | CloseConnection
  -- | An exit signal sent to the I\/O manager.
  | Exit ThreadId ExitReason

-- | An internal type containing the I\/O manager state.
data IOManagerState = IOManagerState
  { -- | A sequence of actions used to respond to outstanding commands.
    responds :: S.Seq ([Reply] -> IO ()),
    -- | The thread in which event handlers are invoked.
    evHandlerTid :: ThreadId,
    -- | A map from event name to event handler.
    evHandlers :: M.Map ByteString ([Reply] -> IO ()),
    -- | Has the QUIT command been sent?
    quitSent :: Bool }

-- | Start the thread that manages all I\/O associated with a Tor control
-- connection, linking it to the calling thread. We receive messages sent with
-- the returned 'Connection' and send the appropriate command to Tor. When we
-- receive replies from Tor, we pass them in a message to the thread that
-- requested the corresponding command. Asynchronous event handlers are
-- maintained as local state, invoked as necessary for incoming events.
startIOManager :: Handle -> IO Connection
startIOManager handle = do
  ioChan <- newChan
  ioManagerTid <- forkLinkIO $ do
    setTrapExit ((writeChan ioChan .) . Exit)
    socketReaderTid <- startSocketReader handle (writeChan ioChan . Replies)
    eventChan <- newChan
    initEventTid <- startEventHandler eventChan
    let runIOManager io =
          fix io (IOManagerState S.empty initEventTid M.empty False)
            `E.finally` hClose handle
    runIOManager $ \loop s -> do
      message <- readChan ioChan
      case message of
        Exit tid reason
          | tid == evHandlerTid s -> do
              newEvHandlerTid <- startEventHandler eventChan
              loop s { evHandlerTid = newEvHandlerTid }
          | isNothing reason -> loop s
          | tid == socketReaderTid
          , Just (E.IOException e) <- reason, isEOFError e
          , quitSent s, S.null (responds s) -> kill $ evHandlerTid s
          | otherwise -> exit reason

        CloseConnection -> mapM_ kill [socketReaderTid, evHandlerTid s]

        Replies replies@(r:_)
          | ('6',_,_) <- repCode r -> do
              whenJust (eventCode r `M.lookup` evHandlers s) $
                writeChan eventChan . Right . ($ replies)
              loop s
          | responds' :> respond <- viewr (responds s) -> do
              respond replies
              loop s { responds = responds' }
        Replies _ -> loop s

        SendCommand command isQuit mbEvHandlers respond -> do
          B.hPut handle $ renderCommand command
          hFlush handle
          case mbEvHandlers of
            Just hs -> loop s' { evHandlers = M.fromList .
                                  map (\(EventHandler c h) -> (c, h)) $ hs }
            _       -> loop s'
          where s' = s { responds = respond <| responds s, quitSent = isQuit }

  return $ Conn (writeChan ioChan) ioManagerTid
  where
    startEventHandler eventChan = do
      ioManagerTid <- myThreadId
      forkLinkIO $ do
        setTrapExit (curry $ writeChan eventChan . Left)
        fix $ \loop -> do
          message <- readChan eventChan
          case message of
            Left (tid,reason)
              | tid == ioManagerTid -> exit reason
              | otherwise           -> loop
            Right event             -> event >> loop

    kill tid = terminateThread Nothing tid . throwTo tid . Just $
                 E.AsyncException E.ThreadKilled

    renderCommand (Command key args []) =
      B.join (b 1 " "#) (key : args) `B.append` b 2 "\r\n"#
    renderCommand c@(Command _ _ data') =
      B.cons '+' (renderCommand c { comData = [] }) `B.append` renderData data'

    renderData =
      B.concat . foldr (\line xs -> line : b 2 "\r\n"# : xs) [b 3 ".\r\n"#]

    eventCode = B.takeWhile (/= ' ') . repText

-- | Reply types in a single sequence of replies.
data ReplyType
  = MidReply  {-# UNPACK #-} !Reply -- ^ A reply preceding other replies.
  | LastReply {-# UNPACK #-} !Reply -- ^ The last reply.
  deriving Show

-- | Start a thread that reads replies from @handle@ and passes them to
-- @sendRepliesToIOManager@, linking it to the calling thread.
startSocketReader :: Handle -> ([Reply] -> IO ()) -> IO ThreadId
startSocketReader handle sendRepliesToIOManager =
  forkLinkIO . forever $ readReplies >>= sendRepliesToIOManager
  where
    readReplies = do
      line <- parseReplyLine =<< hGetLine handle crlf maxLineLength
      case line of
        MidReply reply  -> fmap (reply :) readReplies
        LastReply reply -> return [reply]

    parseReplyLine line =
      either (E.throwDyn . ProtocolError) (parseReplyLine' typ text)
             (parseReplyCode code)
      where (code,(typ,text)) = B.splitAt 1 `second` B.splitAt 3 line

    parseReplyLine' typ text code
      | typ == b 1 "-"# = return . MidReply $ Reply code text []
      | typ == b 1 "+"# = (MidReply . Reply code text) `fmap` readData
      | typ == b 1 " "# = return . LastReply $ Reply code text []
      | otherwise = E.throwDyn . ProtocolError $
                      cat "Malformed reply line type " (esc 1 typ) '.'

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

-- | An error type used in dynamic exceptions.
data TorControlError
  -- | A command, negative reply code, and human-readable status message.
  = TCError Command ReplyCode ByteString
  | ParseError ShowS -- ^ Parsing a reply from Tor failed.
  | ProtocolError ShowS -- ^ A reply from Tor didn't follow the protocol.
  | ConnectionClosed -- ^ The control connection is closed.
  deriving Typeable

instance Show TorControlError where
  showsPrec _ (TCError command (x,y,z) text) = cat (commandFailed command)
                                                   [x,y,z,' '] (esc 512 text)
  showsPrec _ (ParseError msg) = cat "Parsing error: " msg
  showsPrec _ (ProtocolError msg) = cat "Protocol error: " msg
  showsPrec _ ConnectionClosed = ("Connection is already closed" ++)

-- | Given a command, return a \"command failed\" message.
commandFailed :: Command -> ShowS
commandFailed (Command key args _) =
  cat "Command \"" key ' ' (B.unwords args) "\" failed with: "

-- | Throw a 'ProtocolError' given a command and error message.
protocolError :: Command -> ShowS -> IO a
protocolError command = E.throwDyn . ProtocolError . cat (commandFailed command)

-- | Throw a 'ParseError' given a command and an error message.
parseError :: Command -> ShowS -> IO a
parseError command = E.throwDyn . ParseError . cat (commandFailed command)

-- | Convert a command and negative reply to a 'TorControlError'.
toTCError :: Command -> Reply -> TorControlError
toTCError command (Reply code text _) = TCError command code text

-- | Parse a reply code. 'throwError' in the monad if parsing fails.
parseReplyCode :: MonadError ShowS m => ByteString -> m ReplyCode
parseReplyCode bs
  | all isDigit cs, [x,y,z] <- cs = return (x, y, z)
  | otherwise = throwError $ cat "Malformed reply code " (esc 3 bs) '.'
  where cs = B.unpack bs

-- | Throw a 'TorControlError' if the reply indicates failure.
throwIfNotPositive :: Command -> Reply -> IO ()
throwIfNotPositive command reply =
  unless (isPositive $ repCode reply) $
    E.throwDyn $ toTCError command reply

-- | Is a reply successful?
isPositive :: ReplyCode -> Bool
isPositive ('2',_,_) = True
isPositive _         = False

--------------------------------------------------------------------------------
-- Aliases

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> ByteString
b = B.unsafePackAddress
