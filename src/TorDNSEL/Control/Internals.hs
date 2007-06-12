{-# OPTIONS_GHC -fglasgow-exts #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Control.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Interfacing with Tor using the Tor control protocol, version 1. We support
-- fetching router descriptors and router status entries, including those sent
-- in asynchronous events that Tor generates when it receives new information
-- from directories.
--
-- See <https://tor.eff.org/svn/trunk/doc/spec/control-spec.txt> for details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Control.Internals (
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
  , useVerboseNames
  , fetchDescriptor
  , fetchAllDescriptors
  , fetchRouterStatus
  , fetchNetworkStatus
  , setFetchUselessDescriptors
  , fetchDocument
  , setConf
  , sendCommand

  -- * Asynchronous events
  , EventHandler(..)
  , registerEventHandlers
  , newDescriptors
  , newNetworkStatus

  -- * Backend connection manager
  , IOMessage(..)
  , ioManager
  , ReplyType(..)
  , socketReader

  -- * Errors
  , TorControlError(..)
  , statusCodeToError
  , throwIfNotSuccess
  , throwParseIfNothing
  , isSuccess

  -- * Helpers
  , b
  ) where

import Control.Concurrent (forkIO, killThread, myThreadId)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newEmptyMVar, takeMVar, putMVar, withMVar)
import qualified Control.Exception as E
import Control.Monad (unless)
import Data.Maybe (fromMaybe, catMaybes, maybeToList)
import Data.Foldable (traverse_)
import Data.Typeable (Typeable)
import qualified Data.Map as M
import qualified Data.Sequence as S
import Data.Sequence ((<|), ViewR((:>)), viewr)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import System.IO (Handle, hClose, hSetBuffering, BufferMode(..), hFlush)

import GHC.Prim (Addr#)

import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Connections

-- | A Tor control connection.
data Connection
  = Conn {-# UNPACK #-} !(Chan IOMessage) -- the channel 'ioManager' reads
         {-# UNPACK #-} !(MVar ())        -- signals a terminated connection

-- | Open a connection with a handle and pass it to an IO action. If the IO
-- action throws an exception or an I\/O error occurs during the connection, the
-- connection will be terminated and the exception re-thrown in the current
-- thread.
withConnection :: Handle -> (Connection -> IO a) -> IO a
withConnection handle io = do
  tid <- myThreadId
  let closeHandler = flip whenJust (E.throwTo tid . E.IOException)
  E.bracket (openConnection handle closeHandler) closeConnection io

-- | Open a connection with a handle, installing a handler to be invoked when
-- the connection terminates. If the connection is terminated by an I\/O error,
-- we pass an 'IOError' to the handler. Otherwise, it was terminated by
-- 'closeConnection', so it will be passed 'Nothing'.
openConnection :: Handle -> (Maybe IOError -> IO ()) -> IO Connection
openConnection handle closeHandler = do
  hSetBuffering handle LineBuffering
  chan <- newChan
  mv <- newEmptyMVar
  -- closeHandler should be called before putMVar so the async exception can
  -- interrupt waitForConnection inside withConnection. Otherwise, the async
  -- exception will be delivered outside withConnection, creating a race
  -- condition for external exception handlers.
  forkIO $ ioManager handle chan (\e -> closeHandler e `E.finally` putMVar mv ())
  return (Conn chan mv)

-- | Block the current thread until a connection terminates. This can happen
-- when an I\/O error occurs or another thread calls 'closeConnection'.
waitForConnection :: Connection -> IO ()
waitForConnection (Conn _ mv) = withMVar mv return

-- | Close a connection, blocking the current thread until the connection has
-- terminated.
closeConnection :: Connection -> IO ()
closeConnection (Conn chan mv) = do
  writeChan chan CloseConnection
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
    comData :: {-# UNPACK #-} !(Maybe [ByteString])
  } deriving Show

-- | A reply sent by Tor in response to a command.
data Reply = Reply
  { -- | A reply status code.
    repStatus :: {-# UNPACK #-} !Int
    -- | Reply text.
  , repText   :: {-# UNPACK #-} !ByteString
    -- | A list of lines from the data section.
  , repData   :: {-# UNPACK #-} !(Maybe [ByteString])
  } deriving Show

-- | Authenticate with Tor using a hashed password or cookie, then enable long
-- names in future replies. Throw 'TorControlError' if either reply code
-- indicates failure.
authenticate :: Maybe ByteString -> Connection -> IO ()
authenticate secret conn = do
  sendCommand command conn >>= throwIfNotSuccess . head
  useVerboseNames conn
  where command = Command (b 12 "authenticate"#) (maybeToList secret) Nothing

-- | Enable long names in future replies. Throw 'TorControlError' if the reply
-- code indicates failure.
useVerboseNames :: Connection -> IO ()
useVerboseNames conn =
  sendCommand command conn >>= throwIfNotSuccess . head
  where command = Command (b 10 "usefeature"#) [b 13 "verbose_names"#] Nothing

-- | Fetch the most recent descriptor for a given router. Throw
-- 'TorControlError' if the reply code isn't 250 or parsing the descriptor
-- fails.
fetchDescriptor :: Fingerprint -> Connection -> IO Descriptor
fetchDescriptor fp = throwParseIfNothing . fetchDocument key parseDescriptor
  where key = b 8 "desc/id/"# `B.append` encodeBase16Fingerprint fp

-- | Fetch the most recent descriptor for every router Tor knows about. Throw
-- 'TorControlError' if the reply code isn't 250.
fetchAllDescriptors :: Connection -> IO [Descriptor]
fetchAllDescriptors = fetchDocument key parseDescriptors
  where key = b 15 "desc/all-recent"#

-- | Fetch the current status entry for a given router. Throw 'TorControlError'
-- if the reply code isn't 250 or parsing the router status entry fails.
fetchRouterStatus :: Fingerprint -> Connection -> IO RouterStatus
fetchRouterStatus fp = throwParseIfNothing . fetchDocument arg parseRouterStatus
  where arg = b 6 "ns/id/"# `B.append` encodeBase16Fingerprint fp

-- | Fetch the current status entries for every router Tor has an opinion about.
-- Throw 'TorControlError' if the reply code isn't 250.
fetchNetworkStatus :: Connection -> IO [RouterStatus]
fetchNetworkStatus = fetchDocument arg parseRouterStatuses
  where arg = b 6 "ns/all"#

-- | Set Tor's config option \"FetchUselessDescriptors\" so we get descriptors
-- for non-running routers. Throw 'TorControlError' if the reply code isn't 250.
setFetchUselessDescriptors :: Connection -> IO ()
setFetchUselessDescriptors conn =
  setConf [(b 23 "fetchuselessdescriptors"#, Just (b 1 "1"#))] conn

-- | Send a @GETINFO@ command using @key@ as a single keyword. If the reply code
-- is 250, pass the document contained in data from the first reply to @parse@
-- and return the parsed document. Otherwise, throw 'TorControlError'.
fetchDocument :: ByteString -> (Document -> doc) -> Connection -> IO doc
fetchDocument key parse conn = do
  reply:_ <- sendCommand command conn
  case reply of
    Reply 250 _ (Just doc) | repText reply == key `B.snoc` '='
      -> return . parse . parseDocument $ doc
    _ -> E.throwDyn . statusCodeToError . repStatus $ reply
  where command = Command (b 7 "getinfo"#) [key] Nothing

-- | Send a @SETCONF@ command with a set of key-value pairs. Throw
-- 'TorControlError' if the reply code isn't 250.
setConf :: [(ByteString, Maybe ByteString)] -> Connection -> IO ()
setConf args conn = do
  reply:_ <- sendCommand command conn
  case reply of
    Reply 250 _ _ -> return ()
    _             -> E.throwDyn . statusCodeToError . repStatus $ reply
  where
    command = Command (b 7 "setconf"#) (map renderArg args) Nothing
    renderArg (key, Just val) = B.join (b 1 "="#) [key,val]
    renderArg (key, _)        = key

-- | Send a command using a connection, blocking the current thread until all
-- replies have been received.
sendCommand :: Command -> Connection -> IO [Reply]
sendCommand c (Conn chan _) = do
  mv <- newEmptyMVar
  writeChan chan (SendCommand c (putMVar mv))
  takeMVar mv

--------------------------------------------------------------------------------
-- Asynchronous events

-- | An asynchronous event handler.
data EventHandler = EventHandler
  { evCode    :: {-# UNPACK #-} !ByteString         -- ^ The event code.
  , evHandler :: {-# UNPACK #-} !([Reply] -> IO ()) -- ^ The event handler.
  }

-- | Register a set of handlers for asynchronous events. This deregisters any
-- previously registered event handlers for this connection. Throw
-- 'TorControlError' if the reply code indicates failure.
registerEventHandlers :: [EventHandler] -> Connection -> IO ()
registerEventHandlers handlers (Conn chan _) = do
  mv <- newEmptyMVar
  writeChan chan (RegisterEvents command (putMVar mv) handlers)
  takeMVar mv >>= throwIfNotSuccess . head
  where command = Command (b 9 "setevents"#) (map evCode handlers) Nothing

-- | Create an event handler to handle new router descriptor events.
newDescriptors :: ([Descriptor] -> IO ()) -> Connection -> EventHandler
newDescriptors handler conn = EventHandler (b 7 "NEWDESC"#) handleNewDesc
  where
    safeFetchDescriptor fp = Just `fmap` fetchDescriptor fp conn
      `E.catchDyn` \(_ :: TorControlError) -> return Nothing
    handleNewDesc (reply@(Reply 650 _ _):_)
      | Just fps' <- mapM decodeBase16Fingerprint fps
      = handler . catMaybes =<< mapM safeFetchDescriptor fps'
      where
        fps = map (B.take 40 . B.drop 1) longNames
        longNames = B.split ' ' . B.drop 8 . repText $ reply
    handleNewDesc _ = return ()

-- | Create an event handler to handle new router status events.
newNetworkStatus :: ([RouterStatus] -> IO ()) -> EventHandler
newNetworkStatus handler = EventHandler (b 2 "NS"#) handleNS
  where
    handleNS (Reply 650 _ (Just doc):_) =
      handler . parseRouterStatuses . parseDocument $ doc
    handleNS _ = return ()

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
  -- | The 'socketReader' died due to an I\/O error.
  | ReaderDied IOError

-- | Manage all I\/O associated with a Tor control connection. We receive
-- messages from @chan@ and send the appropriate command to Tor. When we receive
-- replies from Tor, we pass them in a message to the thread that requested the
-- corresponding command. Asynchronous event handlers are maintained as local
-- state, invoked as necessary for incoming events. If an I\/O error occurs or
-- a 'CloseConnection' message is received, we pass the possible error to
-- @closeHandler@ and return.
ioManager :: Handle -> Chan IOMessage -> (Maybe IOError -> IO ()) -> IO ()
ioManager handle chan closeHandler = do
  reader <- forkIO $ socketReader handle (writeChan chan)
  loop reader S.empty M.empty
  where
    loop reader responds evHandlers = do
      message <- readChan chan
      case message of
        ReaderDied e    -> close (Just e)
        CloseConnection -> close Nothing
        ReceiveReplies replies@(r:_)
          -- if we have a handler, invoke it in a separate thread
          | 600 <= repStatus r, repStatus r <= 699 -> do
            whenJust (M.lookup (eventCode r) evHandlers) $
              \handler -> forkIO (handler replies) >> return ()
            loop reader responds evHandlers
          -- give replies to the oldest respond action
          | responds' :> respond <- viewr responds ->
            respond replies >> loop reader responds' evHandlers
          -- no respond actions to handle these replies
          | otherwise -> loop reader responds evHandlers
        SendCommand command respond ->
          (E.tryJust E.ioErrors . putBS . renderCommand) command
            >>= either (close . Just)
                       (const $ loop reader (respond <| responds) evHandlers)
        RegisterEvents command respond handlers ->
          (E.tryJust E.ioErrors . putBS . renderCommand) command
            >>= either (close . Just)
                       (const $ loop reader (respond <| responds) hs)
            where
              hs = M.fromList $ map (\(EventHandler c h) -> (c,h)) handlers
        ReceiveReplies [] -> error "ioManager: empty replies"
      where
        close e = do
          -- send resource exhausted to threads blocked waiting for a reply
          traverse_ ($ [Reply 451 B.empty Nothing]) responds
          killThread reader
          hClose handle `E.finally` closeHandler e

    renderCommand c@(Command _ _ Nothing) =
      comKey c `B.append` B.concat (map (B.cons ' ') (comArgs c))
        `B.append` b 2 "\r\n"#
    renderCommand c@(Command _ _ (Just data')) =
      B.cons '+' (renderCommand c { comData = Nothing })
        `B.append` renderData data'
    renderData dataLines =
      B.join (b 2 "\r\n"#) (dataLines ++ [b 5 "\r\n.\r\n"#])
    eventCode = B.takeWhile (/= ' ') . repText
    putBS bs = B.hPut handle bs >> hFlush handle

-- | Reply types in a single sequence of replies.
data ReplyType
  = MidReply {-# UNPACK #-} !Reply  -- ^ A reply preceding other replies.
  | LastReply {-# UNPACK #-} !Reply -- ^ The last reply.
  deriving Show

-- | In an infinite loop, read replies from @handle@ and pass them to @send@.
-- If an I\/O error occurs, pass it to @send@ and return.
socketReader :: Handle -> (IOMessage -> IO ()) -> IO ()
socketReader handle send =
  E.catchJust E.ioErrors
    (forever $ readReplies >>= send . ReceiveReplies)
    (send . ReaderDied)
  where

    readReplies = do
      replyLine <- parseReplyLine =<< B.hGetLine handle
      case replyLine of
        MidReply reply  -> fmap (reply :) readReplies
        LastReply reply -> return [reply]

    parseReplyLine line
      | lineType == b 1 "-"# = return . MidReply . reply $ Nothing
      | lineType == b 1 "+"# = (dataReply . reply . Just) `fmap` readData
      | otherwise            = return . LastReply . reply $ Nothing
      where
        reply = Reply status' text
        status' = fromMaybe 551 . readInt $ status
        (lineType,text) = B.splitAt 1 line'
        (status,line') = B.splitAt 3 . B.init $ line
        -- data reply lines for async events don't follow the tc1 grammar
        dataReply | status' == 650 = LastReply
                  | otherwise      = MidReply
    readData = do
      x <- B.hGetLine handle
      let x' | B.last x == '\r' = B.init x
             | otherwise        = x
      case () of
        _| x == b 2 ".\r"#   -> return []
         | any B.null [x,x'] -> readData
         | otherwise         -> fmap (x' :) readData

--------------------------------------------------------------------------------
-- Errors

-- | A negative reply code used in dynamic exceptions.
data TorControlError
  = ResourceExhausted         -- ^ 451 Resource exhausted
  | ProtocolSyntaxError       -- ^ 500 Syntax error: protocol
  | UnrecognizedCommand       -- ^ 510 Unrecognized command
  | UnimplementedCommand      -- ^ 511 Unimplemented command
  | ArgumentSyntaxError       -- ^ 512 Syntax error in command argument
  | UnrecognizedArgument      -- ^ 513 Unrecognized command argument
  | AuthenticationRequired    -- ^ 514 Authentication required
  | BadAuthentication         -- ^ 515 Bad authentication
  | UnspecifiedTorError       -- ^ 550 Unspecified Tor error
  | InternalError             -- ^ 551 Internal error
  | UnrecognizedEntity        -- ^ 552 Unrecognized entity
  | InvalidConfigurationValue -- ^ 553 Invalid configuration value
  | InvalidDescriptor         -- ^ 554 Invalid descriptor
  | UnmanagedEntity           -- ^ 555 Unmanaged entity
  | UnrecognizedError Int     -- ^ An unrecognized error code
  | ControllerParseError      -- ^ Parsing a reply from Tor failed
  deriving Typeable

instance Show TorControlError where
  show e = case e of
    ResourceExhausted         -> "451 Resource exhausted"
    ProtocolSyntaxError       -> "500 Syntax error: protocol"
    UnrecognizedCommand       -> "510 Unrecognized command"
    UnimplementedCommand      -> "511 Unimplemented command"
    ArgumentSyntaxError       -> "512 Syntax error in command argument"
    UnrecognizedArgument      -> "513 Unrecognized command argument"
    AuthenticationRequired    -> "514 Authentication required"
    BadAuthentication         -> "515 Bad authentication"
    UnspecifiedTorError       -> "550 Unspecified Tor error"
    InternalError             -> "551 Internal error"
    UnrecognizedEntity        -> "552 Unrecognized entity"
    InvalidConfigurationValue -> "553 Invalid configuration value"
    InvalidDescriptor         -> "554 Invalid descriptor"
    UnmanagedEntity           -> "555 Unmanaged entity"
    UnrecognizedError status  -> show status ++ " Unrecognized error"
    ControllerParseError      -> "Controller parse error"

-- | Convert a status code to a 'TorControlError' to be thrown as a dynamic
-- exception.
statusCodeToError :: Int -> TorControlError
statusCodeToError status = case status of
  451 -> ResourceExhausted
  500 -> ProtocolSyntaxError
  510 -> UnrecognizedCommand
  511 -> UnimplementedCommand
  512 -> ArgumentSyntaxError
  513 -> UnrecognizedArgument
  514 -> AuthenticationRequired
  515 -> BadAuthentication
  550 -> UnspecifiedTorError
  551 -> InternalError
  552 -> UnrecognizedEntity
  553 -> InvalidConfigurationValue
  554 -> InvalidDescriptor
  555 -> UnmanagedEntity
  _   -> UnrecognizedError status

-- | Throw TorControlError if a reply indicates failure.
throwIfNotSuccess :: Reply -> IO ()
throwIfNotSuccess reply =
  unless (isSuccess reply) . E.throwDyn . statusCodeToError . repStatus $ reply

-- | Run an IO action, throwing 'ControllerParseError' if it returns 'Nothing'.
throwParseIfNothing :: IO (Maybe a) -> IO a
throwParseIfNothing = (maybe (E.throwDyn ControllerParseError) return =<<)

-- | Is a reply successful?
isSuccess :: Reply -> Bool
isSuccess r = 200 <= repStatus r && repStatus r <= 299

--------------------------------------------------------------------------------
-- Helpers

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> ByteString
b = B.unsafePackAddress
