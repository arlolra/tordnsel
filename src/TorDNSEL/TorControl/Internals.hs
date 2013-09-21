{-# LANGUAGE ExistentialQuantification #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.TorControl.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, concurrency, extended exceptions,
--                             multi-parameter type classes, existentially
--                             quantified types, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Interfacing with Tor using the Tor control protocol, version 1. We support
-- fetching router descriptors and router status entries, including those sent
-- in asynchronous events that Tor generates when it receives new directory
-- information.
--
-- See <https://www.torproject.org/svn/trunk/doc/spec/control-spec.txt> for details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.TorControl.Internals (
  -- * Connections
    Connection(..)
  , Connection'
  , toConn'
  , ConfSetting(..)
  , withConnection
  , openConnection
  , closeConnection
  , closeConnection'
  , protocolInfo

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
  , sendCommand'

  -- ** Config variables
  , ConfVal(..)
  , SameConfVal
  , ConfVar(..)
  , getConf
  , setConf
  , resetConf
  , onCloseSetConf
  , onCloseRollback
  , setConfWithRollback
  , fetchUselessDescriptors
  , fetchDirInfoEarly
  , boolVar

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
  , startSocketReader

  -- * Data types
  , TorVersion(..)
  , parseTorVersion
  , AuthMethods(..)
  , ProtocolInfo(..)
  , parseProtocolInfo
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

  ) where

import Control.Arrow (first, second)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Concurrent.MVar
  (MVar, newMVar, newEmptyMVar, takeMVar, tryPutMVar, withMVar, modifyMVar_)
import qualified Control.Exception as E
import Control.Monad (when, unless, liftM, mzero, mplus, forever)
import Control.Monad.Error (MonadError(..))
import Control.Monad.Fix (fix)
import Control.Monad.State (StateT(StateT), get, put, lift, evalStateT)
import Control.Applicative
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (isSpace, isAlphaNum, isDigit, isAlpha, toLower)
import Data.Dynamic (Dynamic, fromDynamic)
import Data.List (find)
import qualified Data.Map as M
import Data.Maybe (fromMaybe, maybeToList, listToMaybe, isNothing, isJust)
import qualified Data.Sequence as S
import Data.Sequence ((<|), ViewR((:>)), viewr)
import Data.Time (UTCTime, TimeZone, localTimeToUTC, getCurrentTimeZone)
import Data.Typeable (Typeable)
import System.IO (Handle, hClose, hSetBuffering, BufferMode(..), hFlush)
import System.IO.Error (isEOFError)

import           Data.Conduit
import qualified Data.Conduit.Binary as CB
import qualified Data.Conduit.List as CL

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
         ProtocolInfo         -- protocol information for this connection
         (MVar [ConfSetting]) -- conf settings that should be rolled back

instance Thread Connection where
  threadId (Conn _ tid _ _) = tid

-- | A synonym for the values making up an incompletely initialized
-- 'Connection'.
type Connection' = (IOMessage -> IO (), ThreadId)

-- | Convert a 'Connection' to a 'Connection\''
toConn' :: Connection -> Connection'
toConn' (Conn tellIOManager ioManagerTid _ _) = (tellIOManager, ioManagerTid)

-- | An existential type containing a reference to a conf variable and a value
-- to which it should be rolled back when the connection is closed.
data ConfSetting = forall a b. (ConfVal b, SameConfVal a b) =>
  ConfSetting (ConfVar a b) (Maybe b)

-- | Open a connection with a handle and an optional password and pass it to an
-- 'IO' action. If an exception interrupts execution, close the connection
-- gracefully before re-throwing the exception.
withConnection :: Handle -> Maybe ByteString -> (Connection -> IO a) -> IO a
withConnection handle mbPasswd =
  bracket' (openConnection handle mbPasswd) closeConnection

-- | Open a connection with a handle and an optional password. Throw a
-- 'TorControlError' or 'IOError' if initializing the connection fails.
openConnection :: Handle -> Maybe ByteString -> IO Connection
openConnection handle mbPasswd = do
  hSetBuffering handle LineBuffering
  conn@(tellIOManager,ioManagerTid) <- startIOManager handle
  confSettings <- newMVar []

  ( do let protInfoCommand = Command (B.pack "protocolinfo") [B.pack "1"] []
       rs@(r:_) <- sendCommand' protInfoCommand False Nothing conn
       throwIfNotPositive protInfoCommand r
       protInfo <- either (protocolError protInfoCommand) return
                          (parseProtocolInfo rs)

       let conn' = Conn tellIOManager ioManagerTid protInfo confSettings
       authenticate mbPasswd conn'
       useFeature [VerboseNames] conn'
       return conn'
    ) `onException'` closeConnection' conn confSettings

-- | Close a connection gracefully, blocking the current thread until the
-- connection has terminated.
closeConnection :: Connection -> IO ()
closeConnection conn@(Conn _ _ _ confSettings) =
  closeConnection' (toConn' conn) confSettings

-- | 'closeConnection' with unpacked parameters.
closeConnection' :: Connection' -> MVar [ConfSetting] -> IO ()
closeConnection' conn@(tellIOManager,ioManagerTid) confSettingsMv =
  -- hold a lock here until the connection has terminated so onCloseSetConf
  -- blocks in other threads while we're trying to close the connection
  withMVar confSettingsMv $ \confSettings ->
    -- roll back all the registered conf settings
    foldl E.finally (return ()) (map set confSettings)
    `E.finally`
    (sendCommand' quit True Nothing conn >>= throwIfNotPositive quit . head)
    `E.finally`
    terminateThread Nothing ioManagerTid (tellIOManager CloseConnection)
  where set (ConfSetting var val) = setConf_ var val conn
        quit = Command (B.pack "quit") [] []

-- | 'ProtocolInfo' associated with a 'Connection'.
protocolInfo :: Connection -> ProtocolInfo
protocolInfo (Conn _ _ protInfo _) = protInfo

--------------------------------------------------------------------------------
-- Commands

-- | A command to send to Tor.
data Command = Command
  { -- | A command keyword.
    comKey  :: !ByteString,
    -- | Command arguments.
    comArgs :: ![ByteString],
    -- | A list of lines sent in the data section.
    comData :: ![ByteString]
  } deriving Show

-- | A reply sent by Tor in response to a command.
data Reply = Reply
  { -- | A reply code.
    repCode :: !(Char, Char, Char)
    -- | Reply text.
  , repText :: !ByteString
    -- | A list of lines from the data section.
  , repData :: ![ByteString]
  } deriving Show

-- | Authenticate with Tor. Throw a 'TorControlError' if authenticating fails
-- or an 'IOError' if reading the authentication cookie fails.
authenticate :: Maybe ByteString -> Connection -> IO ()
authenticate mbPasswd conn = do
  let methods = authMethods $ protocolInfo conn
  secret <- fmap encodeBase16 `fmap` case () of
   _| nullAuth methods                            -> return Nothing
    | hashedPasswordAuth methods, isJust mbPasswd -> return mbPasswd
    | Just cookiePath <- cookieAuth methods -> Just `fmap` B.readFile cookiePath
    | otherwise                                   -> return Nothing
  let authCommand = Command (B.pack "authenticate") (maybeToList secret) []
  sendCommand authCommand False Nothing conn
    >>= throwIfNotPositive authCommand { comArgs = [B.pack "[scrubbed]"] } . head

-- | Control protocol extensions
data Feature = ExtendedEvents -- ^ Extended event syntax
             | VerboseNames   -- ^ Identify routers by long name

-- | Enable control protocol extensions. Throw a 'TorControlError' if the reply
-- code indicates failure.
useFeature :: [Feature] -> Connection -> IO ()
useFeature features conn =
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command (B.pack "usefeature") (map renderFeature features) []
    renderFeature ExtendedEvents = B.pack "extended_events"
    renderFeature VerboseNames   = B.pack "verbose_names"

-- | Fetch the most recent descriptor for a given router. Throw a
-- 'TorControlError' if the reply code isn't 250 or parsing the descriptor
-- fails.
getDescriptor :: RouterID -> Connection -> IO Descriptor
getDescriptor rid conn = do
  (r,command) <- getDocument arg parseDescriptor conn
  either (parseError command) return r
  where arg = B.pack "desc/id/" `B.append` encodeBase16RouterID rid

-- | Fetch the most recent descriptor for every router Tor knows about. Throw a
-- 'TorControlError' if the reply code isn't 250. Also return error messages for
-- any descriptors that failed to be parsed.
getAllDescriptors :: Connection -> IO ([Descriptor], [ShowS])
getAllDescriptors conn = do
  (r,command) <- getDocument arg parseDescriptors conn
  return $ map (cat (commandFailed command)) `second` swap (partitionEither r)
  where arg = B.pack "desc/all-recent"

-- | Fetch the current status entry for a given router. Throw a
-- 'TorControlError' if the reply code isn't 250 or parsing the router status
-- entry fails.
getRouterStatus :: RouterID -> Connection -> IO RouterStatus
getRouterStatus rid conn = do
  (r,command) <- getDocument arg parseRouterStatus conn
  either (parseError command) return r
  where arg = B.pack "ns/id/" `B.append` encodeBase16RouterID rid

-- | Fetch the current status entries for every router Tor has an opinion about.
-- Throw a 'TorControlError' if the reply code isn't 250. Also return error
-- messages for any router status entries that failed to be parsed.
getNetworkStatus :: Connection -> IO ([RouterStatus], [ShowS])
getNetworkStatus conn = do
  (r,command) <- getDocument arg parseRouterStatuses conn
  return $ map (cat (commandFailed command)) `second` swap (partitionEither r)
  where arg = B.pack "ns/all"

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
    _             -> E.throwIO $ toTCError command reply
  where command = Command (B.pack "getinfo") [key] []
        maxRepLen = 64

-- | Get the current status of all open circuits. Throw a 'TorControlError' if
-- the reply code isn't 250.
getCircuitStatus :: Connection -> IO [CircuitStatus]
getCircuitStatus = getStatus (B.pack "circuit-status") parseCircuitStatus

-- | Get the current status of all open streams. Throw a 'TorControlError' if
-- the reply code isn't 250.
getStreamStatus :: Connection -> IO [StreamStatus]
getStreamStatus = getStatus (B.pack "stream-status") parseStreamStatus

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
    _                  -> E.throwIO $ toTCError command reply
  where command = Command (B.pack "getinfo") [key] []
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
      | msg:cid':_ <- B.split ' ' text, msg == B.pack "EXTENDED"
      , maybe True (== CircId cid') circuit -> return $ CircId (B.copy cid')
      | otherwise -> protocolError command $ cat "Got " (esc maxRepLen text) '.'
    _             -> E.throwIO $ toTCError command reply
  where
    command = Command (B.pack "extendcircuit") args []
    args = add purpose [cid, B.intercalate (B.pack ",") $ map encodeBase16RouterID path]
    CircId cid = fromMaybe nullCircuitID circuit
    renderPurpose CrGeneral    = B.pack "general"
    renderPurpose CrController = B.pack "controller"
    add = maybe id (\p -> (++ [B.pack "purpose=" `B.append` renderPurpose p]))
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
    command = Command (B.pack "attachstream") (add hop [sid,cid]) []
    CircId cid = fromMaybe nullCircuitID circuit
    add = maybe id (flip (++) . (:[]) . B.append (B.pack "HOP=") . B.pack . show)

-- | Change a stream's destination address and port, if specified. Throw a
-- 'TorControlError' if the reply code indicates failure.
redirectStream :: StreamID -> Address -> Maybe Port -> Connection -> IO ()
redirectStream (StrmId sid) addr port conn =
  sendCommand command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command (B.pack "redirectstream") args []
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
    command = Command (B.pack "closecircuit") (cid : flagArgs) []
    flagArgs = [flag | (p,flag) <- [(ifUnused, B.pack "IfUnused")], p flags]

-- | Send a GETCONF command with a set of config variable names, returning
-- a set of key-value pairs. Throw a 'TorControlError' if the reply code
-- indicates failure.
getConf' :: [ByteString] -> Connection' -> IO [(ByteString, Maybe ByteString)]
getConf' keys conn = do
  rs@(r:_) <- sendCommand' command False Nothing conn
  throwIfNotPositive command r
  either (protocolError command) return (mapM (parseText . repText) rs)
  where
    command = Command (B.pack "getconf") keys []
    parseText text
      | B.null eq = return (key, Nothing)
      | eq == (B.pack "=") = return (key, Just val)
      | otherwise = throwError $ cat "Malformed GETCONF reply "
                                     (esc maxTextLen text) '.'
      where (key,(eq,val)) = B.splitAt 1 `second` B.span isAlpha text
            maxTextLen = 128

-- | Send a SETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code indicates failure.
setConf' :: [(ByteString, Maybe ByteString)] -> Connection' -> IO ()
setConf' = setConf'' (B.pack "setconf")

-- | Send a RESETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code indicates failure.
resetConf' :: [(ByteString, Maybe ByteString)] -> Connection' -> IO ()
resetConf' = setConf'' (B.pack "resetconf")

-- | Send a SETCONF or RESETCONF command with a set of key-value pairs. Throw a
-- 'TorControlError' if the reply code indicates failure.
setConf''
  :: ByteString -> [(ByteString, Maybe ByteString)] -> Connection' -> IO ()
setConf'' name args conn =
  sendCommand' command False Nothing conn >>= throwIfNotPositive command . head
  where
    command = Command name (map renderArg args) []
    renderArg (key, Just val) = B.intercalate (B.pack "=") [key, val]
    renderArg (key, _)        = key

-- | Send a command using a connection, blocking the current thread until all
-- replies have been received. The optional @mbEvHandlers@ parameter specifies
-- a list of event handlers to replace the currently installed event handlers.
-- @isQuit@ specifies whether this is a QUIT command.
sendCommand
  :: Command -> Bool -> Maybe [EventHandler] -> Connection -> IO [Reply]
sendCommand command isQuit mbEvHandlers =
  sendCommand' command isQuit mbEvHandlers . toConn'

-- | 'sendCommand' with unpacked parameters.
sendCommand'
  :: Command -> Bool -> Maybe [EventHandler] -> Connection' -> IO [Reply]
sendCommand' command isQuit mbEvHandlers (tellIOManager,ioManagerTid) = do
  mv <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar mv
  withMonitor ioManagerTid (putResponse . Left) $ do
    tellIOManager $ SendCommand command isQuit mbEvHandlers (putResponse.Right)
    response <- takeMVar mv
    case response of
      Left NormalExit                               -> E.throwIO ConnectionClosed
      Left (AbnormalExit (E.fromException -> Just NonexistentThread))
                                                    -> E.throwIO ConnectionClosed
      Left (AbnormalExit e)                         -> E.throwIO e
      Right replies                                 -> return replies

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
  encodeConfVal True  = (B.pack "1")
  encodeConfVal False = (B.pack "0")

  decodeConfVal bool
    | bool == (B.pack "1") = return True
    | bool == (B.pack "0") = return False
    | otherwise = throwError $ cat "Malformed boolean conf value "
                                   (esc maxBoolLen bool) '.'
    where maxBoolLen = 32

-- | A constraint requiring 'setConf' and 'resetConf' to take the same type of
-- config value as 'getConf' returns.
class SameConfVal a b where
  -- | Convert a value returned by 'getConf' to a value suitable for 'setConf'.
  getToSet :: a -> Maybe b

instance SameConfVal a a where
  getToSet = Just

instance SameConfVal (Maybe a) a where
  getToSet = id

-- | A functional reference to a config variable.
data (ConfVal b, SameConfVal a b) => ConfVar a b
  = ConfVar { getConf_   :: Connection' -> IO a
            , setConf_
            , resetConf_ :: Maybe b -> Connection' -> IO () }

-- | Retrieve the value of a config variable, throwing a 'TorControlError'
-- if the command fails.
getConf :: (ConfVal b, SameConfVal a b) => ConfVar a b -> Connection -> IO a
getConf var = getConf_ var . toConn'

-- | Set the value of a config variable, throwing a 'TorControlError' if the
-- command fails.
setConf :: (ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Maybe b -> Connection -> IO ()
setConf var val = setConf_ var val . toConn'

-- | Reset the value of a config variable, throwing a 'TorControlError' if
-- the command fails.
resetConf :: (ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Maybe b -> Connection -> IO ()
resetConf var val = resetConf_ var val . toConn'

-- | When the connection is closed, set the given conf variable to the given
-- value.
onCloseSetConf :: (ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Maybe b -> Connection -> IO ()
onCloseSetConf var val (Conn _ _ _ confSettings) =
  modifyMVar_ confSettings (return . (ConfSetting var val :))

-- | Get the current value of a conf variable, then ensure that the variable
-- will be rolled back to that value when the connection is closed. Throw a
-- 'TorControlError' if a command fails.
onCloseRollback :: (ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Connection -> IO ()
onCloseRollback var conn = do
  val <- getConf var conn
  onCloseSetConf var (getToSet val) conn

-- | Get the current value of a conf variable. If the current value is different
-- from the given value, ensure that the original value is rolled back when the
-- connection is closed, then set the variable to the given value. Throw a
-- 'TorControlError' if a command fails.
setConfWithRollback :: (Eq b, ConfVal b, SameConfVal a b) =>
  ConfVar a b -> Maybe b -> Connection -> IO ()
setConfWithRollback var newVal conn = do
  origVal <- getToSet `fmap` getConf var conn
  when (origVal /= newVal) $ do
    onCloseSetConf var origVal conn
    setConf var newVal conn

-- | Enables fetching descriptors for non-running routers.
fetchUselessDescriptors :: ConfVar Bool Bool
fetchUselessDescriptors = boolVar (B.pack "fetchuselessdescriptors")

-- | Enables fetching directory info on the mirror schedule, preferably from
-- authorities.
fetchDirInfoEarly :: ConfVar Bool Bool
fetchDirInfoEarly = boolVar (B.pack "fetchdirinfoearly")

-- | Given the name of a boolean conf variable, return the corresponding
-- 'ConfVar'.
boolVar :: ByteString -> ConfVar Bool Bool
boolVar var = ConfVar getc (setc setConf') (setc resetConf') where
  getc conn = do
    (key,val):_ <- getConf' [var] conn
    case fmap decodeConfVal val of
      Nothing       -> psErr $ cat "Unexpected empty value for \"" var "\"."
      Just (Left e) -> psErr $ cat "Failed parsing value for \"" var "\": " e
      Just (Right val')
        | B.map toLower key /= var -> psErr $ cat "Received conf value "
            (esc maxVarLen key) ", expecting \"" var "\"."
        | otherwise                -> return val'
  setc f val = f [(var, fmap encodeConfVal val)]
  psErr = E.throwIO . ParseError
  maxVarLen = 64

--------------------------------------------------------------------------------
-- Asynchronous events

-- | An asynchronous event handler.
data EventHandler = EventHandler
  { evCode    :: !ByteString         -- ^ The event code.
  , evHandler :: !([Reply] -> IO ()) -- ^ The event handler.
  }

-- | Register a set of handlers for asynchronous events. This deregisters any
-- previously registered event handlers for this connection. Throw a
-- 'TorControlError' if the reply code indicates failure.
registerEventHandlers :: [EventHandler] -> Connection -> IO ()
registerEventHandlers handlers conn =
  sendCommand command False (Just handlers) conn
    >>= throwIfNotPositive command . head
  where command = Command (B.pack "setevents") (map evCode handlers) []

-- | Create an event handler for new router descriptor events.
newDescriptorsEvent ::
  ([TorControlError] -> [Descriptor] -> IO ()) -> Connection -> EventHandler
newDescriptorsEvent handler conn = EventHandler (B.pack "NEWDESC") handleNewDesc
  where
    safeGetDescriptor rid = Right `fmap` getDescriptor rid conn
      `E.catch` \(e :: TorControlError) -> return (Left e)
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
networkStatusEvent handler = EventHandler (B.pack "NS") handleNS
  where
    handleNS (Reply _ _ doc@(_:_):_) = handler (map ParseError es) rs
      where (es,rs) = partitionEither . parseRouterStatuses $ parseDocument doc
    handleNS _ = return ()

-- | Create an event handler for stream status change events.
streamEvent :: (Either TorControlError StreamStatus -> IO ()) -> EventHandler
streamEvent = lineEvent (B.pack "STREAM") parseStreamStatus

-- | Create an event handler for circuit status change events.
circuitEvent :: (Either TorControlError CircuitStatus -> IO ()) -> EventHandler
circuitEvent = lineEvent (B.pack "CIRC") parseCircuitStatus

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
addressMapEvent handler = EventHandler (B.pack "ADDRMAP") handleAddrMap
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
-- the returned 'Connection\'' and send the appropriate command to Tor. When we
-- receive replies from Tor, we pass them in a message to the thread that
-- requested the corresponding command. Asynchronous event handlers are
-- maintained as local state, invoked as necessary for incoming events.
startIOManager :: Handle -> IO Connection'
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
        Exit tid _
          | tid == evHandlerTid s -> do
              newEvHandlerTid <- startEventHandler eventChan
              loop s { evHandlerTid = newEvHandlerTid }

        Exit _ NormalExit         -> loop s

        Exit tid (AbnormalExit (E.fromException -> Just e))
          | tid == socketReaderTid
          , isEOFError e
          , quitSent s
          , S.null (responds s)   -> kill $ evHandlerTid s

        Exit _ reason             -> exit reason

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

  return (writeChan ioChan, ioManagerTid)
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

    kill tid = terminateThread Nothing tid . throwTo tid $
                exitReason E.ThreadKilled

    renderCommand (Command key args []) =
      B.intercalate (B.pack " ") (key : args) `B.append` B.pack "\r\n"
    renderCommand c@(Command _ _ data') =
      B.cons '+' (renderCommand c { comData = [] }) `B.append` renderData data'

    renderData =
      B.concat . foldr (\line xs -> line : B.pack "\r\n" : xs) [B.pack ".\r\n"]

    eventCode = B.takeWhile (/= ' ') . repText

-- | Start a thread that reads replies from @handle@ and passes them to
-- @sendRepliesToIOManager@, linking it to the calling thread.
startSocketReader :: Handle -> ([Reply] -> IO ()) -> IO ThreadId
startSocketReader handle sendRepliesToIOManager =
  forkLinkIO $ CB.sourceHandle handle $=
               repliesC               $$
               CL.mapM_ sendRepliesToIOManager

-- | Conduit taking lines to 'Reply' blocks.
replyC :: Conduit B.ByteString IO [Reply]
replyC =
    line0 []
  where

    line0 acc = await >>= return () `maybe` \line -> do
      let (code, (typ, text)) = B.splitAt 1 `second` B.splitAt 3 line
      code' <- either (monadThrow . ProtocolError) return $
                      parseReplyCode code
      case () of
        _ | typ == B.pack "-" -> line0 (Reply code' text [] : acc)
          | typ == B.pack "+" -> line0 . (: acc) . Reply code' text =<< rest []
          | typ == B.pack " " -> do
              yield $ reverse (Reply code' text [] : acc)
              line0 []
          | otherwise -> monadThrow $ ProtocolError $
                            cat "Malformed reply line type " (esc 1 typ) '.'

    rest acc =
      await >>= \mline -> case mline of
          Nothing                        -> return $ reverse acc
          Just line | B.null line        -> rest acc
                    | line == B.pack "." -> return $ reverse (line:acc)
                    | otherwise          -> rest (line:acc)

-- | Conduit taking raw 'ByteString' to 'Reply' blocks.
repliesC :: Conduit B.ByteString IO [Reply]
repliesC =
    CB.lines =$= CL.map strip =$= replyC
  where
    strip bs = case unsnoc bs of
        Just (bs', '\r') -> bs'
        _                -> bs

--------------------------------------------------------------------------------
-- Data types

-- | A new-style (since 0.1.0) Tor version number.
data TorVersion
  = TorVersion Integer    -- major
               Integer    -- minor
               Integer    -- micro
               Integer    -- patch level
               ByteString -- status tag
  deriving (Eq, Ord)

instance Show TorVersion where
  showsPrec _ (TorVersion major minor micro patchLevel statusTag)
    | B.null statusTag = prefix
    | otherwise        = cat prefix '-' statusTag
    where prefix = cat major '.' minor '.' micro '.' patchLevel

-- | Parse a new-style (since 0.1.0) Tor version number. 'throwError' in the
-- monad if parsing fails.
parseTorVersion :: MonadError ShowS m => ByteString -> m TorVersion
parseTorVersion bs
  | Just v <- evalStateT version bs = return v
  | otherwise = throwError $ cat "Malformed Tor version " (esc maxVerLen bs) '.'
  where
    version :: StateT ByteString Maybe TorVersion
    version = do
      major <- int; dot
      minor <- int; dot
      micro <- int
      patchLevel <- (dot >> int) `mplus` return 0
      statusTag <- (hyphen >> get) `mplus` (eof >> return B.empty)
      return $! TorVersion major minor micro patchLevel statusTag

    int = StateT (maybe mzero return . B.readInteger)

    (dot,hyphen) = (str (B.pack "."), str (B.pack "-"))

    str x = do
      (x',rest) <- B.splitAt (B.length x) `fmap` get
      if x == x' then put rest
                 else lift mzero

    eof = get >>= flip unless (lift mzero) . B.null

    maxVerLen = 32

-- | Authentication methods accepted by Tor.
data AuthMethods = AuthMethods
  { nullAuth                     -- ^ No authentication is required
  , hashedPasswordAuth :: Bool   -- ^ The original password must be supplied
  , cookieAuth :: Maybe FilePath -- ^ The contents of a cookie must be supplied
  } deriving Show

-- | Control protocol information for a connection.
data ProtocolInfo = ProtocolInfo
  { torVersion  :: TorVersion
  , authMethods :: AuthMethods }
  deriving Show

-- | Parse a response to a PROTOCOLINFO command. 'throwError' in the monad if
-- parsing fails.
parseProtocolInfo :: MonadError ShowS m => [Reply] -> m ProtocolInfo
parseProtocolInfo [] = throwError ("Missing PROTOCOLINFO reply." ++)
parseProtocolInfo (Reply _ text _:rs)
  | not $ B.isPrefixOf (B.pack "PROTOCOLINFO") text
  = throwError ("Malformed PROTOCOLINFO reply." ++)
  | B.drop 13 text /= (B.pack "1")
  = throwError ("Unsupported PROTOCOLINFO version." ++)
  | otherwise = do
      authLine <- findPrefix (B.pack "AUTH METHODS=")
      let (methods,restAuth) = B.split ',' `first` B.span (/= ' ') authLine
      cookiePath <- if (B.pack " COOKIEFILE=") `B.isPrefixOf` restAuth
        then (Just . fst) `liftM` parseQuotedString (B.drop 12 restAuth)
        else return Nothing
      versionLine <- findPrefix (B.pack "VERSION Tor=")
      version <- parseTorVersion . fst =<< parseQuotedString versionLine
      return $! ProtocolInfo version AuthMethods
        { nullAuth           = B.pack "NULL" `elem` methods
        , hashedPasswordAuth = B.pack "HASHEDPASSWORD" `elem` methods
        , cookieAuth         = B.unpack `liftM` cookiePath }
  where
    findPrefix prefix
      | Just r <- find (B.isPrefixOf prefix . repText) rs
      = return . B.drop (B.length prefix) . repText $ r
      | otherwise = throwError $ cat "Missing " (B.takeWhile (/= ' ') prefix)
                                     " line."

-- | A circuit identifier.
newtype CircuitID = CircId ByteString
  deriving (Eq, Ord)

instance Show CircuitID where
  showsPrec _ (CircId cid) = cat "(CID " cid ')'

-- | A special 'CircuitID' of "0".
nullCircuitID :: CircuitID
nullCircuitID = CircId (B.pack "0")

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
  | bs == (B.pack "LAUNCHED") = return CrLaunched
  | bs == (B.pack "BUILT")    = return CrBuilt
  | bs == (B.pack "EXTENDED") = return CrExtended
  | bs == (B.pack "FAILED")   = return CrFailed
  | bs == (B.pack "CLOSED")   = return CrClosed
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
  | bs == (B.pack "NEW")         = return StNew
  | bs == (B.pack "NEWRESOLVE")  = return StNewResolve
  | bs == (B.pack "REMAP")       = return StRemap
  | bs == (B.pack "SENTCONNECT") = return StSentConnect
  | bs == (B.pack "SENTRESOLVE") = return StSentResolve
  | bs == (B.pack "SUCCEEDED")   = return StSucceeded
  | bs == (B.pack "FAILED")      = return StFailed
  | bs == (B.pack "CLOSED")      = return StClosed
  | bs == (B.pack "DETACHED")    = return StDetached
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
  | fst (breakWS rest) == (B.pack "NEVER") = return $! mapping Never
  | (B.pack "\"") `B.isPrefixOf` rest, _:time:_ <- B.split '"' rest
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

instance E.Exception TorControlError

-- | Given a command, return a \"command failed\" message.
commandFailed :: Command -> ShowS
commandFailed (Command key args _) =
  cat "Command \"" key ' ' (B.unwords args) "\" failed with: "

-- | Throw a 'ProtocolError' given a command and error message.
protocolError :: Command -> ShowS -> IO a
protocolError command = E.throwIO . ProtocolError . cat (commandFailed command)

-- | Throw a 'ParseError' given a command and an error message.
parseError :: Command -> ShowS -> IO a
parseError command = E.throwIO . ParseError . cat (commandFailed command)

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
    E.throwIO $ toTCError command reply

-- | Is a reply successful?
isPositive :: ReplyCode -> Bool
isPositive ('2',_,_) = True
isPositive _         = False
