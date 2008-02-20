{-# LANGUAGE PatternGuards #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.NetworkState.Storage.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, pattern guards, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Implements a thread that manages the storage of exit test results in the
-- file system.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.NetworkState.Storage.Internals where

import Prelude hiding (log)
import Control.Arrow (second, (&&&))
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Concurrent.MVar (newEmptyMVar, tryPutMVar, takeMVar)
import qualified Control.Exception as E
import Control.Monad (liftM2)
import Control.Monad.Error (MonadError(throwError))
import Control.Monad.Fix (fix)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (toUpper, isSpace)
import Data.List (sortBy)
import Data.Map (Map)
import qualified Data.Map as M
import Data.Maybe (mapMaybe)
import Data.Time (UTCTime)
import Network.Socket (HostAddress)
import System.Directory (removeFile, renameFile)
import System.IO (Handle, openFile, hFlush, hClose, IOMode(AppendMode))
import System.IO.Error (isDoesNotExistError)
import System.Posix.Files (getFileStatus, fileSize)

import GHC.Prim (Addr#)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.Directory
import TorDNSEL.Document
import TorDNSEL.Log
import TorDNSEL.NetworkState.Types
import TorDNSEL.Util

storePath, tempStorePath, journalPath :: FilePath
storePath = "/exit-addresses" -- ^ Path to our exit addresses store.
 -- | Path to a new exit addresses store while writing to it.
tempStorePath = "/exit-addresses.tmp"
journalPath = "/exit-addresses.new" -- ^ Path to the exit addresses journal.

-- | The storage manager configuration.
data StorageConfig = StorageConfig
  { stcfStateDir :: FilePath -- ^ The path to our state directory.
  } deriving Show

-- | An internal type for messages sent to the storage manager.
data StorageMessage
  = ReadExitAddresses ([ExitAddress] -> IO ())
  | RebuildExitAddressStorage (Map RouterID Router)
  | StoreNewExitAddress ExitAddress (Map RouterID Router)
  | Reconfigure (StorageConfig -> StorageConfig) (Map RouterID Router) (IO ())
  | Terminate ExitReason

-- | A handle to the storage manager thread.
data StorageManager = StorageManager (StorageMessage -> IO ()) ThreadId

instance Thread StorageManager where
  threadId (StorageManager _ tid) = tid

-- | An internal type containing the storage manager state.
data StorageManagerState = StorageManagerState
  { storageConf :: StorageConfig
  , exitAddrLen, journalLen :: !Integer }

-- | Start the storage manager with an initial 'StorageConfig', returning a
-- handle to it. If the storage manager exits before completely starting, throw
-- its exit signal in the calling thread. Link the storage manager to the
-- calling thread.
startStorageManager :: StorageConfig -> IO StorageManager
startStorageManager initConf = do
  log Notice "Starting storage manager."
  initState <- liftM2 (StorageManagerState initConf)
    (getFileSize (stcfStateDir initConf ++ storePath))
    (getFileSize (stcfStateDir initConf ++ journalPath))

  err <- newEmptyMVar
  let putResponse = (>> return ()) . tryPutMVar err
      runStorageManager = forkLinkIO . flip fix (initState, putResponse Nothing)
  storageChan <- newChan
  storageTid <- runStorageManager $ \reset (state,signal) -> do
    let openJournal =
          openFile (stcfStateDir (storageConf state) ++ journalPath) AppendMode
    (reset =<<) . E.bracket openJournal hClose $ \journalHandle -> do
      signal
      flip fix state $ \loop s -> do
        message <- readChan storageChan
        case message of
          ReadExitAddresses respond -> do
            hClose journalHandle
            (readExitAddresses . stcfStateDir . storageConf) s >>= respond
            return (s, nullSignal)

          RebuildExitAddressStorage routers ->
            rebuildExitAddresses journalHandle routers s

          StoreNewExitAddress addr routers -> do
            len <- appendExitAddressToJournal journalHandle addr
            if isJournalTooLarge (exitAddrLen s) (journalLen s + len)
              then rebuildExitAddresses journalHandle routers s
              else loop s { journalLen = journalLen s + len }

          Reconfigure reconf routers newSignal
            | stcfStateDir newConf /= stcfStateDir (storageConf s) -> do
                hClose journalHandle
                addrLen <- replaceExitAddresses (stcfStateDir newConf) routers
                mapM_ (removeFile . (stcfStateDir (storageConf s) ++))
                      [storePath, journalPath]
                return (s { storageConf = newConf
                          , exitAddrLen = addrLen, journalLen = 0 }, newSignal)
            | otherwise -> newSignal >> loop s { storageConf = newConf }
            where newConf = reconf (storageConf s)

          Terminate reason -> do
            log Notice "Terminating storage manager."
            exit reason

  withMonitor storageTid putResponse $
    takeMVar err >>= flip whenJust E.throwIO
  return $ StorageManager (writeChan storageChan) storageTid
  where
    rebuildExitAddresses journalHandle routers s = do
      hClose journalHandle
      addrLen <- replaceExitAddresses (stcfStateDir $ storageConf s) routers
      return (s { exitAddrLen = addrLen, journalLen = 0 }, nullSignal)

    getFileSize fp =
      E.catchJust E.ioErrors
        ((fromIntegral . fileSize) `fmap` getFileStatus fp)
        (\e -> if isDoesNotExistError e then return 0 else ioError e)

    nullSignal = return ()

-- | Read all the exit address entries from our state directory. If the storage
-- manager exits before returning the entries, throw its exit signal or
-- 'NonexistentThread' in the calling thread.
readExitAddressesFromStorage :: StorageManager -> IO [ExitAddress]
readExitAddressesFromStorage (StorageManager tellStorageManager tid) =
  call (tellStorageManager . ReadExitAddresses) tid

-- | Asynchronously rebuild the exit address store using the given network
-- information.
rebuildExitAddressStorage :: Map RouterID Router -> StorageManager -> IO ()
rebuildExitAddressStorage routers (StorageManager tellStorageManager _) =
  tellStorageManager $ RebuildExitAddressStorage routers

-- | Asynchronously add an exit address entry with new information to the
-- journal, using the given network information to rebuild the store if
-- necessary.
storeNewExitAddress
  :: RouterID -> Router -> Map RouterID Router -> StorageManager -> IO ()
storeNewExitAddress rid rtr routers (StorageManager tellStorageManager _) =
  whenJust (mkExitAddress (rid, rtr)) $ \addr ->
    tellStorageManager $ StoreNewExitAddress addr routers

-- | Reconfigure the storage manager synchronously with the given function and
-- current network information. If the server exits abnormally before
-- reconfiguring itself, throw its exit signal in the calling thread.
reconfigureStorageManager
  :: (StorageConfig -> StorageConfig) -> Map RouterID Router -> StorageManager
  -> IO ()
reconfigureStorageManager reconf routers (StorageManager tellStorageManager tid)
  = sendSyncMessage (tellStorageManager . Reconfigure reconf routers) tid

-- | Terminate the storage manager gracefully. The optional parameter specifies
-- the amount of time in microseconds to wait for the thread to terminate. If
-- the thread hasn't terminated by the timeout, an uncatchable exit signal will
-- be sent.
terminateStorageManager :: Maybe Int -> StorageManager -> IO ()
terminateStorageManager mbWait (StorageManager tellStorageManager tid) =
  terminateThread mbWait tid (tellStorageManager $ Terminate Nothing)

-- | An exit address entry stored in our state directory. The design here is the
-- same as Tor uses for storing router descriptors.
data ExitAddress = ExitAddress
  { -- | The identity of the exit node we tested through.
    eaRouterID   :: {-# UNPACK #-} !RouterID,
    -- | The current descriptor published time when the test was initiated. We
    -- don't perform another test until a newer descriptor arrives.
    eaPublished  :: {-# UNPACK #-} !UTCTime,
    -- | When we last received a network status update for this router. This
    -- helps us decide when to discard a router.
    eaLastStatus :: {-# UNPACK #-} !UTCTime,
    -- | A map from exit address to when the address was last seen.
    eaAddresses  :: {-# UNPACK #-} !(Map HostAddress UTCTime)
  } deriving Eq

instance Show ExitAddress where
  showsPrec _ = cat . renderExitAddress

-- | Exit test results are represented using the same document meta-format Tor
-- uses for router descriptors and network status documents.
renderExitAddress :: ExitAddress -> B.ByteString
renderExitAddress x = B.unlines $
  [ b 9 "ExitNode "# `B.append` renderID (eaRouterID x)
  , b 10 "Published "# `B.append` renderTime (eaPublished x)
  , b 11 "LastStatus "# `B.append` renderTime (eaLastStatus x) ] ++
  (map renderTest . sortBy (compare `on` snd) . M.assocs . eaAddresses $ x)
  where
    renderID = B.map toUpper . encodeBase16RouterID
    renderTest (addr,time) =
      B.unwords [b 11 "ExitAddress"#, B.pack $ inet_htoa addr, renderTime time]
    renderTime = B.pack . take 19 . show

-- | Parse a single exit address entry. Return the result or 'throwError' in the
-- monad if parsing fails.
parseExitAddress :: MonadError ShowS m => Document -> m ExitAddress
parseExitAddress items =
  prependError ("Failed parsing exit address entry: " ++) $ do
    rid        <- decodeBase16RouterID =<< findArg (b 8  "ExitNode"#) items
    published  <- parseUTCTime         =<< findArg (b 9  "Published"#) items
    lastStatus <- parseUTCTime         =<< findArg (b 10 "LastStatus"#) items
    addrs <- mapM parseAddr . filter ((b 11 "ExitAddress"# ==) . iKey) $ items
    return $! ExitAddress rid published lastStatus (M.fromList addrs)
  where
    parseAddr Item { iArg = Just line } =
      let (addr,testTime) = B.dropWhile isSpace `second` B.break isSpace line
      in prependError ("Failed parsing exit address item: " ++)
                      (liftM2 (,) (inet_atoh addr) (parseUTCTime testTime))
    parseAddr _ = throwError ("Failed parsing exit address item." ++)

-- | On startup, read the exit test results from the state directory. Return the
-- results in ascending order of their fingerprints.
readExitAddresses :: FilePath -> IO [ExitAddress]
readExitAddresses stateDir =
  M.elems `fmap` liftM2 (M.unionWith merge)
                        (M.fromListWith merge `fmap` parseFile journalPath)
                        (M.fromDistinctAscList `fmap` parseFile storePath)
  where
    merge new old = new { eaAddresses = (M.union `on` eaAddresses) new old }
    parseFile fp = do
      let path = stateDir ++ fp
      file <- E.catchJust E.ioErrors
        (B.readFile path)
        (\e -> if isDoesNotExistError e then return B.empty else ioError e)
      return . map (eaRouterID &&& id) . filterRight .
        parseSubDocs (b 8 "ExitNode"#) parseExitAddress . parseDocument .
        B.lines $ file

-- | On startup, and when the journal becomes too large, replace the
-- exit-addresses file with our most current test results and clear the journal.
-- Return the new exit-addresses file's size in bytes.
replaceExitAddresses :: FilePath -> Map RouterID Router -> IO Integer
replaceExitAddresses stateDir routers = do
  L.writeFile (stateDir ++ tempStorePath) (L.fromChunks $ addrs routers)
  renameFile (stateDir ++ tempStorePath) (stateDir ++ storePath)
  writeFile (stateDir ++ journalPath) ""
  (toInteger . fileSize) `fmap` getFileStatus (stateDir ++ storePath)
  where addrs = mapMaybe (fmap renderExitAddress . mkExitAddress) . M.toList

-- | Return an exit address entry if we have enough information to create one.
mkExitAddress :: (RouterID, Router) -> Maybe ExitAddress
mkExitAddress (rid,r) = do
  t <- rtrTestResults r
  return $! ExitAddress rid (tstPublished t) (rtrLastStatus r) (tstAddresses t)

-- | Add an exit address entry to the journal. Return the entry's length in
-- bytes.
appendExitAddressToJournal :: Handle -> ExitAddress -> IO Integer
appendExitAddressToJournal journal addr = do
  B.hPut journal bs
  hFlush journal
  return $! toInteger . B.length $ bs
  where bs = renderExitAddress addr

-- | Is the exit address journal large enough that it should be cleared?
isJournalTooLarge :: Integer -> Integer -> Bool
isJournalTooLarge addrSize journalSize
  | addrSize > 65536 = journalSize > addrSize
  | otherwise        = journalSize > 65536

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
