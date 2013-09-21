{-# OPTIONS_GHC -fno-warn-unused-imports #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (imprecise exceptions, pattern guards)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Decoding and encoding the subset of DNS necessary for running a DNSBL
-- server.
--
-- See RFC 1035 and RFC 2308 for details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.DNS.Internals (
  -- * I\/O
    runServer
  , recvMessageFrom
  , sendMessageTo
  , recvFrom
  , sendTo

  -- * Serialization
  , Packet(..)
  , encodeMessage
  , decodeMessage
  , unsafeDecodeMessage
  , PutState(..)
  , initialPutState
  , PutMessage
  , runPutMessage
  , incrOffset
  , BinaryPacket(..)

  -- ** Name compression
  , Offset
  , TargetMap(..)
  , emptyTargetMap
  , compressName
  , compressNameStatefully

  -- * Data types
  , Message(..)
  , Question(..)
  , ResourceRecord(..)
  , DomainName(..)
  , Label(..)
  , RCode(..)
  , OpCode(..)
  , Type(..)
  , Class(..)
  ) where

import qualified Control.Exception as E
import Control.Monad (when, unless, replicateM, liftM2, liftM3, forM, forever)
import qualified Control.Monad.State as S
import Control.Monad.Trans (lift)
import Control.DeepSeq
import Data.Bits ((.|.), (.&.), xor, shiftL, shiftR, testBit, setBit)
import Data.List (foldl')
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import qualified Data.Map as M
import Data.Map (Map)
import Network.Socket
  (HostAddress, Socket, SockAddr(..), sendBufTo, recvBufFrom)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr)

import Data.Binary (Binary(..), Get, getWord8, putWord8, Word16, Word32)
import Data.Binary.Get
  (runGet, getWord16be, getByteString, bytesRead, lookAhead, skip, isEmpty)
import Data.Binary.Put (runPut, putWord16be, putByteString, PutM)

import TorDNSEL.Util

--------------------------------------------------------------------------------
-- I/O

-- | Run a DNS server using a bound UDP socket. Pass received messages to the
-- handler and send back responses returned by the handler.
runServer
  :: Socket -> (Int -> Int -> IO ()) -> (Message -> IO (Maybe Message)) -> IO ()
{-# INLINE runServer #-} -- critical
runServer sock stats handler = forever $ do
  (msg,inBytes,addr) <- recvMessageFrom sock
  outBytes <- handleQuery msg addr
  stats inBytes outBytes
  where
    handleQuery (Just query) sockAddr@(SockAddrInet port _)
      | (fromIntegral port :: Int) >= 1024 = do
          response <- handler query
          case response of
            Just r  -> sendMessageTo sock r sockAddr
            Nothing -> return 0
    handleQuery _ _ = return 0

-- | Read a DNS message from a bound UDP socket. Return the source 'SockAddr',
-- the number of bytes read, and @'Just' msg@ if parsing the message succeeded.
recvMessageFrom :: Socket -> IO (Maybe Message, Int, SockAddr)
recvMessageFrom sock = do
  (pkt,sockAddr) <- recvFrom sock 512
  msg <- decodeMessage $ Packet pkt
  return (msg, B.length pkt, sockAddr)

{-
-- avoids an extra memcpy
recvMessageFrom sock = do
  fp <- B.mallocByteString 512
  withForeignPtr fp $ \p -> do
    (l,addr) <- recvBufFrom sock p 512
    E.assert (l <= 512) $ do
      msg <- decodeMessage . Packet $ B.PS fp 0 l
      return (msg, l, addr)
-}

-- | Send a DNS message to a 'SockAddr' with a UDP socket. If the encoded
-- message is larger than 512 bytes and is a response, remove any resource
-- records it contains and change its 'RCode' to 'ServerFailure'. If it's
-- a query, drop it silently.
sendMessageTo :: Socket -> Message -> SockAddr -> IO Int
sendMessageTo sock msg sockAddr
  |              B.length datagram      <= 512 = sendBS datagram
  | msgQR msg && B.length truncatedResp <= 512 = sendBS truncatedResp
  | otherwise                                  = return 0
  where
    datagram      = toBS msg
    truncatedResp = toBS msg { msgRCode = ServerFailure, msgAnswers = []
                             , msgAuthority = [], msgAdditional = [] }
    sendBS bs = sendTo sock bs sockAddr >> return (B.length bs)
    toBS = unPacket . encodeMessage

-- | A wrapper for using 'recvBufFrom' with 'ByteString's.
recvFrom :: Socket -> Int -> IO (ByteString, SockAddr)
recvFrom sock i = do
  (bs, sockAddr) <- B.createAndTrim' i $ \p -> do
    (l,addr) <- recvBufFrom sock p i
    return (0, l, addr)
  return (bs, sockAddr)

-- | A wrapper for using 'sendBufTo' with 'ByteString's.
sendTo :: Socket -> ByteString -> SockAddr -> IO Int
sendTo _    (B.PS _  _ 0) _        = return 0
sendTo sock (B.PS ps s l) sockAddr =
  withForeignPtr ps $ \p -> sendBufTo sock (p `plusPtr` s) l sockAddr

--------------------------------------------------------------------------------
-- Serialization

-- | An encoded DNS message.
newtype Packet = Packet { unPacket :: ByteString }
  deriving (Eq, Show)

-- | Encode a DNS message.
encodeMessage :: Message -> Packet
encodeMessage = Packet . B.concat . L.toChunks . runPutMessage . putPacket

-- | Decode a DNS message strictly, returning @'Just' _@ if parsing succeeded.
--
-- XXX We just fight lazy decoding here -- we should replace `binary` with
-- `cereal`. ( See `Socks`. )
decodeMessage :: Packet -> IO (Maybe Message)
decodeMessage pkt =
  ( E.evaluate $ Just $!! unsafeDecodeMessage pkt )
    `E.catch` \(E.ErrorCall _) -> return Nothing

-- | Lazily decode a DNS message. If parsing fails, the result will contain an
-- exceptional value at some level.
unsafeDecodeMessage :: Packet -> Message
unsafeDecodeMessage pkt = runGet (getPacket pkt) (L.fromChunks [unPacket pkt])

-- | A value representing the current name compression targets and current
-- offset (in bytes) into the datagram we're serializing.
data PutState = PutState
  { psTargets :: !TargetMap
  , psCurOff  :: !Offset }

-- | The initial state before we start writing a datagram.
initialPutState :: PutState
initialPutState = PutState emptyTargetMap 0

-- | The state\/writer monad we use to serialize messages.
type PutMessage = S.StateT PutState PutM ()

-- | Run an action in the serialization monad, returning a lazy 'ByteString'
-- containing the serialized datagram.
runPutMessage :: PutMessage -> L.ByteString
runPutMessage = runPut . flip S.evalStateT initialPutState

-- | Increment the current offset by @n@ bytes.
incrOffset :: Offset -> PutMessage
incrOffset n = S.modify $ \s -> s { psCurOff = psCurOff s + n }

-- | Binary serialization and deserialization of a packet. The entire packet is
-- available as context for deserialization.
class BinaryPacket a where
  -- XXX we could use a ReaderT monad here
  getPacket :: Packet -> Get a
  putPacket :: a -> PutMessage

--------------------------------------------------------------------------------
-- Name compression

-- | A byte offset into a datagram.
type Offset = Int

-- | A tree of labels used as compression targets. The top level represents
-- top-level domain names, the second level second-level and so on. Making this
-- a newtype triggers a bug in GHC 6.6.
data TargetMap = TargetMap !(Map Label (Offset, TargetMap))
  deriving Show

-- | The empty target map.
emptyTargetMap :: TargetMap
emptyTargetMap = TargetMap M.empty

-- | Given the current offset into a datagram, compress a domain name. Return
-- the compressed name and the updated map of compression targets.
compressName :: Offset -> DomainName -> TargetMap -> (ByteString, TargetMap)
compressName initOff (DomainName labels) = compress Nothing (reverse labels)
  where
    compress off lls@(l:ls) targets
      | Just (off', subTargets) <- lookupZone l targets
      = let (compressedName, subTargets') = compress (Just off') ls subTargets
        in (compressedName, insertZone l (off', subTargets') targets)
      | otherwise
      = let offs = tail $ scanr (\(Label x) a -> a + 1 + B.length x) initOff lls
        in (encodeName (reverse lls) off, insertZones (lls `zip` offs) targets)
    compress off [] targets
      = (encodeOffset off, targets)

    insertZones ((l,off):ls) targets
      = insertZone l (off, insertZones ls emptyTargetMap) targets
    insertZones [] targets = targets

    encodeName ls off = B.concat . L.toChunks . runPut $
      mapM_ put ls >> putByteString (encodeOffset off)

    encodeOffset Nothing    = B.singleton 0
    encodeOffset (Just off) = B.pack . map fromIntegral $ [ptr `shiftR` 8, ptr]
      where ptr = off .|. 0xc000

    lookupZone k (TargetMap targets) = k `M.lookup` targets

    insertZone k v (TargetMap targets) = TargetMap (M.insert k v targets)

-- | Compress a domain name, updating the compression target and current
-- offset state. Return the compressed name.
compressNameStatefully :: DomainName -> S.StateT PutState PutM ByteString
compressNameStatefully name = do
  s <- S.get
  let (name', targets) = compressName (psCurOff s) name (psTargets s)
  S.put $ PutState targets (psCurOff s + B.length name')
  return name'

--------------------------------------------------------------------------------
-- Data types

-- | A DNS message containing the header, question, and possibly answers.
data Message = Message
  { -- | A message identifier set by the originator.
    msgID         :: !Word16,
    -- | Is this message a response?
    msgQR         :: !Bool,
    -- | The kind of query in this message.
    msgOpCode     :: !OpCode,
    -- | Is the name server an authority for this domain name?
    msgAA         :: !Bool,
    -- | Is this a truncated response?
    msgTC         :: !Bool,
    -- | Does the originator desire the query to be pursued recursively?
    msgRD         :: !Bool,
    -- | Does the name server support recursive queries?
    msgRA         :: !Bool,
    -- | Has the data in this response been verified by the name server?
    msgAD         :: !Bool,
    -- | Is non-verified data acceptable to the resolver sending this query?
    msgCD         :: !Bool,
    -- | Response code set by the name server.
    msgRCode      :: !RCode,
    -- | The first question set by the originator.
    msgQuestion   :: !Question,
    -- | Answers to the question set by the name server.
    msgAnswers    :: ![ResourceRecord],
    -- | Authority records set by the name server.
    msgAuthority  :: ![ResourceRecord],
    -- | Additional records set by the name server.
    msgAdditional :: ![ResourceRecord] }
  deriving (Eq, Show)

instance NFData Message where
  rnf !msg = msgQuestion   msg `deepseq`
             msgAnswers    msg `deepseq`
             msgAuthority  msg `deepseq`
             msgAdditional msg `deepseq` ()

instance BinaryPacket Message where
  getPacket pkt = do
    i <- get
    flags <- getWord16be
    let [qr,aa,tc,rd,ra,ad,cd] = map (testBit flags) [15,10,9,8,7,5,4]
        opCode = case flags `shiftR` 11 .&. 0xf of
          0 -> StandardQuery
          1 -> InverseQuery
          2 -> ServerStatusRequest
          _ -> error "unknown opcode"
        rCode = case flags .&. 0xf of
          0 -> NoError
          1 -> FormatError
          2 -> ServerFailure
          3 -> NXDomain
          4 -> NotImplemented
          5 -> Refused
          _ -> error "unknown rcode"
    [qdCount,anCount,nsCount,arCount] <- replicateM 4 getWord16be
    question:_ <- replicateM (fromIntegral qdCount) (getPacket pkt)
    [answers,authority,additional] <- forM [anCount, nsCount, arCount] $ \n ->
      replicateM (fromIntegral n) (getPacket pkt)
    isEnd <- isEmpty
    () <- unless isEnd $
      fail "unexpected extra bytes after message"
    return $! Message i qr opCode aa tc rd ra ad cd rCode question answers
                      authority additional

  putPacket (Message ident qr opCode aa tc rd ra ad cd rCode question answers
                     authority additional) = do
    lift $ do
      put ident
      putWord16be $ flags (opCode' .|. rCode')
      putWord16be 1
      mapM_ (putWord16be . fromIntegral . length)
        [answers, authority, additional]
    incrOffset 12
    putPacket question
    mapM_ (mapM_ putPacket) [answers, authority, additional]
    where
      flags = foldl' (.) id [flip setBit bit | (flag,bit) <- bitFlags, flag]
      bitFlags = [qr,aa,tc,rd,ra,ad,cd] `zip` [15,10,9,8,7,5,4]
      opCode' = (`shiftL` 11) $ case opCode of
        StandardQuery       -> 0
        InverseQuery        -> 1
        ServerStatusRequest -> 2
      rCode' = case rCode of
        NoError        -> 0
        FormatError    -> 1
        ServerFailure  -> 2
        NXDomain       -> 3
        NotImplemented -> 4
        Refused        -> 5

-- | A question to the name server.
data Question = Question
  { -- | The domain name this question is about.
    qName  :: !DomainName,
    -- | The type of this question. We only support 'A' and *.
    qType  :: !Type,
    -- | The class of this question. We only support 'IN'.
    qClass :: !Class }
  deriving (Eq, Show)

instance NFData Question where
  rnf !q = rnf (qName q)

instance BinaryPacket Question where
  getPacket pkt = liftM3 Question (getPacket pkt) get get

  putPacket (Question name qsType qsClass) = do
    putPacket name
    lift $ do
      put qsType
      put qsClass
    incrOffset 4

-- | A resource record.
data ResourceRecord
  -- | A record containing an IPv4 address.
  = A
    { -- | The domain name to which this record pertains.
      rrName :: !DomainName,
      -- | A time interval, in seconds, that the answer may be cached.
      rrTTL  :: !Word32,
      -- | An IPv4 address.
      aAddr  :: !HostAddress }

  -- | An authoritative name server record.
  | NS
    { -- | The domain name to which this record pertains.
      rrName  :: !DomainName,
      -- | A time interval, in seconds, that the answer may be cached.
      rrTTL   :: !Word32,
      -- | The host that should be authoritative for this zone.
      nsDName :: !DomainName }

  -- | A start of zone of authority record.
  | SOA
    { -- | The domain name to which this record pertains.
      rrName     :: !DomainName,
      -- | A time interval, in seconds, that the answer may be cached.
      rrTTL      :: !Word32,
      -- | The name server that was the original source of data for this zone.
      soaMName   :: !DomainName,
      -- | A name specifying the email address of the person responsible for
      -- this zone.
      soaRName   :: !DomainName,
      -- | The version number of the original copy of this zone.
      soaSerial  :: !Word32,
      -- | The number of seconds before the zone should be refreshed.
      soaRefresh :: !Word32,
      -- | The number of seconds before a failed refresh should be retried.
      soaRetry   :: !Word32,
      -- | The number of seconds that can elapse before the zone is no longer
      -- authoritative.
      soaExpire  :: !Word32,
      -- | The default TTL of records that do not contain a TTL, and the TTL of
      -- negative responses.
      soaMinimum :: !Word32 }

  -- | An unsupported record.
  | UnsupportedResourceRecord
    { -- | The domain name to which this record pertains.
      rrName  :: !DomainName,
      -- | A time interval, in seconds, that the answer may be cached.
      rrTTL   :: !Word32,
      -- | The 'Type' of this record.
      rrType  :: !Type,
      -- | The 'Class' of this record.
      rrClass :: !Class,
      -- | An opaque 'ByteString' containing the resource data.
      rrData  :: !ByteString }
  deriving (Eq, Show)

instance NFData ResourceRecord where
  rnf !rr = rrName rr `deepseq`
      case rr of
           A{}   -> aAddr rr `deepseq` ()
           NS{}  -> nsDName rr `deepseq` ()
           SOA{} -> soaMName rr `deepseq` soaRName rr `deepseq` ()
           _     -> ()

instance BinaryPacket ResourceRecord where
  getPacket pkt = do
    name   <- getPacket pkt
    rType  <- get
    rClass <- get
    ttl    <- get
    len    <- getWord16be
    begin  <- bytesRead
    rec <- case (rClass, rType) of
      (IN,TA)   -> A name ttl `fmap` get
      (IN,TNS)  -> NS name ttl `fmap` getPacket pkt
      (IN,TSOA) -> do
        mName <- getPacket pkt
        rName <- getPacket pkt
        [serial,refresh,retry,expire,minim] <- replicateM 5 get
        return $! SOA name ttl mName rName serial refresh retry expire minim
      _         -> do
        rData <- getByteString $ fromIntegral len
        return $! UnsupportedResourceRecord name ttl rType rClass rData
    end <- bytesRead
    if end - begin == fromIntegral len
      then return rec
      else fail "incorrect rdata length"

  putPacket (A name ttl addr) = do
    putPacket name
    lift $ put TA >> put IN >> put ttl >> putWord16be 4 >> put addr
    incrOffset 14

  putPacket (NS name ttl dName) = do
    putPacket name
    lift $ put TNS >> put IN >> put ttl
    incrOffset 10
    dName' <- compressNameStatefully dName
    lift $ do
      putWord16be . fromIntegral . B.length $ dName'
      putByteString dName'

  putPacket (SOA name ttl mName rName serial refresh retry expire minim) = do
    putPacket name
    lift $ put TSOA >> put IN >> put ttl
    incrOffset 10
    [mName',rName'] <- mapM compressNameStatefully [mName, rName]
    lift $ do
      putWord16be . fromIntegral $ B.length mName' + B.length rName' + 20
      mapM_ putByteString [mName', rName']
      mapM_ put [serial, refresh, retry, expire, minim]
    incrOffset 20

  putPacket (UnsupportedResourceRecord name ttl rType rClass rData) = do
    putPacket name
    lift $ do
      put ttl >> put rType >> put rClass
      putWord16be . fromIntegral . B.length $ rData
      putByteString rData
    incrOffset (10 + B.length rData)

-- | A domain name.
newtype DomainName = DomainName [Label]
  deriving (Eq, Show)

instance NFData DomainName where
  rnf (DomainName ls) = rnf ls

instance BinaryPacket DomainName where
  -- Read a DomainName as a sequence of 'Label's ending with either a null label
  -- or a pointer to a label in a prior domain name.
  getPacket (Packet pkt) = do
    domain <- fmap DomainName . getLabels . fromIntegral =<< bytesRead
    () <- when (domainLen domain > 255) $
      fail "domain name too long"
    return domain
    where
      domainLen (DomainName name) =
        1 + sum' (map ((1+) . B.length . unLabel) name)
      sum' = foldl' (+) 0

      getLabels p = do
        len <- lookAhead getWord8
        case len of
          0                        -> skip 1 >> return []
          _ | len .&. 0xc0 == 0xc0 -> do
                ptr <- xor 0xc000 `fmap` getWord16be
                () <- unless (ptr < p && ptr >= 12) $
                  fail "invalid name pointer"
                let priorLen = fromIntegral (p - ptr)
                    -- names can't overlap
                    prior = B.take priorLen . B.drop (fromIntegral ptr) $ pkt
                return $! runGet (getLabels ptr) (L.fromChunks [prior])
            | len > 63             -> fail "label too long"
            | otherwise            -> liftM2 (:) get (getLabels p)

  -- Write a DomainName as a possibly null list of 'Label's terminated by
  -- either a null label or a pointer to a label from a prior domain name.
  putPacket = (lift . putByteString =<<) . compressNameStatefully

-- | A 'DomainName' is represented as a sequence of labels.
newtype Label = Label { unLabel :: ByteString }
  deriving (Eq, Ord, Show)

instance NFData Label where

instance Binary Label where
  get = do
    len <- getWord8
    Label `fmap` getByteString (fromIntegral len)

  put (Label label) = do
    putWord8 . fromIntegral . B.length $ label
    putByteString label

-- | A response code set by the name server.
data RCode
  = NoError        -- ^ No error condition.
  | FormatError    -- ^ The name server was unable to interpret the query.
  | ServerFailure  -- ^ The name server was unable to process this query due
                   -- to a problem with the name server.
  | NXDomain       -- ^ The domain name referenced in the query does not exist.
  | NotImplemented -- ^ The name server does not support the requested
                   -- kind of query.
  | Refused        -- ^ The name server refuses to perform the specified
                   -- operation for policy reasons.
  deriving (Eq, Show)

instance NFData RCode where

-- | Specifies the kind of query in a message set by the originator.
data OpCode
  = StandardQuery       -- ^ A standard query. We only support this opcode.
  | InverseQuery        -- ^ An inverse query. (obsolete)
  | ServerStatusRequest -- ^ A server status request.
  deriving (Eq, Show)

instance NFData OpCode where

-- | The TYPE or QTYPE values that appear in resource records or questions,
-- respectively.
data Type
  = TA                      -- ^ An IPv4 host address.
  | TNS                     -- ^ An authoritative name server.
  | TSOA                    -- ^ A start of zone of authority.
  | TAny                    -- ^ A request for all records.
  | UnsupportedType !Word16 -- ^ Any other type.
  deriving (Eq, Show)

instance NFData Type where

instance Binary Type where
  get = do
    t <- get
    case t of
      1   -> return TA
      2   -> return TNS
      6   -> return TSOA
      255 -> return TAny
      _   -> return $ UnsupportedType t

  put TA                  = putWord16be 1
  put TNS                 = putWord16be 2
  put TSOA                = putWord16be 6
  put TAny                = putWord16be 255
  put (UnsupportedType t) = put t

-- | The CLASS or QCLASS values that appear in resource records or questions,
-- respectively.
data Class
  = IN                       -- ^ The Internet. We only support this class.
  | UnsupportedClass !Word16 -- ^ Any other class.
  deriving (Eq, Show)
  -- XXX support *

instance NFData Class where

instance Binary Class where
  get = do
    c <- get
    case c of
      1 -> return IN
      _ -> return $ UnsupportedClass c

  put IN                   = putWord16be 1
  put (UnsupportedClass c) = put c
