-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (imprecise exceptions)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Decoding and encoding the subset of DNS necessary for running a DNSBL
-- server.
--
-- See RFC 1035 for details.
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
  , BinaryPacket(..)

  -- * Data types
  , Message(..)
  , Question(..)
  , Answer(..)
  , DomainName(..)
  , Label(..)
  , QR(..)
  , RCode(..)
  , OpCode(..)
  , Type(..)
  , Class(..)
  ) where

import qualified Control.Exception as E
import Control.Monad (unless, replicateM, liftM2, liftM3)
import Data.Bits ((.|.), (.&.), xor, shiftL, shiftR, testBit, setBit)
import Data.List (foldl')
import qualified Data.ByteString as B
import qualified Data.ByteString.Base as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Network.Socket
  (HostAddress, Socket, SockAddr(..), sendBufTo, recvBufFrom)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr)

import Data.Binary (Binary(..), Get, Put, getWord8, putWord8, Word16, Word32)
import Data.Binary.Get
  (runGet, getWord16be, getByteString, bytesRead, lookAhead, skip)
import Data.Binary.Put (runPut, putWord16be, putByteString)

import TorDNSEL.DeepSeq
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- I/O

-- | Run a DNS server using a bound UDP socket. Pass received messages to the
-- handler and send back responses returned by the handler.
runServer :: Socket -> (Message -> IO Message) -> IO ()
{-# INLINE runServer #-} -- critical
runServer sock handler = forever $ recvMessageFrom sock >>= handleQuery
  where
    handleQuery (Just query, sockAddr@(SockAddrInet port _))
      | (fromIntegral port :: Int) >= 1024 = do
          response <- handler query
          sendMessageTo sock response sockAddr
    handleQuery _ = return ()

-- | Read a DNS message from a bound UDP socket. Return the source 'SockAddr'
-- and @'Just' _@ if parsing the message succeeded, or 'Nothing' if it failed.
recvMessageFrom :: Socket -> IO (Maybe Message, SockAddr)
recvMessageFrom sock = do
  (pkt,_,sockAddr) <- recvFrom sock 512
  msg <- decodeMessage $ Packet pkt
  return (msg, sockAddr)

-- | Send a DNS message to a 'SockAddr' with a UDP socket.
sendMessageTo :: Socket -> Message -> SockAddr -> IO ()
sendMessageTo sock msg sockAddr = do
  sendTo sock (unPacket $ encodeMessage msg) sockAddr
  return ()

-- | A wrapper for using 'recvBufFrom' with 'ByteString's.
recvFrom :: Socket -> Int -> IO (ByteString, Int, SockAddr)
recvFrom sock i = do
  (bs, (l, sockAddr)) <- B.createAndTrim' i $ \p -> do
    r@(l,_) <- recvBufFrom sock p i
    return (0, l, r)
  return (bs, l, sockAddr)

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
encodeMessage = Packet . B.concat . L.toChunks . runPut . putPacket

-- | Decode a DNS message strictly, returning @'Just' _@ if parsing succeeded.
decodeMessage :: Packet -> IO (Maybe Message)
decodeMessage pkt = do
  r <- E.try (E.evaluate $!! unsafeDecodeMessage pkt)
  return $ either (const Nothing) Just r

-- | Lazily decode a DNS message. If parsing fails, the result will contain an
-- exceptional value at some level.
unsafeDecodeMessage :: Packet -> Message
unsafeDecodeMessage pkt = runGet (getPacket pkt) (L.fromChunks [unPacket pkt])

-- | Binary serialization and deserialization of a packet. The entire packet is
-- available as context for deserialization.
class BinaryPacket a where
  getPacket :: Packet -> Get a
  putPacket :: a -> Put

--------------------------------------------------------------------------------
-- Data types

-- | A DNS message containing the header, question, and possibly answers.
data Message = Message
  { -- | A message identifier set by the originator.
    msgID       :: {-# UNPACK #-} !Word16,
    -- | Is this message a query or a response?
    msgQR       :: {-# UNPACK #-} !QR,
    -- | The kind of query in this message.
    msgOpCode   :: {-# UNPACK #-} !OpCode,
    -- | Is the name server an authority for this domain name?
    msgAA       :: {-# UNPACK #-} !Bool,
    -- | Is this message truncated?
    msgTC       :: {-# UNPACK #-} !Bool,
    -- | Does the originator desire the query to be pursued recursively?
    msgRD       :: {-# UNPACK #-} !Bool,
    -- | Does the name server support recursive queries?
    msgRA       :: {-# UNPACK #-} !Bool,
    -- | Response code set by the name server.
    msgRCode    :: {-# UNPACK #-} !RCode,
    -- | The first question set by the originator.
    msgQuestion :: {-# UNPACK #-} !Question,
    -- | Answers to the question set by the name server.
    msgAnswers  :: {-# UNPACK #-} ![Answer] }
  deriving (Eq, Show)

instance DeepSeq Message where
  deepSeq (Message a b c d e f g h i j) =
    deepSeq a . deepSeq b . deepSeq c . deepSeq d . deepSeq e .
      deepSeq f . deepSeq g . deepSeq h . deepSeq i $ deepSeq j

instance BinaryPacket Message where
  getPacket pkt = do
    i <- get
    flags <- getWord16be
    let [qr,aa,tc,rd,ra] = map (testBit flags) [15,10,9,8,7]
        qr' = if qr then Response else Query
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
    0 <- return $ flags `shiftR` 4 .&. 7
    qdCount <- getWord16be
    anCount <- getWord16be
    -- parsing fails if nscount or arcount are non-zero
    [0,0] <- replicateM 2 getWord16be
    question:_ <- replicateM (fromIntegral qdCount) (getPacket pkt)
    answers    <- replicateM (fromIntegral anCount) (getPacket pkt)
    return $! Message i qr' opCode aa tc rd ra rCode question answers

  putPacket (Message i qr opCode aa tc rd ra rCode question answers) = do
    put i
    putWord16be $ flags (opCode' .|. rCode')
    putWord16be 1
    putWord16be . fromIntegral . length $ answers
    replicateM 2 (putWord16be 0)
    putPacket question
    mapM_ putPacket answers
    where
      flags = foldl' (.) id [flip setBit bit | (flag,bit) <- bitFlags, flag]
      bitFlags = [qr == Response,aa,tc,rd,ra] `zip` [15,10,9,8,7]
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
    qName  :: {-# UNPACK #-} !DomainName,
    -- | The type of this question. We only support 'A'.
    qType  :: {-# UNPACK #-} !Type,
    -- | The class of this question. We only support 'IN'.
    qClass :: {-# UNPACK #-} !Class }
  deriving (Eq, Show)

instance DeepSeq Question where
  deepSeq (Question a b c) = deepSeq a . deepSeq b $ deepSeq c

instance BinaryPacket Question where
  getPacket pkt = liftM3 Question (getPacket pkt) get get
  putPacket (Question n t c) = putPacket n >> put t >> put c

-- | An answer resource record of type A and class IN.
-- DNSBLs should only send this kind of answer.
data Answer = Answer
  { -- | The domain name to which this answer pertains.
    ansName  :: {-# UNPACK #-} !DomainName,
    -- | A time interval, in seconds, that the answer may be cached.
    ansTTL   :: {-# UNPACK #-} !Word32,
    -- | The resource data, namely an IPv4 network address.
    ansRData :: {-# UNPACK #-} !HostAddress }
  deriving (Eq, Show)

instance DeepSeq Answer where
  deepSeq (Answer a b c) =
    deepSeq a . deepSeq b $ deepSeq c

instance BinaryPacket Answer where
  getPacket pkt = do
    name <- getPacket pkt
    -- parsing fails when type isn't A or class isn't IN
    A    <- get
    IN   <- get
    ttl  <- get
    4    <- getWord16be
    Answer name ttl `fmap` get

  putPacket (Answer name ttl rData) =
    putPacket name >> put A >> put IN >> put ttl >> putWord16be 4 >> put rData

-- | A domain name.
data DomainName
  -- | A domain name. Serializes without pointers.
  = DomainName {-# UNPACK #-} ![Label]
  -- | For use in 'Answer's. Serializes to a pointer to the first question's
  -- domain name.
  | QuestionName
  deriving (Eq, Show)

instance DeepSeq DomainName where
  deepSeq (DomainName ls) = deepSeq ls
  deepSeq QuestionName = id

instance BinaryPacket DomainName where
  -- Read a DomainName as a sequence of 'Label's ending with either a null label
  -- or a pointer to a label in a prior domain name.
  getPacket (Packet pkt) =
    fmap DomainName . getLabels . fromIntegral =<< bytesRead
    where
      getLabels p = do
        len <- lookAhead getWord8
        if len == 0
          then skip 1 >> return []
          else if len .&. 0xc0 == 0xc0
            then do
              ptr <- xor 0xc000 `fmap` getWord16be
              () <- unless (ptr < p) $
                fail "invalid name pointer"
              return $! runGet (getLabels ptr)
                               (L.fromChunks [B.drop (fromIntegral ptr) pkt])
            else liftM2 (:) get (getLabels p)

  -- Write a DomainName as a null-terminated sequence of 'Label's or as a
  -- pointer to the domain name in the question section of a message.
  putPacket (DomainName labels) = mapM_ put labels >> putWord8 0
  putPacket QuestionName        = putWord16be 0xc00c

-- | A 'DomainName' is represented as a sequence of labels.
newtype Label = Label { unLabel :: ByteString }
  deriving (Eq, Show)

instance Binary Label where
  get = do
    len <- getWord8
    Label `fmap` getByteString (fromIntegral len)

  put (Label label) = do
    putWord8 . fromIntegral . B.length $ label
    putByteString label

instance DeepSeq Label where
  deepSeq (Label bs) = deepSeq bs

-- | The message type.
data QR
  = Query    -- ^ A query.
  | Response -- ^ A response.
  deriving (Eq, Show)

instance DeepSeq QR where deepSeq = seq

-- | A response code set by the name server. We send 'NoError' for positive
-- results, 'NXDomain' for negative results, 'NotImplemented' for unsupported
-- 'OpCode's, and 'ServerFailure' for domain names we don't control.
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

instance DeepSeq RCode where deepSeq = seq

-- | Specifies the kind of query in a message set by the originator.
data OpCode
  = StandardQuery       -- ^ A standard query. We only support this opcode.
  | InverseQuery        -- ^ An inverse query.
  | ServerStatusRequest -- ^ A server status request.
  deriving (Eq, Show)

instance DeepSeq OpCode where deepSeq = seq

-- | The TYPE or QTYPE values that appear in resource records or questions,
-- respectively.
data Type
  = A -- ^ An IPv4 host address. We only support this type.
  | UnsupportedType {-# UNPACK #-} !Word16 -- ^ Any other type.
  deriving (Eq, Show)

instance Binary Type where
  get = do
    t <- get
    case t of
      1 -> return A
      _ -> return $ UnsupportedType t

  put A                   = putWord16be 1
  put (UnsupportedType t) = put t

instance DeepSeq Type where
  deepSeq A = id
  deepSeq (UnsupportedType t) = deepSeq t

-- | The CLASS or QCLASS values that appear in resource records or questions,
-- respectively.
data Class
  = IN -- ^ The Internet. We only support this class.
  | UnsupportedClass {-# UNPACK #-} !Word16 -- ^ Any other class.
  deriving (Eq, Show)

instance Binary Class where
  get = do
    c <- get
    case c of
      1 -> return IN
      _ -> return $ UnsupportedClass c

  put IN                   = putWord16be 1
  put (UnsupportedClass c) = put c

instance DeepSeq Class where
  deepSeq IN = id
  deepSeq (UnsupportedClass c) = deepSeq c
