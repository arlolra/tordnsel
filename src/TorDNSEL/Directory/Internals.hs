{-# LANGUAGE PatternGuards #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Directory.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Parsing and processing router descriptors, exit policies, and router
-- status entries from the Tor directory protocol, version 2. We only
-- parse information necessary for running the exit list server.
--
-- See <http://tor.eff.org/svn/trunk/doc/spec/dir-spec.txt> for details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Directory.Internals (
  -- * Router descriptors
    Descriptor(..)
  , parseDescriptor
  , parseDescriptors

  -- * Router status entries
  , RouterStatus(..)
  , parseRouterStatus
  , parseRouterStatuses

  -- * Identity fingerprints
  , Fingerprint(..)
  , decodeBase16Fingerprint
  , decodeBase64Fingerprint
  , encodeBase16Fingerprint

  -- * Exit policies
  , ExitPolicy
  , Rule(..)
  , RuleType(..)
  , parseExitPolicy
  , exitPolicyAccepts

  -- * Document meta-format
  , Document
  , Item(..)
  , Object(..)
  , parseDocument
  , parseSubDocs

  -- * Helpers
  , b
  ) where

import Control.Monad (unless)
import Data.Char (ord, isSpace, isHexDigit, digitToInt)
import Data.List (foldl', find)
import Data.Bits ((.|.), (.&.), shiftL, shiftR)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as W
import Data.ByteString (ByteString)
import Data.Time (fromGregorian, UTCTime(..), addUTCTime)
import Network.Socket (HostAddress, PortNumber)

import GHC.Prim (Addr#)

import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Router descriptors

-- | A router descriptor.
data Descriptor = Desc
  { -- | The IPv4 address at which this router accepts connections.
    descListenAddr  :: {-# UNPACK #-} !HostAddress,
    -- | The time when this descriptor was generated.
    descPublished   :: {-# UNPACK #-} !UTCTime,
    -- | This router's identity fingerprint.
    descFingerprint :: {-# UNPACK #-} !Fingerprint,
    -- | This router's exit policy.
    descExitPolicy  :: {-# UNPACK #-} !ExitPolicy }

instance Show Descriptor where
  showsPrec _ d = shows (descFingerprint d) . (" " ++) .
    (inet_htoa (descListenAddr d) ++) . (" " ++) .
    shows (descPublished d) . ("\n" ++) .
    foldl' (.) id (map (\p -> shows p . ("\n" ++)) (descExitPolicy d))

-- | Parse a router descriptor. Returns the result or 'fail' in the monad if the
-- format is invalid.
parseDescriptor :: Monad m => Document -> m Descriptor
parseDescriptor items = do
  address    <- parseRouter           =<< findArg isRouter
  time       <- parseTime . B.take 19 =<< findArg isPublished
  fp         <- parseFingerprint      =<< findArg isFingerprint
  exitPolicy <- parseExitPolicy . filter isRule $ items
  return $! Desc address time fp exitPolicy
  where
    isRouter = (b 6 "router"# ==) . iKey
    isPublished = (b 9 "published"# ==) . iKey
    isFingerprint = (b 11 "fingerprint"# ==) . iKey
    isRule = (\k -> k == b 6 "accept"# || k == b 6 "reject"#) . iKey

    findArg p | Just item <- find p items, Just arg <- iArg item = return arg
    findArg _ = fail "parseDescriptor: item doesn't exist"

    parseRouter router = do
      _:address:_ <- return $ B.splitWith isSpace router
      inet_atoh address

    -- Parse a UTCTime in this format: "YYYY-MM-DD HH:MM:SS"
    parseTime bs = do
      [date,time]          <- return       $ B.split ' ' bs
      [year,month,day]     <- mapM readInt $ B.split '-' date
      [hour,minute,second] <- mapM readInt $ B.split ':' time
      let utcDay = fromGregorian (fromIntegral year) month day
          utcDayTime = hour * 3600 + minute * 60 + second
      return $! addUTCTime (fromIntegral utcDayTime) (UTCTime utcDay 0)

    parseFingerprint = decodeBase16Fingerprint . B.filter (/= ' ')

-- | Parse a 'Document' containing multiple router descriptors.
parseDescriptors :: Document -> [Descriptor]
parseDescriptors = parseSubDocs (b 6 "router"#) parseDescriptor

--------------------------------------------------------------------------------
-- Router status entries

-- | A router status entry.
data RouterStatus = RS
  { -- | This router's identity fingerprint.
    rsFingerprint :: {-# UNPACK #-} !Fingerprint,
    -- | Is this router running?
    rsIsRunning   :: {-# UNPACK #-} !Bool }
  deriving Show

-- | Parse a router status entry. Returns the result or 'fail' in the monad if
-- the format is invalid.
parseRouterStatus :: Monad m => Document -> m RouterStatus
parseRouterStatus items = do
  fingerprint <- parseRouter =<< findArg ((b 1 "r"# ==) . iKey)
  return $! RS fingerprint (parseStatus . findArg $ (b 1 "s"# ==) . iKey)
  where
    findArg p | Just item <- find p items, Just arg <- iArg item = return arg
    findArg _ = fail "parseRouterStatus: item doesn't exist"

    parseRouter router = do
      _:base64Fingerprint:_ <- return $ B.splitWith isSpace router
      decodeBase64Fingerprint base64Fingerprint

    parseStatus = maybe False (elem (b 7 "Running"#) . B.splitWith isSpace)

-- | Parse a 'Document' containing multiple router status entries. Such a
-- document isn't the same as a network-status document as it doesn't contain
-- a preamble or a signature.
parseRouterStatuses :: Document -> [RouterStatus]
parseRouterStatuses = parseSubDocs (b 1 "r"#) parseRouterStatus

--------------------------------------------------------------------------------
-- Identity fingerprints

-- | A fingerprint for a router's identity key.
newtype Fingerprint = FP { unFP :: ByteString }
  deriving (Eq, Ord)

instance Show Fingerprint where
  show = B.unpack . encodeBase16Fingerprint

-- | Decode a 'Fingerprint' encoded in base16. Returns the result or 'fail' in
-- the monad if the format is invalid.
decodeBase16Fingerprint :: Monad m => ByteString -> m Fingerprint
decodeBase16Fingerprint bs = do
  unless (B.length bs == 40 && B.all isHexDigit bs) $
    fail "decodeBase16Fingerprint: failed"
  return $! FP . fst . W.unfoldrN 20 toBytes . B.unpack $ bs
  where
    toBytes (x:y:ys) = Just (fromBase16 x `shiftL` 4 .|. fromBase16 y, ys)
    toBytes _        = Nothing
    fromBase16 = fromIntegral . digitToInt

-- | Decode a 'Fingerprint' encoded in base64 with trailing \'=\' signs removed.
-- Returns the result or 'fail' in the monad if the format is invalid.
decodeBase64Fingerprint :: Monad m => ByteString -> m Fingerprint
decodeBase64Fingerprint bs = do
  unless (B.length bs == 27 && B.all isBase64Char bs) $
    fail "decodeBase64Fingerprint: failed"
  return $! FP . B.init . toBytes . blocks $ bs
  where
    toBytes = W.pack . concatMap (indicesToBytes . map base64Index . B.unpack)
    blocks = takeWhile (not . B.null) . map (B.take 4) . iterate (B.drop 4)

    indicesToBytes is = map (fromIntegral . (0xff .&.) . shiftR buf) [16,8,0]
      where buf = foldl' (.|.) 0 $ zipWith shiftL is [18,12..]

    base64Index x
      | 'A' <= x, x <= 'Z' = ord x - 65
      | 'a' <= x, x <= 'z' = ord x - 71
      | '0' <= x, x <= '9' = ord x + 4
    base64Index '+' = 62
    base64Index '/' = 63
    base64Index _   = error "base64Index: invalid base64 index"

    isBase64Char x =
      'A' <= x && x <= 'Z' || 'a' <= x && x <= 'z' ||
      '0' <= x && x <= '9' || x `elem` "+/"

-- | Encode a 'Fingerprint' in base16.
encodeBase16Fingerprint :: Fingerprint -> ByteString
encodeBase16Fingerprint = encodeBase16 . unFP

--------------------------------------------------------------------------------
-- Exit policies

-- | An exit policy consisting of a sequence of rules.
type ExitPolicy = [Rule]

-- | An exit policy rule consisting of a 'RuleType' and an address\/mask and
-- port range pattern.
data Rule = Rule
  { -- | Whether an exit connection is allowed.
    ruleType      :: {-# UNPACK #-} !RuleType,
    -- | The IPv4 address part of the pattern.
    ruleAddress   :: {-# UNPACK #-} !HostAddress,
    -- | The IPv4 address mask part of the pattern.
    ruleMask      :: {-# UNPACK #-} !HostAddress,
    -- | The first port in the pattern's port range.
    ruleBeginPort :: {-# UNPACK #-} !PortNumber,
    -- | The last port in the pattern's port range.
    ruleEndPort   :: {-# UNPACK #-} !PortNumber }

instance Show Rule where
  showsPrec _ p = shows (ruleType p) . (" " ++) .
    (inet_htoa (ruleAddress p) ++) . ("/" ++) . (inet_htoa (ruleMask p) ++) .
    (":" ++) . shows (ruleBeginPort p) . ("-" ++) . shows (ruleEndPort p)

-- | Whether a rule allows an exit connection.
data RuleType
  = Accept -- ^ The rule accepts connections.
  | Reject -- ^ The rule rejects connections.
  deriving Show

-- | Parse an 'ExitPolicy' from a list of accept or reject items. Returns the
-- result or 'fail' in the monad if the format is invalid.
parseExitPolicy :: Monad m => [Item] -> m ExitPolicy
parseExitPolicy = mapM parseRule
  where

    parseRule (Item key (Just arg) _) = do
      [addrSpec,portSpec] <- return $ B.split ':' arg
      ruleType'           <- parseRuleType key
      (address,mask)      <- parseAddrSpec addrSpec
      (beginPort,endPort) <- parsePortSpec portSpec
      return $! Rule ruleType' address mask beginPort endPort
    parseRule _ = fail "parseRule: failed"

    parseRuleType key
      | key == b 6 "accept"# = return Accept
      | key == b 6 "reject"# = return Reject
      | otherwise            = fail "parseRuleType: failed"

    parseAddrSpec bs
      | bs == b 1 "*"# = return (0, 0)
      | [addr,mask] <- B.split '/' bs = do
        addr' <- inet_atoh addr
        mask' <- maybe (bitsToMask =<< readInt mask) return (inet_atoh mask)
        return (addr' .&. mask', mask')
      | otherwise = do
        addr <- inet_atoh bs
        return (addr, 0xffffffff)

    parsePortSpec bs
      | bs == b 1 "*"# = return (0, 65535)
      | Just [begin,end] <- mapM (fmap fromIntegral . readInt) (B.split '-' bs)
      = return (begin, end)
      | Just port <- fromIntegral `fmap` readInt bs = return (port, port)
      | otherwise = fail "parsePortSpec: failed"

    bitsToMask x
      | 0 <= x, x <= 32 = return $ 0xffffffff `shiftL` (32 - x)
      | otherwise       = fail "bitsToMask: failed"

-- | Return whether the exit policy allows an exit connection to the given IPv4
-- address and port. The first matching rule determines the result. If no rule
-- matches, the address\/port are accepted.
exitPolicyAccepts :: HostAddress -> PortNumber -> ExitPolicy -> Bool
exitPolicyAccepts addr port exitPolicy
  | Reject:_ <- matchingRules = False
  | otherwise                 = True
  where
    matchingRules = map ruleType . filter matches $ exitPolicy
    matches r = addr .&. ruleMask r == ruleAddress r &&
                ruleBeginPort r <= port && port <= ruleEndPort r

--------------------------------------------------------------------------------
-- Document meta-format

-- | A document consisting of a sequence of one or more items.
type Document = [Item]

-- | An item consisting of a keyword, possibly arguments, and zero or more
-- objects.
data Item = Item
  { iKey :: {-# UNPACK #-} !ByteString         -- ^ Keyword
  , iArg :: {-# UNPACK #-} !(Maybe ByteString) -- ^ Arguments
  , iObj :: {-# UNPACK #-} ![Object]           -- ^ Objects
  } deriving Show

-- | An object consisting of a keyword and a block of base64-encoded data.
data Object = Object
  { objKey  :: {-# UNPACK #-} !ByteString -- ^ Keyword
  , objData :: {-# UNPACK #-} !ByteString -- ^ Base64-encoded data
  } deriving Show

-- | Parse a 'Document' from a list of lines.
parseDocument :: [ByteString] -> Document
parseDocument []     = []
parseDocument (x:xs) = Item key arguments objects : parseDocument xs'
  where

    (key,x') = B.break isSpace . dropOpt $ x
    arguments | B.null x' = Nothing
              | otherwise = Just . B.dropWhile isSpace $ x'
    (xs',objects) = parseObjects xs
    dropOpt | b 4 "opt "# `B.isPrefixOf` x = B.drop 4
            | otherwise                    = id

    parseObjects :: [ByteString] -> ([ByteString], [Object])
    parseObjects (y:ys)
      | b 11 "-----BEGIN "# `B.isPrefixOf` y, b 5 "-----"# `B.isSuffixOf` y
      = (ys'', Object oKey (B.unlines objLines) : objects')
      where
        oKey = B.take (B.length y - 16) . B.drop 11 $ y
        endLine = b 9 "-----END "# `B.append` oKey `B.append` b 5 "-----"#
        (objLines, ys') = break (== endLine) ys
        (ys'',objects') = parseObjects . drop 1 $ ys'
    parseObjects ys = (ys, [])

-- | Break a document into sub-documents each beginning with an item that has
-- the keyword @firstKey@. Apply @parseDoc@ to each sub-document, returning the
-- parsed document in the result if @parseDoc subDocument@ matches @Just _@.
parseSubDocs :: ByteString -> (Document -> Maybe doc) -> Document -> [doc]
parseSubDocs _        _        []    = []
parseSubDocs firstKey parseDoc (x:xs)
  | Just doc <- parseDoc (x : items) = doc : docs
  | otherwise                        = docs
  where
    (items,xs') = break ((firstKey ==) . iKey) xs
    docs = parseSubDocs firstKey parseDoc xs'

--------------------------------------------------------------------------------
-- Helpers

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> ByteString
b = B.unsafePackAddress
