{-# LANGUAGE PatternGuards, TypeSynonymInstances, FlexibleContexts #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Directory.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, type synonym instances,
--                             GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Parsing and processing router descriptors, exit policies, and router
-- status entries from the Tor directory protocol, version 2. We only
-- parse information necessary for running the exit list server.
--
-- See <https://www.torproject.org/svn/trunk/doc/spec/dir-spec-v2.txt> for details.
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

  -- * Router identifiers
  , RouterID(..)
  , decodeBase16RouterID
  , decodeBase64RouterID
  , encodeBase16RouterID

  -- * Exit policies
  , ExitPolicy
  , Rule(..)
  , RuleType(..)
  , parseExitPolicy
  , exitPolicyAccepts

  -- * Shared values
  , Hash(..)
  , lookupSharedValue
  ) where

import Control.Concurrent.MVar (newMVar, withMVar)
import qualified TorDNSEL.Compat.Exception as E
import Control.Monad (when, unless, liftM)
import Control.Monad.Error (MonadError(throwError))
import Data.Char
  ( ord, isSpace, isHexDigit, digitToInt, isAscii, isAsciiUpper
  , isAsciiLower, isAlpha, isDigit )
import qualified Data.HashTable as HT
import Data.List (foldl')
import Data.Bits ((.|.), (.&.), shiftL, shiftR, complement, xor)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as W
import Data.ByteString (ByteString)
import Data.Int (Int32)
import Data.Time (UTCTime)
import Data.Time.Clock.POSIX
  (POSIXTime, utcTimeToPOSIXSeconds, posixSecondsToUTCTime)
import Network.Socket (HostAddress)
import System.IO.Unsafe (unsafePerformIO)
import System.Mem.Weak (mkWeakPtr, deRefWeak, finalize)

import TorDNSEL.Document
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Router descriptors

-- | A router descriptor.
data Descriptor = Desc
  { -- | The IPv4 address at which this router accepts connections.
    descListenAddr :: {-# UNPACK #-} !HostAddress,
    -- | The time when this descriptor was generated.
    descPublished  :: {-# UNPACK #-} !POSIXTime,
    -- | This router's identifier.
    descRouterID   :: {-# UNPACK #-} !RouterID,
    -- | This router's exit policy.
    descExitPolicy :: {-# UNPACK #-} !ExitPolicy }

instance Show Descriptor where
  showsPrec _ d = cat (descRouterID d) ' ' (inet_htoa $ descListenAddr d) ' '
    (posixSecondsToUTCTime $ descPublished d) '\n'
    (foldl' (.) id (map (\p -> shows p . ('\n' :)) (descExitPolicy d)))

-- | Parse a router descriptor. Return the result or 'throwError' in the monad
-- if the format is invalid.
parseDescriptor :: MonadError ShowS m => Document -> m Descriptor
parseDescriptor items =
  prependError ("Failed parsing router descriptor: " ++) $ do
    address    <- parseRouter    =<< findArg (B.pack "router")      items
    time       <- parsePOSIXTime =<< findArg (B.pack "published")   items
    fp         <- parseRouterID  =<< findArg (B.pack "fingerprint") items
    exitPolicy <- parseExitPolicy . filter isRule $ items
    return $! Desc address time fp exitPolicy
  where
    isRule = (\k -> k == (B.pack "accept") || k == B.pack("reject")) . iKey

    parseRouter router
      | _:address:_ <- B.splitWith isSpace router = inet_atoh address
      | otherwise = throwError $ cat "Malformed router item "
                                     (esc maxRouterLen router) '.'
      where maxRouterLen = 53

    parsePOSIXTime = liftM utcTimeToPOSIXSeconds . parseUTCTime . B.take 19

    parseRouterID = decodeBase16RouterID . B.filter (/= ' ')

-- | Parse a 'Document' containing multiple router descriptors.
parseDescriptors :: Document -> [Either ShowS Descriptor]
parseDescriptors = parseSubDocs (B.pack "router") parseDescriptor

--------------------------------------------------------------------------------
-- Router status entries

-- | A router status entry.
data RouterStatus = RS
  { -- | This router's identifier.
    rsRouterID  :: {-# UNPACK #-} !RouterID,
    -- | When this router's most recent descriptor was published.
    rsPublished :: {-# UNPACK #-} !UTCTime,
    -- | Is this router running?
    rsIsRunning :: {-# UNPACK #-} !Bool }
  deriving Show

-- | Parse a router status entry. Return the result or 'throwError' in the
-- monad if the format is invalid.
parseRouterStatus :: MonadError ShowS m => Document -> m RouterStatus
parseRouterStatus items = do
  (rid,published) <- prependError ("Failed parsing router status entry: " ++)
                                  (parseRouter =<< findArg (B.pack "r") items)
  return $! RS rid published (parseStatus $ findArg (B.pack "s") items)
  where
    parseRouter router
      | _:base64RouterID:_:date:time:_ <- B.splitWith isSpace router = do
        rid <- decodeBase64RouterID base64RouterID
        published <- parseUTCTime $ B.unwords [date, time]
        return (rid, published)
      | otherwise = throwError $ cat "Malformed status "
                                     (esc maxStatusLen router) '.'
      where maxStatusLen = 122

    parseStatus = maybe False (elem (B.pack "Running") . B.splitWith isSpace)

-- | Parse a 'Document' containing multiple router status entries. Such a
-- document isn't the same as a network-status document as it doesn't contain
-- a preamble or a signature.
parseRouterStatuses :: Document -> [Either ShowS RouterStatus]
parseRouterStatuses = parseSubDocs (B.pack "r") parseRouterStatus

--------------------------------------------------------------------------------
-- Router identifiers

-- | A digest of a router's identity key.
newtype RouterID = RtrId { unRtrId :: ByteString }
  deriving (Eq, Ord)

instance Show RouterID where
  show = B.unpack . encodeBase16RouterID

instance Hash RouterID where
  hash = foldl' (flip $ xor . chunk) 0 . split 4 . unRtrId
    where chunk x = foldl' (flip $ (.|.) . fromIntegral . W.index x) 0 [0..3]

-- | Decode a 'RouterID' encoded in base16. Return the result or 'throwError' in
-- the monad if the format is invalid.
decodeBase16RouterID :: MonadError ShowS m => ByteString -> m RouterID
decodeBase16RouterID bs = do
  unless (B.length bs == routerIDLen && B.all isHexDigit bs) $
    throwError $ cat "Failed hex-decoding router identifier "
                     (esc routerIDLen bs) '.'
  return $! RtrId . fst . W.unfoldrN 20 toBytes . B.unpack $ bs
  where
    toBytes (x:y:ys) = Just (fromBase16 x `shiftL` 4 .|. fromBase16 y, ys)
    toBytes _        = Nothing
    fromBase16 = fromIntegral . digitToInt
    routerIDLen = 40

-- | Decode a 'RouterID' encoded in base64 with trailing \'=\' signs removed.
-- Return the result or 'throwError' in the monad if the format is invalid.
decodeBase64RouterID :: MonadError ShowS m => ByteString -> m RouterID
decodeBase64RouterID bs = do
  unless (B.length bs == routerIDLen && B.all isBase64Char bs) $
    throwError $ cat "Failed base64-decoding router identifier "
                     (esc routerIDLen bs) '.'
  return $! RtrId . B.init . toBytes . split 4 $ bs
  where
    routerIDLen = 27
    toBytes = W.pack . concatMap (indicesToBytes . map base64Index . B.unpack)

    indicesToBytes is = map (fromIntegral . (0xff .&.) . shiftR buf) [16,8,0]
      where buf = foldl' (.|.) 0 $ zipWith shiftL is [18,12..]

    base64Index x
      | isAsciiUpper x = ord x - 65
      | isAsciiLower x = ord x - 71
      | isDigit x      = ord x + 4
    base64Index '+'    = 62
    base64Index '/'    = 63
    base64Index _      = error "base64Index: invalid base64 index"

    isBase64Char x = isAscii x && or [isAlpha x, isDigit x, x `elem` "+/"]

-- | Encode a 'RouterID' in base16.
encodeBase16RouterID :: RouterID -> ByteString
encodeBase16RouterID = encodeBase16 . unRtrId

--------------------------------------------------------------------------------
-- Exit policies

-- | An exit policy consisting of a sequence of rules.
type ExitPolicy = [Rule]

instance Hash ExitPolicy where
  hash = fromIntegral . foldl' (flip $ (+) . hash) 0

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
    ruleBeginPort :: {-# UNPACK #-} !Port,
    -- | The last port in the pattern's port range.
    ruleEndPort   :: {-# UNPACK #-} !Port
  } deriving (Eq, Ord)

instance Show Rule where
  showsPrec _ p = cat (ruleType p) ' ' (inet_htoa $ ruleAddress p) '/'
    (inet_htoa $ ruleMask p) ':' (ruleBeginPort p) '-' (ruleEndPort p)

instance Hash Rule where
  hash (Rule typ addr mask begin end) =
    fromIntegral . (if typ == Reject then complement else id) $
      addr + mask + fromIntegral begin `shiftL` 8 + fromIntegral end `shiftL` 16

-- | Whether a rule allows an exit connection.
data RuleType
  = Accept -- ^ The rule accepts connections.
  | Reject -- ^ The rule rejects connections.
  deriving (Show, Eq, Ord)

-- | Parse an 'ExitPolicy' from a list of accept or reject items. Return the
-- result or 'throwError' in the monad if the format is invalid.
parseExitPolicy :: MonadError ShowS m => [Item] -> m ExitPolicy
parseExitPolicy xs = do
  policy <- mapM (prependError ("Failed parsing exit rule: " ++) . parseRule) xs
  return $! lookupSharedValue policy
  where
    parseRule (Item key (Just arg) _)
      | [addrSpec,portSpec] <- B.split ':' arg = do
        ruleType' <- parseRuleType key
        (address,mask) <- prependError
          (cat "Malformed address specifier " (esc maxAddrLen addrSpec) ": ")
          (parseAddrSpec addrSpec)
        (beginPort,endPort) <- prependError
          (cat "Malformed port specifier " (esc maxPortLen portSpec) ": ")
          (parsePortSpec portSpec)
        return $! lookupSharedValue $
          Rule ruleType' address mask beginPort endPort
    parseRule (Item key arg _) =
      throwError $ cat "Malformed exit rule " (esc maxRuleTypeLen key) ' '
                       (maybe id (esc maxRuleLen) arg) '.'

    parseRuleType key
      | key == (B.pack "accept") = return Accept
      | key == (B.pack "reject") = return Reject
      | otherwise = throwError $ cat "Invalid rule type "
                                     (esc maxRuleTypeLen key) '.'

    parseAddrSpec bs
      | bs == (B.pack "*") = return (0, 0)
      | [addr,mask] <- B.split '/' bs = do
        addr' <- inet_atoh addr
        mask' <- maybe (bitsToMask =<< readInt mask) return (inet_atoh mask)
        return (addr' .&. mask', mask')
      | otherwise = do
        addr <- inet_atoh bs
        return (addr, 0xffffffff)

    parsePortSpec bs
      | bs == (B.pack "*") = return (0, 65535)
      | ports@[_,_] <- B.split '-' bs = do
        [begin,end] <- mapM parsePort ports
        when (begin > end) $
          throwError $ cat "Begin port is greater then end port."
        return (begin, end)
      | otherwise = do
        port <- parsePort bs
        return (port, port)

    bitsToMask x
      | 0 <= x, x <= 32 = return $ 0xffffffff `shiftL` (32 - x)
      | otherwise = throwError $ cat "Prefix length " x " is out of range."

    maxRuleLen = maxAddrLen + 1 + maxPortLen
    maxRuleTypeLen = 6
    maxAddrLen = 31
    maxPortLen = 11

-- | Return whether the exit policy allows an exit connection to the given IPv4
-- address and port. The first matching rule determines the result. If no rule
-- matches, the address\/port are accepted.
exitPolicyAccepts :: HostAddress -> Port -> ExitPolicy -> Bool
{-# INLINE exitPolicyAccepts #-}
exitPolicyAccepts addr port exitPolicy
  | Reject:_ <- matchingRules = False
  | otherwise                 = True
  where
    matchingRules = map ruleType . filter matches $ exitPolicy
    matches r = addr .&. ruleMask r == ruleAddress r &&
                ruleBeginPort r <= port && port <= ruleEndPort r
--------------------------------------------------------------------------------
-- Shared values

-- | A type that can be hashed for storage in a 'HashTable'.
class Hash a where
  hash :: a -> Int32 -- ^ A hash function.

-- | Look up a value in a table of shared values. If the value is present,
-- return the shared value from the table. Otherwise, insert the given value
-- into the table and return it. The idea here is to save memory by storing
-- only one copy of equivalent values. This function is only referentially
-- transparent when the 'Eq' instance implements structural equality.
lookupSharedValue :: (Hash a, Eq a) => a -> a
{-# NOINLINE lookupSharedValue #-}
lookupSharedValue = unsafePerformIO . E.block $ do
  -- These will be run only once in each specialized version of this function.
  lock <- newMVar ()
  -- A hash table containing weak pointers to shared values. When a shared value
  -- becomes unreachable, a finalizer removes it from the table.
  table <- HT.new (==) hash
  return $ \value -> unsafePerformIO . E.block . withMVar lock . const $ do
    mbValuePtr <- HT.lookup table value
    case mbValuePtr of
      Nothing -> insert table value
      Just valuePtr -> do
        mbSharedValue <- deRefWeak valuePtr
        case mbSharedValue of
          Nothing -> do
            finalize valuePtr
            insert table value
          Just sharedValue -> return sharedValue
  where
    insert table value = do
      let finalizer = HT.delete table value
      mkWeakPtr value (Just finalizer) >>= HT.insert table value
      return value
