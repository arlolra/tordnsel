{-# LANGUAGE ForeignFunctionInterface, OverlappingInstances, UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-orphans #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Util
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, bang patterns, concurrency,
--                             FFI, type synonym instances, overlapping
--                             instances, undecidable instances)
--
-- Common utility functions.
--
-----------------------------------------------------------------------------

module TorDNSEL.Util (
  -- * Parsing functions
    readInt
  , readInteger
  , inet_atoh
  , parseUTCTime
  , parseLocalTime
  , parseQuotedString
  , prependError
  , replaceError
  , handleError

  -- * Show functions
  , bshow

  -- * Strict functions
  , adjust'
  , alter'
  , update'
  , mapInsert'
  , modify'

  -- * Miscellaneous functions
  , on
  , unfoldAccumR
  , swap
  , partitionEither
  , whenJust
  , untilM
  , untilM_
  , muntil
  , inet_htoa
  , encodeBase16
  , split
  , unsnoc
  , syncExceptions
  , bracket'
  , finally'
  , bracketOnError'
  , onException'
  , exitUsage
  , trySync
  , inBoundsOf
  , htonl
  , ntohl
  , showUTCTime

  -- * Conduit utilities
  , takeC
  , frames
  , frame

  -- * Network functions
  , bindUDPSocket
  , bindListeningTCPSocket
  , bindListeningUnixDomainStreamSocket

  -- * Monads
  , MaybeT(..)

  -- * Address
  , Address(..)
  , showAddress
  , readAddress

  -- * Ports
  , Port(..)
  , parsePort

  -- * Escaped strings
  , EscapedString
  , escaped
  , unescLen
  , escape
  , showEscaped
  , esc

  -- * Constants
  , tcpProtoNum
  , udpProtoNum

  -- * Variable-parameter string concatenation
  , CatArg
  , CatType(..)
  , cat
  , HCatType
  , hCat
  ) where

import Control.Arrow ((&&&), first, second)
import Control.Applicative
import Control.Monad
import qualified Control.Exception as E
import Control.Monad.Error (Error(..), MonadError(..), MonadTrans(..), MonadIO(..))
import qualified Control.Monad.State as State
import Control.Monad.State (MonadState)
import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import Data.Char
  (intToDigit, showLitChar, isPrint, isControl, chr, ord, digitToInt, isAscii)
import Data.List (foldl', intersperse)
import Data.Monoid
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Internal as B (c2w)
import Data.ByteString (ByteString)
import qualified Data.Map as M
import Data.Ratio (numerator, denominator, (%))
import Data.Time
  ( fromGregorian, UTCTime(..), LocalTime(LocalTime)
  , timeOfDayToTime, timeToTimeOfDay )
import Data.Word (Word16, Word32)
import Network.Socket
  ( HostAddress, ProtocolNumber, Socket, SockAddr(..), SocketOption(ReuseAddr)
  , SocketType(Datagram, Stream), Family(AF_INET, AF_UNIX), socket, bindSocket
  , listen, setSocketOption, sClose, sOMAXCONN )
import System.Directory (doesFileExist, removeFile)
import System.Environment (getProgName)
import System.Exit (exitWith, ExitCode)
import System.IO (Handle, hPutStr)
import System.Posix.Files (setFileMode)
import System.Posix.Types (FileMode)
import Text.Printf (printf)
import Data.Binary (Binary(..))

import qualified Data.Conduit as C
import qualified Data.Conduit.Binary as CB

#include <netinet/in.h>

--------------------------------------------------------------------------------
-- Parsing functions

-- | Parse an 'Int' from a 'B.ByteString'. Return the result or 'throwError' in
-- the monad if parsing fails.
readInt :: MonadError ShowS m => ByteString -> m Int
readInt bs = case B.readInt bs of
  Just (int,rest) | B.null rest -> return int
  _ -> throwError $ cat "Malformed integer " (esc maxIntLen bs) '.'
  where maxIntLen = 10

-- | Parse an 'Integer' from a 'B.ByteString'. Return the result or 'throwError'
-- in the monad if parsing fails.
readInteger :: MonadError ShowS m => ByteString -> m Integer
readInteger bs = case B.readInteger bs of
  Just (int,rest) | B.null rest -> return int
  _ -> throwError $ cat "Malformed integer " (esc maxIntegerLen bs) '.'
  where maxIntegerLen = 32

-- | Convert an IPv4 address in dotted-quad form to a 'HostAddress'. Return the
-- result or 'throwError' in the monad if the format is invalid.
inet_atoh :: MonadError ShowS m => ByteString -> m HostAddress
inet_atoh bs
  | Just os@[_,_,_,_] <- mapM readInt $ B.split '.' bs
  , all (\o -> o .&. 0xff == o) os
  = return . foldl' (.|.) 0 . zipWith shiftL (map fromIntegral os) $ [24,16..]
inet_atoh bs = throwError $ cat "Malformed IP address " (esc maxAddrLen bs) '.'
  where maxAddrLen = 15

-- | Parse a UTCTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseUTCTime :: MonadError ShowS m => ByteString -> m UTCTime
parseUTCTime bs = do
  LocalTime day timeOfDay <- parseLocalTime bs
  return $! UTCTime day (timeOfDayToTime timeOfDay)

-- | Parse a LocalTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseLocalTime :: MonadError ShowS m => ByteString -> m LocalTime
parseLocalTime bs
  | B.length bs == timeLen, [date,time] <- B.split ' ' bs
  = prependError (cat "Malformed time " (esc timeLen bs) ": ") $ do
      [year,month,day]  <- mapM readInt $ B.split '-' date
      [hour,minute,sec] <- mapM readInt $ B.split ':' time
      when (month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 ||
            hour > 24 || minute < 0 || minute > 59 || sec < 0 || sec > 61) $
        throwError $ cat "Failed sanity check."
      let diff = fromInteger . toInteger $ hour * 3600 + minute * 60 + sec
      return $! LocalTime (fromGregorian (toInteger year) month day)
                          (timeToTimeOfDay diff)
  | otherwise = throwError $ cat "Malformed time " (esc timeLen bs) '.'
  where timeLen = 19

-- | Parse a quoted string with C-style escape sequences. Also return the
-- remainder of the input string. 'throwError' in the monad if parsing fails.
parseQuotedString
  :: MonadError ShowS m => ByteString -> m (ByteString, ByteString)
parseQuotedString input =
  maybe (throwError ("Malformed quoted string." ++)) return $ do
    guard $ B.take 1 input == B.pack "\""
    (content,rest) <- parseContent . B.span isText . B.drop 1 $ input
    guard $ B.take 1 rest == B.pack "\""
    return (B.concat content, B.drop 1 rest)
  where
    parseContent (text,rest)
      | B.take 1 rest /= B.pack "\\" = return ([text], rest)
      | otherwise = do
          guard $ B.length rest >= 2
          (char,escLen) <- case B.head (B.drop 1 rest) of
            '\\' -> return ('\\', 2)
            '"'  -> return ('"', 2)
            '\'' -> return ('\'', 2)
            'n'  -> return ('\n', 2)
            't'  -> return ('\t', 2)
            'r'  -> return ('\r', 2)
            _    -> do guard $ B.length ds == 3 && B.all isOctal ds && n <= 0xff
                       return (chr n, 4)
              where
                n = d1 * 8^2 + d2 * 8 + d3
                [d1,d2,d3] = map (digitToInt . B.index ds) [0..2]
                ds = B.take 3 (B.drop 1 rest)
                isOctal x = 48 <= ord x && ord x <= 55
          (parsed,unparsed) <- parseContent . B.span isText $ B.drop escLen rest
          return (text : B.singleton char : parsed, unparsed)

    isText x = isAscii x && isPrint x && x /= '\\' && x /= '"'

-- | Prepend a string to any error message thrown by the given action.
prependError :: MonadError ShowS m => ShowS -> m a -> m a
prependError msg = handleError (throwError . (msg .))

-- | Substitute another error for an error thrown by the given action.
replaceError :: MonadError e m => e -> m a -> m a
replaceError e = handleError (const $ throwError e)

-- | 'catchError' with the argument order reversed.
handleError :: MonadError e m => (e -> m a) -> m a -> m a
handleError = flip catchError

--------------------------------------------------------------------------------
-- Show functions

bshow :: (Show a) => a -> B.ByteString
bshow = B.pack . show

--------------------------------------------------------------------------------
-- Strict functions

-- | Same as 'M.adjust', but the adjusting function is applied strictly.
adjust' :: Ord k => (a -> a) -> k -> M.Map k a -> M.Map k a
adjust' = M.update . ((Just $!) .)

-- | Same as 'M.alter', but the new value is evaluated before being inserted.
alter' :: Ord k => (Maybe a -> Maybe a) -> k -> M.Map k a -> M.Map k a
alter' = M.alter . (maybe Nothing (Just $!) .)

-- | Same as 'M.update', but the new value is evaluated before being inserted.
update' :: Ord k => (a -> Maybe a) -> k -> M.Map k a -> M.Map k a
update' = M.update . (maybe Nothing (Just $!) .)

-- | Same as 'M.insert', but the new value is evaluated before being inserted.
mapInsert' :: Ord k => k -> a -> M.Map k a -> M.Map k a
mapInsert' k !x = M.insert k x

-- | Same as 'modify', but the new state is evaluated before replacing the
-- current state.
modify' :: MonadState s m => (s -> s) -> m ()
modify' f = State.get >>= (State.put $!) . f

--------------------------------------------------------------------------------
-- Miscellaneous functions

-- | A useful combinator for applying a binary function to the result of
-- applying a unary function to each of two arguments.
on :: (b -> b -> c) -> (a -> b) -> a -> a -> c
(f `on` g) x y = g x `f` g y

-- | Like 'unfoldr', except the return value contains the final accumulator
-- parameter.
unfoldAccumR :: (acc -> Either (x, acc) acc) -> acc -> ([x], acc)
unfoldAccumR f acc = case f acc of
  Left (x,acc') -> (x :) `first` unfoldAccumR f acc'
  Right acc'    -> ([], acc')

-- | Swap the elements of a pair.
swap :: (a, b) -> (b, a)
swap (x,y) = (y,x)

-- | Partition the elements of a list into two separate lists corresponding to
-- elements tagged 'Left' and 'Right'.
partitionEither :: [Either a b] -> ([a], [b])
partitionEither []           = ([], [])
partitionEither (Left x:xs)  = (x :) `first` partitionEither xs
partitionEither (Right x:xs) = (x :) `second` partitionEither xs

-- | When the argument matches @Just x@, pass @x@ to a monadic action.
whenJust :: Monad m => Maybe a -> (a -> m ()) -> m ()
whenJust = flip . maybe . return $ ()

-- | Repeat an 'IO' action until a predicate is satisfied, collecting the
-- results into a list. The predicate is evaluated before the 'IO' action.
untilM :: Monad m => m Bool -> m a -> m [a]
untilM p io = p >>= \p' ->
  if p' then return [] else liftM2 (:) io $ untilM p io

-- | Like 'untilM', but ignoring the results of the 'IO' action.
untilM_ :: Monad m => m Bool -> m a -> m ()
untilM_ p io = p >>= (`unless` (io >> untilM_ p io))

-- | Like 'untilM', but the predicate is not monadic.
muntil :: Monad m => (a -> Bool) -> m a -> m [a]
muntil p a = a >>= \a' ->
  if p a' then return [] else (a':) `liftM` muntil p a

-- | Convert an IPv4 address to a 'String' in dotted-quad form.
inet_htoa :: HostAddress -> String
inet_htoa addr =
  concat . intersperse "." . map (show . (0xff .&.) . shiftR addr) $ [24,16..0]

-- | Encode a 'ByteString' in base16.
encodeBase16 :: ByteString -> ByteString
encodeBase16 = B.pack . concat . B.foldr ((:) . toBase16 . B.c2w) []
  where toBase16 x = map (intToDigit . fromIntegral) [x `shiftR` 4, x .&. 0xf]

-- | Split a 'ByteString' into blocks of @x@ length.
split :: Int -> ByteString -> [ByteString]
split x = takeWhile (not . B.null) . map (B.take x) . iterate (B.drop x)

-- | Deconstruct a 'ByteString' at the tail.
unsnoc :: ByteString -> Maybe (ByteString, Char)
unsnoc bs | B.null bs = Nothing
          | otherwise = Just (B.init bs, B.last bs)

-- | Try an action, catching -- roughly -- "synchronous" exceptions.
--
-- XXX This is a remnant of the original code base; it's actually impossible to
-- determine if an exception was thrown synchronously just by its type. Usage of
-- this and derived combinators should be pruned in favour of only handling
-- per-use-site expected exceptions.
--
trySync :: IO a -> IO (Either E.SomeException a)
trySync = E.tryJust $ \e ->
  case E.fromException (e :: E.SomeException) of
       Just (_ :: E.AsyncException) -> Nothing
       _                            -> Just e

-- | Like 'E.bracket', but if cleanup re-throws while handling a throw, don't
-- eat the original exception.
bracket' :: IO a -> (a -> IO b) -> (a -> IO c) -> IO c
bracket' before after act =
  E.mask $ \restore -> do
    a <- before
    r <- restore (act a) `E.onException` trySync (after a)
    _ <- after a
    return r

-- | Like 'E.finally', but if cleanup re-throws while handling a throw, don't
-- eat the original exception.
finally' :: IO a -> IO b -> IO a
finally' act after = bracket' (return ()) (const after) (const act)

-- | Like 'E.bracketOnError', but if cleanup re-throws while handling a throw,
-- don't eat the original exception.
bracketOnError' :: IO a -> (a -> IO b) -> (a -> IO c) -> IO c
bracketOnError' before after act =
  E.mask $ \restore -> do
    a <- before
    restore (act a) `E.onException` trySync (after a)

-- | Like 'E.onException'
onException' :: IO a -> IO b -> IO a
onException' io act = io `E.catch` \e ->
  trySync act >> E.throwIO (e :: E.SomeException)

-- | A predicate matching synchronous exceptions.
-- XXX This is a bad idea. The exn itself conveys no info on how it was thrown.
syncExceptions :: E.SomeException -> Maybe E.SomeException
syncExceptions e
  | show e == "<<timeout>>"                           = Nothing
  | Just (_ :: E.AsyncException) <- E.fromException e = Nothing
  | otherwise                                         = Just e

-- | Print a usage message to the given handle and exit with the given code.
exitUsage :: Handle -> ExitCode -> IO a
exitUsage handle exitCode = do
  progName <- getProgName
  hCat handle "Usage: " progName " [-f <config file>] [options...]\n"
  exitWith exitCode

-- | Is an integral value inside the bounds of another integral type?
-- Unchecked precondition: @b@ is a subset of @a@.
inBoundsOf :: (Integral a, Integral b, Bounded b) => a -> b -> Bool
x `inBoundsOf` y = x >= fromIntegral (minBound `asTypeOf` y) &&
                   x <= fromIntegral (maxBound `asTypeOf` y)

instance Show ShowS where
  showsPrec _ s = shows (s "")

instance Error ShowS where
  noMsg = id
  strMsg = (++)

instance Error e => MonadError e Maybe where
  throwError = const Nothing
  catchError m f = case m of
    Nothing -> f noMsg
    other   -> other

foreign import ccall unsafe "htonl" htonl :: Word32 -> Word32
foreign import ccall unsafe "ntohl" ntohl :: Word32 -> Word32

takeC :: Monad m => Int -> C.ConduitM ByteString o m ByteString
takeC = fmap (mconcat . BL.toChunks) . CB.take

-- | Take a "frame" - delimited sequence - from the input.
-- Returns 'Nothing' if the delimiter does not appear before the stream ends.
frame :: MonadIO m => ByteString -> C.ConduitM ByteString a m (Maybe ByteString)
frame delim = input $ B.pack ""
  where
    input front = C.await >>=
      (Nothing <$ C.leftover front) `maybe` \bs ->

        let (front', bs') = (<> bs) `second`
              B.splitAt (B.length front - d_len + 1) front

        in case B.breakSubstring delim bs' of
          (part, rest) | B.null rest -> input (front' <> bs')
                       | otherwise   -> do
                          leftover $ B.drop d_len rest
                          return $ Just $ front' <> part

    d_len = B.length delim

-- | Stream delimited chunks.
frames :: MonadIO m => ByteString -> C.Conduit ByteString m ByteString
frames delim = frame delim >>=
                  return () `maybe` ((>> frames delim) . C.yield)

leftover :: Monad m => ByteString -> C.Conduit ByteString m o
leftover bs | B.null bs = return ()
            | otherwise = C.leftover bs


-- | Convert a 'UTCTime' to a string in ISO 8601 format.
showUTCTime :: UTCTime -> String
showUTCTime time = printf "%s %02d:%02d:%s" date hours mins secStr'
  where
    date = show (utctDay time)
    (n,d) = (numerator &&& denominator) (toRational $ utctDayTime time)
    (seconds,frac) = n `divMod` d
    (hours,(mins,sec)) = second (`divMod` 60) (seconds `divMod` (60^2))
    secs = fromRational (frac % d) + fromIntegral sec
    secStr = printf "%02.4f" (secs :: Double)
    secStr' = (if length secStr < 7 then ('0':) else id) secStr

--------------------------------------------------------------------------------
-- Network functions

-- | Open a new UDP socket and bind it to the given 'SockAddr'.
bindUDPSocket :: SockAddr -> IO Socket
bindUDPSocket sockAddr =
  E.bracketOnError (socket AF_INET Datagram udpProtoNum) sClose $ \sock -> do
    setSocketOption sock ReuseAddr 1
    bindSocket sock sockAddr
    return sock

-- | Open a new TCP socket, bind it to the given 'SockAddr', then pass it to
-- 'listen'.
bindListeningTCPSocket :: SockAddr -> IO Socket
bindListeningTCPSocket sockAddr = do
  E.bracketOnError (socket AF_INET Stream tcpProtoNum) sClose $ \sock -> do
    setSocketOption sock ReuseAddr 1
    bindSocket sock sockAddr
    listen sock sOMAXCONN
    return sock

-- | Open a listening Unix domain stream socket at @sockPath@, unlinking it
-- first if it exists, then setting it to the given mode.
bindListeningUnixDomainStreamSocket :: FilePath -> FileMode -> IO Socket
bindListeningUnixDomainStreamSocket sockPath mode = do
  sockExists <- doesFileExist sockPath
  when sockExists $
    removeFile sockPath
  E.bracketOnError (socket AF_UNIX Stream 0) sClose $ \sock -> do
    setSocketOption sock ReuseAddr 1
    bindSocket sock $ SockAddrUnix sockPath
    setFileMode sockPath mode
    listen sock sOMAXCONN
    return sock

-- network-2.3 compat
--
deriving instance Ord SockAddr

--------------------------------------------------------------------------------
-- Monads

-- | The transformer version of 'Maybe'.
newtype MaybeT m a = MaybeT { runMaybeT :: m (Maybe a) }

instance Functor f => Functor (MaybeT f) where
  f `fmap` MaybeT m = MaybeT $ fmap f `fmap` m

instance Monad m => Monad (MaybeT m) where
  return = MaybeT . return . Just
  MaybeT m >>= f = MaybeT $ m >>= maybe (return Nothing) (runMaybeT . f)
  fail = const . MaybeT $ return Nothing

instance MonadTrans MaybeT where
  lift = MaybeT . liftM Just

instance MonadIO m => MonadIO (MaybeT m) where
  liftIO io = lift $ liftIO io

instance Monad m => MonadPlus (MaybeT m) where
  mzero = MaybeT $ return Nothing
  MaybeT m1 `mplus` MaybeT m2 = MaybeT $ m1 >>= maybe m2 (return . Just)

instance Monad m => MonadError ShowS (MaybeT m) where
  throwError = const . MaybeT $ return Nothing
  MaybeT m `catchError` f =
    MaybeT $ m >>= maybe (runMaybeT $ f noMsg) (return . Just)

--------------------------------------------------------------------------------
-- Addresses

-- | An IP address or domain name.
data Address = IPv4Addr HostAddress | Addr ByteString

instance Show Address where
  show (IPv4Addr addr) = inet_htoa addr
  show (Addr addr)     = B.unpack addr

-- | Show an 'Address' as text.
showAddress :: Address -> ByteString
showAddress (IPv4Addr addr) = B.pack $ inet_htoa addr
showAddress (Addr addr)     = addr

-- | Parse an 'Address'.
readAddress :: ByteString -> Address
readAddress bs
  | Just addr <- inet_atoh bs = IPv4Addr addr
  | otherwise                 = Addr bs

--------------------------------------------------------------------------------
-- Ports

-- | A TCP or UDP port.
newtype Port = Port { unPort :: Word16 }
  deriving (Eq, Ord, Bounded, Num, Real, Enum, Integral)

instance Show Port where
  show (Port port) = show port

instance Binary Port where
  get = Port `fmap` get
  put = put . unPort

-- | Parse a port, returning the result or 'throwError' in the monad if parsing
-- fails.
parsePort :: MonadError ShowS m => ByteString -> m Port
parsePort bs = do
  (port,int) <- replaceError (cat "Malformed port " (esc maxPortLen bs) '.')
                             ((fromIntegral &&& id) `liftM` readInt bs)
  unless (int `inBoundsOf` port) $
    throwError $ cat "Port " int " is out of range."
  return port
  where maxPortLen = 5

--------------------------------------------------------------------------------
-- Escaped strings

-- | A string with non-printable characters escaped.
data EscapedString = Escaped { escaped :: B.ByteString, unescLen :: Int }

instance Show EscapedString where
  show = B.unpack . escaped

-- | Replace non-printable characters with standard Haskell escape sequences.
escape :: ByteString -> EscapedString
escape = uncurry Escaped . (B.concat . build &&& B.length)
  where
    build bs
      | B.null bs     = []
      | B.null unescd = [escd]
      | otherwise     = escd : escape' unescd : build rest
      where (escd,(unescd,rest)) = B.span isControl `second` B.span isPrint bs
    escape' = B.pack . flip (foldl' (.) id) "" . map showLitChar . B.unpack

-- | Quote an 'EscapedString', truncating it if its escaped length exceeds
-- @maxLen@. When truncated, append a \"[truncated, n total bytes]\" message
-- after the end quote.
showEscaped :: Int -> EscapedString -> ShowS
showEscaped maxLen (Escaped s len)
  | B.length s > maxLen = cat '"' (B.take maxLen s) '"'
                              "[truncated, " len " total bytes]"
  | otherwise           = cat '"' s '"'

-- | Show a quoted and escaped 'ByteString', truncating it to the given length
-- if necessary.
esc :: Int -> ByteString -> ShowS
esc maxLen = showEscaped maxLen . escape

--------------------------------------------------------------------------------
-- Constants

tcpProtoNum, udpProtoNum :: ProtocolNumber
tcpProtoNum = #{const IPPROTO_TCP}
udpProtoNum = #{const IPPROTO_UDP}

--------------------------------------------------------------------------------
-- Variable-parameter string concatenation

-- | The type of an argument to 'cat'.
class CatArg a where
  -- | Convert a 'CatArg' to a string for constant-time concatenation.
  showsCatArg :: a -> ShowS

instance CatArg String where
  showsCatArg = (++)

instance CatArg ShowS where
  showsCatArg = id

instance CatArg Char where
  showsCatArg = (:)

instance CatArg ByteString where
  showsCatArg = (++) . B.unpack

instance Show a => CatArg a where
  showsCatArg = shows

-- | Implements the variable parameter support for 'cat'.
class CatType r where
  cat' :: CatArg a => ShowS -> a -> r

instance CatType (IO a) where
  cat' str arg = putStr (cat' str arg) >> return undefined

instance CatType String where
  cat' str arg = cat' str arg ""

instance CatType ShowS where
  cat' str arg = str . showsCatArg arg

instance CatType ByteString where
  cat' str arg = B.pack (cat' str arg)

instance (CatArg a, CatType r) => CatType (a -> r) where
  cat' str arg = cat' (cat' str arg)

-- | Concatentate a variable number of parameters that can be converted to
-- strings.
cat :: (CatArg a, CatType r) => a -> r
cat = cat' id

-- | Implements the variable parameter support for 'hCat'.
class HCatType r where
  hCat' :: CatArg a => ShowS -> Handle -> a -> r

instance HCatType (IO a) where
  hCat' str handle arg = hPutStr handle (cat' str arg) >> return undefined

instance (CatArg a, HCatType r) => HCatType (a -> r) where
  hCat' str handle arg = hCat' (cat' str arg) handle

-- | Concatentate and output to a 'Handle' a variable number of parameters that
-- can be converted to strings.
hCat :: (CatArg a, HCatType r) => Handle -> a -> r
hCat = hCat' id
