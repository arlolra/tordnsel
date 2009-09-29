{-# LANGUAGE PatternGuards, BangPatterns, ForeignFunctionInterface,
             TypeSynonymInstances, OverlappingInstances,
             UndecidableInstances, FlexibleInstances, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-orphans -Wwarn #-}
--                                                        ^^^^^^
--                                    XXX: findSubstrings is deprecated

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
  , forever
  , untilM
  , untilM_
  , inet_htoa
  , encodeBase16
  , split
  , ignoreJust
  , syncExceptions
  , exitUsage
  , inBoundsOf
  , htonl
  , ntohl
  , hGetLine
  , splitByDelimiter
  , showException
  , showUTCTime

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
import qualified TorDNSEL.Compat.Exception as E
import Control.Monad.Error
  (Error(..), MonadError(..), MonadTrans(..), MonadIO(..))
import qualified Control.Monad.State as State
import Control.Monad.State
  (MonadState, liftM, liftM2, zipWithM_, when, unless, guard, MonadPlus(..))
import Data.Array.ST (runSTUArray, newArray_, readArray, writeArray)
import Data.Array.Unboxed ((!))
import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import Data.Char
  (intToDigit, showLitChar, isPrint, isControl, chr, ord, digitToInt, isAscii)
import Data.Dynamic (Dynamic)
import Data.List (foldl', intersperse)
import Data.Maybe (mapMaybe)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Unsafe as B
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
import System.IO (hPutStr)
import System.IO.Error (isEOFError)
import System.Posix.Files (setFileMode)
import System.Posix.Types (FileMode)
import Text.Printf (printf)

import GHC.Handle
  (wantReadableHandle, fillReadBuffer, readCharFromBuffer, ioe_EOF)
import GHC.IOBase
  ( Handle, Handle__(..), Buffer(..), readIORef, writeIORef
  , BufferMode(NoBuffering) )

import Data.Binary (Binary(..))

import TorDNSEL.DeepSeq

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

-- | Repeat an 'IO' action forever.
forever :: IO a -> IO ()
forever = sequence_ . repeat

-- | Repeat an 'IO' action until a predicate is satisfied, collecting the
-- results into a list. The predicate is evaluated before the 'IO' action.
untilM :: IO Bool -> IO a -> IO [a]
untilM p io = loop where loop = do p' <- p
                                   if p' then return []
                                         else liftM2 (:) io loop

-- | Like 'untilM', but ignoring the results of the 'IO' action.
untilM_ :: IO Bool -> IO a -> IO ()
untilM_ p io = loop where loop = p >>= flip unless (io >> loop)

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

-- | Catch and discard exceptions matching the predicate.
ignoreJust :: (E.Exception -> Maybe a) -> IO () -> IO ()
ignoreJust p = E.handleJust p . const . return $ ()

-- | A predicate matching synchronous exceptions.
syncExceptions :: E.Exception -> Maybe E.Exception
syncExceptions (E.AsyncException _) = Nothing
syncExceptions e                    = Just e

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

-- | Read a line terminated by an arbitrary sequence of bytes from a handle. The
-- end-of-line sequence is stripped before returning the line. @maxLen@
-- specifies the maximum line length to read, not including the end-of-line
-- sequence. If the line length exceeds @maxLen@, return the first @maxLen@
-- bytes. If EOF is encountered, return the bytes preceding it. The handle
-- should be in 'LineBuffering' mode.
hGetLine :: Handle -> ByteString -> Int -> IO ByteString
hGetLine h eol maxLen | B.null eol = B.hGet h maxLen
hGetLine h eol@(B.PS _ _ eolLen) maxLen
  = wantReadableHandle "TorDNSEL.Util.hGetLine" h $ \handle_ -> do
      case haBufferMode handle_ of
        NoBuffering -> error "no buffering"
        _other      -> hGetLineBuffered handle_

  where
    hGetLineBuffered handle_ = do
      let ref = haBuffer handle_
      buf <- readIORef ref
      hGetLineBufferedLoop handle_ ref buf 0 0 []

    hGetLineBufferedLoop handle_ ref
      buf@Buffer{ bufRPtr=r, bufWPtr=w, bufBuf=raw } !len !eolIx xss = do
        (new_eolIx,off) <- findEOL eolIx r w raw
        let new_len = len + off - r

        if maxLen > 0 && new_len - new_eolIx > maxLen
          -- If the line length exceeds maxLen, return a partial line.
          then do
            let maxOff = off - (new_len - maxLen)
            writeIORef ref buf{ bufRPtr = maxOff }
            mkBigPS . (:xss) =<< mkPS raw r maxOff
          else if new_eolIx == eolLen
            -- We have a complete line; strip the EOL sequence and return it.
            then do
              if w == off
                then writeIORef ref buf{ bufRPtr=0, bufWPtr=0 }
                else writeIORef ref buf{ bufRPtr = off }
              if eolLen <= off - r
                then mkBigPS . (:xss) =<< mkPS raw r (off - eolLen)
                else fmap stripEOL . mkBigPS . (:xss) =<< mkPS raw r off
            else do
              xs <- mkPS raw r off
              maybe_buf <- maybeFillReadBuffer (haFD handle_) True
                             (haIsStream handle_) buf{ bufWPtr=0, bufRPtr=0 }
              case maybe_buf of
                -- Nothing indicates we caught an EOF, and we may have a
                -- partial line to return.
                Nothing -> do
                  writeIORef ref buf{ bufRPtr=0, bufWPtr=0 }
                  if new_len > 0
                    then mkBigPS (xs:xss)
                    else ioe_EOF
                Just new_buf ->
                  hGetLineBufferedLoop handle_ ref new_buf new_len new_eolIx
                                       (xs:xss)

    maybeFillReadBuffer fd is_line is_stream buf
      = catch (Just `fmap` fillReadBuffer fd is_line is_stream buf)
              (\e -> if isEOFError e then return Nothing else ioError e)

    findEOL eolIx
      | eolLen == 1 = findEOLChar (B.w2c $ B.unsafeHead eol)
      | otherwise   = findEOLSeq eolIx

    findEOLChar eolChar r w raw
      | r == w = return (0, r)
      | otherwise = do
          (!c,!r') <- readCharFromBuffer raw r
          if c == eolChar
            then return (1, r')
            else findEOLChar eolChar r' w raw

    -- find the end-of-line sequence, if there is one
    findEOLSeq !eolIx r w raw
      | eolIx == eolLen || r == w = return (eolIx, r)
      | otherwise = do
          (!c,!r') <- readCharFromBuffer raw r
          findEOLSeq (next c eolIx + 1) r' w raw

    -- get the next index into the EOL sequence we should match against
    next !c !i = if i >= 0 && c /= eolIndex i then next c (table ! i) else i

    eolIndex = B.w2c . B.unsafeIndex eol

    -- build a match table for the Knuth-Morris-Pratt algorithm
    table = runSTUArray (do
      arr <- newArray_ (0, if eolLen == 1 then 1 else eolLen - 1)
      zipWithM_ (writeArray arr) [0,1] [-1,0]
      loop arr 2 0)
      where
        loop arr !t !p
          | t >= eolLen = return arr
          | eolIndex (t - 1) == eolIndex p
          = let p' = p + 1 in writeArray arr t p' >> loop arr (t + 1) p'
          | p > 0 = readArray arr p >>= loop arr t
          | otherwise = writeArray arr t 0 >> loop arr (t + 1) p

    stripEOL (B.PS p s l) = E.assert (new_len >= 0) . B.copy $ B.PS p s new_len
      where new_len = l - eolLen

    mkPS buf start end = B.create len $ \p -> do
      B.memcpy_ptr_baoff p buf (fromIntegral start) (fromIntegral len)
      return ()
      where len = end - start

    mkBigPS [ps] = return ps
    mkBigPS pss  = return $! B.concat (reverse pss)

-- | Split @bs@ into pieces delimited by @delimiter@, consuming the delimiter.
-- The result for overlapping delimiters is undefined.
splitByDelimiter :: ByteString -> ByteString -> [ByteString]
splitByDelimiter delimiter bs = subst (-len : B.findSubstrings delimiter bs)
  where
    subst (x:xs@(y:_)) = B.take (y-x-len) (B.drop (x+len) bs) : subst xs
    subst [x]          = [B.drop (x+len) bs]
    subst []           = error "splitByDelimiter: empty list"
    len = B.length delimiter

-- | Convert an exception to a string given a list of functions for displaying
-- dynamically typed exceptions.
showException :: [Dynamic -> Maybe String] -> E.Exception -> String
showException fs (E.DynException dyn)
  | str:_ <- mapMaybe ($ dyn) fs = str
showException _ e                = show e

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

instance Ord SockAddr where
  SockAddrInet port1 addr1 `compare` SockAddrInet port2 addr2 =
    case addr1 `compare` addr2 of
      EQ    -> port1 `compare` port2
      other -> other
  SockAddrUnix path1 `compare` SockAddrUnix path2 = path1 `compare` path2
  SockAddrInet _ _ `compare` SockAddrUnix _ = LT
  SockAddrUnix _ `compare` SockAddrInet _ _ = GT

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

instance DeepSeq Port where
  deepSeq = seq . unPort

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
