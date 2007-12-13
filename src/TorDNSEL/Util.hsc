{-# LANGUAGE PatternGuards, BangPatterns, ForeignFunctionInterface,
             TypeSynonymInstances, OverlappingInstances,
             UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-orphans #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Util
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, bang patterns, concurrency,
--                             STM, FFI, type synonym instances, overlapping
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
  , onFailure

  -- * Miscellaneous functions
  , on
  , whenJust
  , forever
  , untilM
  , untilM_
  , inet_htoa
  , encodeBase16
  , split
  , ignoreJust
  , syncExceptions
  , exitLeft
  , inBoundsOf
  , htonl
  , ntohl
  , hGetLine
  , splitByDelimiter
  , showException
  , showUTCTime

  -- * Address
  , Address(..)
  , showAddress
  , readAddress

  -- * Ports
  , Port(..)
  , parsePort

  -- * Bounded transactional FIFO channels
  , BoundedTChan
  , newBoundedTChan
  , readBoundedTChan
  , writeBoundedTChan

  -- * Concurrent futures
  , Future
  , spawn
  , resolve

  -- * Escaped strings
  , EscapedString
  , escaped
  , unescLen
  , escape
  , showEscaped

  -- * Constants
  , tcpProtoNum
  , udpProtoNum

  -- * Variable-parameter string concatenation
  , CatArg(..)
  , CatType
  , cat
  ) where

import Control.Arrow ((&&&), second)
import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, withMVar)
import Control.Concurrent.STM
  ( STM, check, TVar, newTVar, readTVar, writeTVar
  , TChan, newTChan, readTChan, writeTChan )
import qualified Control.Exception as E
import Control.Monad (liftM, liftM2, zipWithM_, when, unless)
import Data.Array.ST (runSTUArray, newArray_, readArray, writeArray)
import Data.Array.Unboxed ((!))
import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import Data.Char (intToDigit, showLitChar, isPrint, isControl)
import Data.Dynamic (Dynamic)
import Data.List (foldl', intersperse)
import Data.Maybe (mapMaybe)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as W
import qualified Data.ByteString.Base as B
import Data.ByteString (ByteString)
import Data.Ratio (numerator, denominator, (%))
import Data.Time
  ( fromGregorian, UTCTime(..), LocalTime(LocalTime)
  , timeOfDayToTime, timeToTimeOfDay )
import Data.Word (Word16, Word32)
import Network.Socket (HostAddress, ProtocolNumber)
import Text.Printf (printf)
import System.Environment (getProgName)
import System.Exit (exitFailure)
import System.IO (hPutStr, stderr)
import System.IO.Error (isEOFError)

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

-- | Parse an 'Int' from a 'B.ByteString'. Return the result or 'fail' in the
-- monad if parsing fails.
readInt :: Monad m => ByteString -> m Int
readInt bs = case B.readInt bs of
  Just (int,rest) | B.null rest -> return int
  _                             -> fail ("Invalid integer " ++ show bs ++ ".")

-- | Parse an 'Integer' from a 'B.ByteString'. Return the result or 'fail' in
-- the monad if parsing fails.
readInteger :: Monad m => ByteString -> m Integer
readInteger bs = case B.readInteger bs of
  Just (int,rest) | B.null rest -> return int
  _                             -> fail ("Invalid integer " ++ show bs ++ ".")

-- | Convert an IPv4 address in dotted-quad form to a 'HostAddress'. Returns the
-- result or 'fail' in the monad if the format is invalid.
inet_atoh :: Monad m => ByteString -> m HostAddress
inet_atoh bs
  | Just os@[_,_,_,_] <- mapM readInt $ B.split '.' bs
  , all (\o -> o .&. 0xff == o) os
  = return . foldl' (.|.) 0 . zipWith shiftL (map fromIntegral os) $ [24,16..]
inet_atoh bs = fail ("Invalid IP address " ++ show bs ++ ".")

-- | Parse a UTCTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseUTCTime :: Monad m => ByteString -> m UTCTime
parseUTCTime bs = do
  LocalTime day timeOfDay <- parseLocalTime bs
  return $! UTCTime day (timeOfDayToTime timeOfDay)

-- | Parse a LocalTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseLocalTime :: Monad m => ByteString -> m LocalTime
parseLocalTime bs = onFailure (const $ "Invalid time " ++ show bs ++ ".") $ do
  [date,time]       <- return       $ B.split ' ' bs
  [year,month,day]  <- mapM readInt $ B.split '-' date
  [hour,minute,sec] <- mapM readInt $ B.split ':' time
  when (month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 ||
        hour > 23 || minute < 0 || minute > 59 || sec < 0 || sec > 61) $ fail ""
  let diff = fromInteger . toInteger $ hour * 3600 + minute * 60 + sec
  return $! LocalTime (fromGregorian (toInteger year) month day)
                      (timeToTimeOfDay diff)

onFailure :: Monad m => ShowS -> Either String a -> m a
onFailure f = either (fail . f) return

--------------------------------------------------------------------------------
-- Miscellaneous functions

-- | A useful combinator for applying a binary function to the result of
-- applying a unary function to each of two arguments.
on :: (b -> b -> c) -> (a -> b) -> a -> a -> c
on f g x y = g x `f` g y

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
encodeBase16 = B.pack . concat . W.foldr ((:) . toBase16) []
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

-- | Lift an @Either String@ computation into the 'IO' monad by printing
-- @Left e@ as an error message and exiting.
exitLeft :: Either String a -> IO a
exitLeft = either (\e -> err e >> exitFailure) return
  where
    err e = hPutStr stderr . unlines . (\u -> [e,u]) . usage =<< getProgName
    usage progName = "Usage: " ++ progName ++ " [-f <config file>] [options...]"

-- | Is an integral value inside the bounds of another integral type?
-- Unchecked precondition: @b@ is a subset of @a@.
inBoundsOf :: (Integral a, Integral b, Bounded b) => a -> b -> Bool
x `inBoundsOf` y = x >= fromIntegral (minBound `asTypeOf` y) &&
                   x <= fromIntegral (maxBound `asTypeOf` y)

instance Functor (Either String) where
  fmap f = either Left (Right . f)

instance Monad (Either String) where
  return = Right
  fail   = Left
  (>>=)  = flip (either Left)

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

-- | Parse a port, 'fail'ing in the monad if parsing fails.
parsePort :: Monad m => ByteString -> m Port
parsePort bs = do
  (port,int) <- onFailure (const $ "Invalid port " ++ show bs ++ ".") $
                          (fromIntegral &&& id) `liftM` readInt bs
  if int `inBoundsOf` port
    then return port
    else fail ("Port " ++ show int ++ " is out of range.")

--------------------------------------------------------------------------------
-- Bounded transactional FIFO channels

-- | An abstract type representing a transactional FIFO channel of bounded size.
data BoundedTChan a = BTChan (TChan a) (TVar Int) Int

-- | Create a new bounded channel of a given size.
newBoundedTChan :: Int -> STM (BoundedTChan a)
newBoundedTChan maxSize = do
  currentSize <- newTVar 0
  chan <- newTChan
  return (BTChan chan currentSize maxSize)

-- | Read from a bounded channel, blocking until an item is available.
readBoundedTChan :: BoundedTChan a -> STM a
readBoundedTChan (BTChan chan currentSize _) = do
  size <- readTVar currentSize
  writeTVar currentSize (size - 1)
  readTChan chan

-- | Write to a bounded channel, blocking until the channel is smaller than its
-- maximum size.
writeBoundedTChan :: BoundedTChan a -> a -> STM ()
writeBoundedTChan (BTChan chan currentSize maxSize) x = do
  size <- readTVar currentSize
  check (size < maxSize)
  writeTVar currentSize (size + 1)
  writeTChan chan x

--------------------------------------------------------------------------------
-- Concurrent futures

-- | An abstract type representing a value being evaluated concurrently in
-- another thread of execution.
newtype Future a = Future (MVar (Either E.Exception a))

-- | Evaluate the given 'IO' action in a separate thread and return a future of
-- its result immediately.
spawn :: IO a -> IO (Future a)
spawn io = do
  mv <- newEmptyMVar
  forkIO (E.try io >>= putMVar mv)
  return $ Future mv

-- | Explicitly unwrap the value contained within a future. Block until the
-- value has been evaluated, throwing an exception if the future failed.
resolve :: Future a -> IO a
resolve (Future mv) = withMVar mv (either E.throwIO return)

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
      | B.null bs    = []
      | B.null unesc = [esc]
      | otherwise    = esc : escape' unesc : build rest
      where (esc,(unesc,rest)) = second (B.span isControl) . B.span isPrint $ bs
    escape' = B.pack . flip (foldl' (.) id) "" . map showLitChar . B.unpack

-- | Quote an 'EscapedString', truncating it if its escaped length exceeds
-- @maxLen@. When truncated, append a \"[truncated, n total bytes]\" message
-- after the end quote.
showEscaped :: Int -> EscapedString -> ShowS
showEscaped maxLen (Escaped s len)
  | B.length s > maxLen = quote (B.unpack (B.take maxLen s) ++) .
                          ("[truncated, " ++) . shows len . (" total bytes]" ++)
  | otherwise           = quote (B.unpack s ++)
  where quote f = ('"':) . f . ('"':)

--------------------------------------------------------------------------------
-- Constants

tcpProtoNum, udpProtoNum :: ProtocolNumber
tcpProtoNum = #{const IPPROTO_TCP}
udpProtoNum = #{const IPPROTO_UDP}

--------------------------------------------------------------------------------
-- Variable-parameter string concatenation

class CatArg a where
  showsCatArg :: a -> ShowS

instance CatArg String where
  showsCatArg = (++)

instance CatArg ShowS where
  showsCatArg = id

instance CatArg Char where
  showsCatArg = (:)

instance Show a => CatArg a where
  showsCatArg = shows

class CatType r where
  cat' :: CatArg a => ShowS -> a -> r

instance CatType (IO ()) where
  cat' = (putStr .) . cat'

instance CatType String where
  cat' str arg = cat' str arg ""

instance CatType ShowS where
  cat' str arg = str . showsCatArg arg

instance (CatArg a, CatType r) => CatType (a -> r) where
  cat' str arg = cat' (cat' str arg)

cat :: (CatArg a, CatType r) => a -> r
cat = cat' id
