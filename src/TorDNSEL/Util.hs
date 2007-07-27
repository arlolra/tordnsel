{-# LANGUAGE PatternGuards, ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Util
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, concurrency, STM, FFI)
--
-- Common utility functions.
--
-----------------------------------------------------------------------------

module TorDNSEL.Util (
  -- * Parsing functions
    readInt
  , inet_atoh
  , parseUTCTime
  , parseLocalTime

  -- * Miscellaneous functions
  , on
  , whenJust
  , forever
  , inet_htoa
  , encodeBase16
  , split
  , ignoreJust
  , exitLeft
  , inBoundsOf
  , htonl
  , ntohl

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
  ) where

import Control.Arrow ((&&&))
import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, withMVar)
import Control.Concurrent.STM
  ( STM, check, TVar, newTVar, readTVar, writeTVar
  , TChan, newTChan, readTChan, writeTChan )
import qualified Control.Exception as E
import Control.Monad (liftM)
import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import Data.Char (intToDigit)
import Data.List (foldl', intersperse)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as W
import Data.ByteString (ByteString)
import Data.Time
  ( fromGregorian, UTCTime(..), LocalTime(LocalTime)
  , timeOfDayToTime, timeToTimeOfDay )
import Data.Word (Word16, Word32)
import Network.Socket (HostAddress)
import System.Environment (getProgName)
import System.Exit (exitFailure)
import System.IO (hPutStr, stderr)

import Data.Binary (Binary(..))

import TorDNSEL.DeepSeq

--------------------------------------------------------------------------------
-- Parsing functions

-- | Parse an 'Int' from a 'B.ByteString'. Return the result or 'fail' in the
-- monad if parsing fails.
readInt :: Monad m => B.ByteString -> m Int
readInt bs = case B.readInt bs of
  Just (x,_) -> return x
  _          -> fail ("Parsing integer " ++ show bs ++ " failed.")

-- | Convert an IPv4 address in dotted-quad form to a 'HostAddress'. Returns the
-- result or 'fail' in the monad if the format is invalid.
inet_atoh :: Monad m => B.ByteString -> m HostAddress
inet_atoh bs
  | Just os@[_,_,_,_] <- mapM readInt $ B.split '.' bs
  , all (\o -> 0 <= o && o <= 0xff) os
  = return . foldl' (.|.) 0 . zipWith shiftL (map fromIntegral os) $ [24,16..]
inet_atoh bs = fail ("Invalid IP address " ++ show bs)

-- | Parse a UTCTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseUTCTime :: Monad m => ByteString -> m UTCTime
parseUTCTime bs = do
  LocalTime day timeOfDay <- parseLocalTime bs
  return $! UTCTime day (timeOfDayToTime timeOfDay)

-- | Parse a LocalTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseLocalTime :: Monad m => ByteString -> m LocalTime
parseLocalTime bs = do
  [date,time]       <- return       $ B.split ' ' bs
  [year,month,day]  <- mapM readInt $ B.split '-' date
  [hour,minute,sec] <- mapM readInt $ B.split ':' time
  let diff = fromInteger . toInteger $ hour * 3600 + minute * 60 + sec
  return $! LocalTime (fromGregorian (toInteger year) month day)
                      (timeToTimeOfDay diff)

--------------------------------------------------------------------------------
-- Miscellaneous functions

-- | A useful combinator for applying a binary function to the result of
-- applying a unary function to each of two arguments.
on :: (b -> b -> c) -> (a -> b) -> a -> a -> c
on f g x y = g x `f` g y

-- | When the argument matches @Just x@, pass @x@ to a monadic action.
whenJust :: Monad m => Maybe a -> (a -> m ()) -> m ()
whenJust = flip . maybe . return $ ()

-- | Repeat an IO action forever.
forever :: IO a -> IO ()
forever = sequence_ . repeat

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
  (port,int) <- (fromIntegral &&& id) `liftM` readInt bs
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
