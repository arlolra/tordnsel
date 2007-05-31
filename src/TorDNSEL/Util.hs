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
-- Portability : non-portable (pattern guards, FFI)
--
-- Common utility functions.
--
-----------------------------------------------------------------------------

module TorDNSEL.Util where

import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import Data.Char (intToDigit)
import Data.List (foldl', intersperse)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as W
import Data.ByteString (ByteString)
import Data.Time (fromGregorian, UTCTime(..), addUTCTime)
import Data.Word (Word32)
import Network.Socket (HostAddress)
import System.Environment (getProgName)
import System.Exit (exitFailure)
import System.IO (hPutStr, stderr)

-- | Parse an 'Int' from a 'B.ByteString'. Return the result or 'fail' in the
-- monad if parsing fails.
readInt :: Monad m => B.ByteString -> m Int
readInt bs = case B.readInt bs of
  Just (x,_) -> return x
  _          -> fail ("readInt \"" ++ B.unpack bs ++ "\": failed")

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

-- | Convert an IPv4 address in dotted-quad form to a 'HostAddress'. Returns the
-- result or 'fail' in the monad if the format is invalid.
inet_atoh :: Monad m => B.ByteString -> m HostAddress
inet_atoh bs
  | Just os@[_,_,_,_] <- mapM readInt $ B.split '.' bs
  , all (\o -> 0 <= o && o <= 255) os
  = return . foldl' (.|.) 0 . zipWith shiftL (map fromIntegral os) $ [24,16..]
inet_atoh bs = fail ("Invalid IP address " ++ show bs)

-- | Encode a 'ByteString' in base16.
encodeBase16 :: ByteString -> ByteString
encodeBase16 = B.pack . concat . W.foldr ((:) . toBase16) []
  where toBase16 x = map (intToDigit . fromIntegral) [x `shiftR` 4, x .&. 0xf]

-- | Parse a UTCTime in this format: \"YYYY-MM-DD HH:MM:SS\".
parseTime :: Monad m => ByteString -> m UTCTime
parseTime bs = do
  [date,time]          <- return       $ B.split ' ' bs
  [year,month,day]     <- mapM readInt $ B.split '-' date
  [hour,minute,second] <- mapM readInt $ B.split ':' time
  let utcDay = fromGregorian (fromIntegral year) month day
      utcDayTime = hour * 3600 + minute * 60 + second
  return $! addUTCTime (fromIntegral utcDayTime) (UTCTime utcDay 0)

-- | Split a 'ByteString' into blocks of @x@ length.
split :: Int -> ByteString -> [ByteString]
split x = takeWhile (not . B.null) . map (B.take x) . iterate (B.drop x)

-- | Lift an @Either String@ computation into the 'IO' monad by printing
-- @Left e@ as an error message and exiting.
exitLeft :: Either String a -> IO a
exitLeft = either (\e -> err e >> exitFailure) return
  where
    err e = hPutStr stderr . unlines . (:[e]) . usage =<< getProgName
    usage progName = "Usage: " ++ progName ++ " [-f <config file>] [options...]"

instance Functor (Either String) where
  fmap f = either Left (Right . f)

instance Monad (Either String) where
  return = Right
  fail   = Left
  (>>=)  = flip (either Left)

foreign import ccall unsafe "htonl" htonl :: Word32 -> Word32
foreign import ccall unsafe "ntohl" ntohl :: Word32 -> Word32
