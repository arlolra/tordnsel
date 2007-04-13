{-# LANGUAGE PatternGuards, ForeignFunctionInterface #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Util
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, ffi)
--
-- Common utility functions.
--
-----------------------------------------------------------------------------

module TorDNSEL.Util where

import Data.Char (intToDigit)
import Data.List (foldl', intersperse)
import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import Network.Socket (HostAddress)
import qualified Data.ByteString as W
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)

-- | Parses an 'Int' from a 'B.ByteString'. Returns the result or 'fail' in the
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
inet_atoh bs = fail ("inet_aton \"" ++ B.unpack bs ++ "\": invalid IP address")

-- | Encode a 'ByteString' in base16.
encodeBase16 :: ByteString -> ByteString
encodeBase16 = B.pack . concat . W.foldr ((:) . padByte . toBase16 []) []
  where
    padByte xs@[_] = '0':xs
    padByte xs     = xs
    toBase16 digits x
      | d == 0    = digits'
      | otherwise = toBase16 digits' (digit `seq` d)
      where
        digits' = digit : digits
        digit = intToDigit . fromIntegral $ m
        (d,m) = x `divMod` 16
