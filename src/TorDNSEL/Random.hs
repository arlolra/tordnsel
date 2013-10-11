{-# LANGUAGE ForeignFunctionInterface, ScopedTypeVariables #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Random
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (FFI)
--
-- Generating cryptographically strong pseudo-random data with OpenSSL.
--
-----------------------------------------------------------------------------

module TorDNSEL.Random (
    randBytes
  , openRandomDevice
  , seedPRNG
  ) where

import Control.Monad (filterM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import System.Directory (doesFileExist)
import System.IO (Handle, openFile, IOMode(ReadMode))

import Foreign (Ptr, Word8, withForeignPtr, plusPtr)
import Foreign.C.Types (CInt(..))

import TorDNSEL.Util

-- | Return @n@ bytes of random data, blocking until the PRNG is seeded.
randBytes :: Handle -> Int -> IO B.ByteString
randBytes random n = B.create n $ \p ->
  untilM_ ((1 ==) `fmap` c_RAND_bytes p (fromIntegral n)) $
    seedPRNG random

foreign import ccall unsafe "openssl/rand.h RAND_bytes"
  c_RAND_bytes :: Ptr Word8 -> CInt -> IO CInt

-- | Open a kernel random number device if one exists.
openRandomDevice :: Monad m => IO (m Handle)
openRandomDevice = do
  devs <- filterM doesFileExist ["/dev/srandom", "/dev/random", "/dev/urandom"]
  case devs of
    dev:_ -> return `fmap` openFile dev ReadMode
    []    -> return $ fail "Kernel random number device not found."

-- | Seed the OpenSSL PRNG if it isn't already seeded with enough data. Block
-- until it's properly seeded.
seedPRNG :: Handle -> IO ()
seedPRNG random = untilM_ randStatus (B.hGet random 8 >>= randSeed)

randSeed :: B.ByteString -> IO ()
randSeed (B.PS ps s l) = withForeignPtr ps $ \p ->
  c_RAND_seed (p `plusPtr` s) (fromIntegral l)

foreign import ccall unsafe "openssl/rand.h RAND_seed"
  c_RAND_seed :: Ptr Word8 -> CInt -> IO ()

randStatus :: IO Bool
randStatus = (1 ==) `fmap` c_RAND_status

foreign import ccall unsafe "openssl/rand.h RAND_status"
  c_RAND_status :: IO CInt
