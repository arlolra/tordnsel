{-# OPTIONS_GHC -fglasgow-exts #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitTest.Request
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (GHC primitives)
--
-- Functions for parsing and generating HTTP requests used to make test
-- connections through exit nodes. Also implements cookies (nonces) for
-- authenticating test connections.
--
-----------------------------------------------------------------------------

module TorDNSEL.ExitTest.Request (
  -- * HTTP requests
    createRequest
  , getRequest

  -- * Cookies
  , Cookie(..)
  , newCookie
  , cookieLen
  ) where

import Control.Arrow ((***))
import Control.Monad (guard)
import Control.Monad.Trans (lift)
import qualified Data.ByteString.Char8 as B
import Data.Char (isSpace, toLower)
import qualified Data.Map as M
import System.IO (Handle)

import GHC.Prim (Addr#)

import TorDNSEL.Random
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- HTTP requests

-- | Create an HTTP request that POSTs a cookie to one of our listening ports.
createRequest :: B.ByteString -> Port -> Cookie -> B.ByteString
createRequest host port cookie =
  B.join (b 2 "\r\n"#)
  -- POST should force caching proxies to forward the request.
  [ b 15 "POST / HTTP/1.0"#
  -- Host doesn't exist in HTTP 1.0. We'll use it anyway to help the request
  -- traverse transparent proxies.
  , b 6 "Host: "# `B.append` hostValue
  , b 38 "Content-Type: application/octet-stream"#
  , b 16 "Content-Length: "# `B.append` B.pack (show cookieLen)
  , b 17 "Connection: close"#
  , b 2 "\r\n"# `B.append` unCookie cookie ]
  where
    hostValue
      | port == 80 = host
      | otherwise  = B.concat [host, b 1 ":"#, B.pack $ show port]

-- | Given an HTTP client, return the cookie contained in the body of the HTTP
-- request if it's well-formatted, otherwise return 'Nothing'.
getRequest :: Handle -> MaybeT IO Cookie
getRequest client = do
  (reqLine,headers) <- lift $ getHeader

  guard $ reqLine `elem` [b 15 "POST / HTTP/1.0"#, b 15 "POST / HTTP/1.1"#]
  contentType <- b 12 "content-type"# `M.lookup` headers
  guard $ contentType == b 24 "application/octet-stream"#
  contentLen <- readInt =<< b 14 "content-length"# `M.lookup` headers
  guard $ contentLen == cookieLen

  fmap Cookie . lift $ B.hGet client cookieLen
  where
    maxHeaderLen = 2048
    crlf = b 2 "\r\n"#
    crlfLen = 2

    getHeader = do
      reqLine <- hGetLine client crlf maxHeaderLen
      headers <- getHeaders (maxHeaderLen - B.length reqLine - crlfLen)
      return (reqLine, M.fromList headers)

    getHeaders remain
      | remain <= 0 = return []
      | otherwise = do
          header <- hGetLine client crlf remain
          if B.null header
            then return []
            else do
              headers <- getHeaders (remain - B.length header - crlfLen)
              return (readHeader header : headers)

    readHeader =
      (B.map toLower *** B.dropWhile isSpace . B.drop 1) . B.break (== ':')

--------------------------------------------------------------------------------
-- Cookies

-- | A cookie containing pseudo-random data that we send in an HTTP request. We
-- associate it with the exit node we're testing through and use it look up that
-- exit node when we receive it on a listening port.
newtype Cookie = Cookie { unCookie :: B.ByteString }
  deriving (Eq, Ord)

-- | Create a new cookie from pseudo-random data.
newCookie :: Handle -> IO Cookie
newCookie random = Cookie `fmap` randBytes random cookieLen

-- | The cookie length in bytes.
cookieLen :: Int
cookieLen = 32

--------------------------------------------------------------------------------
-- Aliases

-- | An alias for 'B.unsafePackAddress'.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
