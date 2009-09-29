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
import Control.Monad.Trans (lift, liftIO)
import qualified Data.ByteString.Char8 as B
import Data.Char (isSpace, toLower)
import qualified Data.Map as M
import System.IO (Handle)

import TorDNSEL.Util

--------------------------------------------------------------------------------
-- HTTP requests

-- | Create an HTTP request that POSTs a cookie to one of our listening ports.
createRequest :: B.ByteString -> Port -> Cookie -> B.ByteString
createRequest host port cookie =
  B.intercalate (B.pack "\r\n")
  -- POST should force caching proxies to forward the request.
  [ B.pack "POST / HTTP/1.0"
  -- Host doesn't exist in HTTP 1.0. We'll use it anyway to help the request
  -- traverse transparent proxies.
  , B.pack "Host: " `B.append` hostValue
  , B.pack "Content-Type: application/octet-stream"
  , B.pack "Content-Length: " `B.append` B.pack (show cookieLen)
  , B.pack "Connection: close"
  , B.pack "\r\n" `B.append` unCookie cookie ]
  where
    hostValue
      | port == 80 = host
      | otherwise  = B.concat [host, B.pack ":", B.pack $ show port]

-- | Given an HTTP client, return the cookie contained in the body of the HTTP
-- request if it's well-formatted, otherwise return 'Nothing'.
getRequest :: Handle -> MaybeT IO Cookie
getRequest client = do
  (reqLine,headers) <- liftIO $ getHeader
  guard $ reqLine `elem` [B.pack "POST / HTTP/1.0", B.pack "POST / HTTP/1.1"]
  Just contentType <- return $ B.pack "content-type" `M.lookup` headers
  guard $ contentType == B.pack "application/octet-stream"
  Just contentLen <- return $ readInt =<< B.pack "content-length" `M.lookup` headers
  guard $ contentLen == cookieLen

  fmap Cookie . lift $ B.hGet client cookieLen
  where
    maxHeaderLen = 2048
    crlf = B.pack "\r\n"
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
newCookie :: (Int -> IO B.ByteString) -> IO Cookie
newCookie getRandBytes = Cookie `fmap` getRandBytes cookieLen

-- | The cookie length in bytes.
cookieLen :: Int
cookieLen = 32
