{-# LANGUAGE OverloadedStrings  #-}

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
import Control.Applicative
import Control.Monad
import Data.Monoid
import Data.Maybe
import qualified Data.ByteString.Char8 as B
import Data.Char (isSpace, toLower)
import qualified Data.Map as M
import System.IO (Handle)

import           Data.Conduit
import qualified Data.Conduit.Binary as CB

import TorDNSEL.Util

--------------------------------------------------------------------------------
-- HTTP requests

-- | Create an HTTP request that POSTs a cookie to one of our listening ports.
createRequest :: B.ByteString -> Port -> Cookie -> B.ByteString
createRequest host port cookie =
    B.intercalate "\r\n"
    -- POST should force caching proxies to forward the request.
    [ "POST / HTTP/1.0"
    -- Host doesn't exist in HTTP 1.0. We'll use it anyway to help the request
    -- traverse transparent proxies.
    , "Host: " <> hostValue
    , "Content-Type: application/octet-stream"
    , "Content-Length: " <> bshow cookieLen
    , "Connection: close"
    , "\r\n" <> unCookie cookie ]

  where
    hostValue
      | port == 80 = host
      | otherwise  = B.concat [host, ":", bshow port]

-- | Given an HTTP client, return the cookie contained in the body of the HTTP
-- request if it's well-formatted, otherwise return 'Nothing'.
getRequest :: Handle -> IO (Maybe Cookie)
getRequest client =
    CB.sourceHandle client $= CB.isolate maxReqLen $$ do
      reqline <- line
      hs      <- accHeaders []
      case checkHeaders reqline hs of
           Nothing -> return Nothing
           Just _  -> Just . Cookie <$> takeC cookieLen

  where
    maxReqLen = 2048 + cookieLen
    line      = fromMaybe "" <$> frame "\r\n"

    accHeaders hs = line >>= \ln ->
      if ln == "" then return $ M.fromList hs
                  else accHeaders (parseHeader ln : hs)

    parseHeader = (B.map toLower *** B.dropWhile isSpace . B.tail) .
                    B.break (== ':')

    checkHeaders reqline headers = do
      contentType <- "content-type" `M.lookup` headers
      contentLen  <- readInt =<< "content-length" `M.lookup` headers
      guard $ reqline `elem` ["POST / HTTP/1.0", "POST / HTTP/1.1"]
      guard $ contentType == "application/octet-stream"
      guard $ contentLen == cookieLen

--------------------------------------------------------------------------------
-- Cookies

-- | A cookie containing pseudo-random data that we send in an HTTP request. We
-- associate it with the exit node we're testing through and use it look up that
-- exit node when we receive it on a listening port.
newtype Cookie = Cookie { unCookie :: B.ByteString }
  deriving (Eq, Ord, Show)

-- | Create a new cookie from pseudo-random data.
newCookie :: (Int -> IO B.ByteString) -> IO Cookie
newCookie getRandBytes = Cookie `fmap` getRandBytes cookieLen

-- | The cookie length in bytes.
cookieLen :: Int
cookieLen = 32

