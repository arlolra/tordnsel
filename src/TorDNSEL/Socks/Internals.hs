{-# LANGUAGE GeneralizedNewtypeDeriving, DeriveDataTypeable #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Socks.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (dynamic exceptions, newtype deriving)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Making a TCP connection using the SOCKS4A protocol. Support for various
-- Tor extensions to SOCKS is sketched out.
--
-- See <https://www.torproject.org/svn/trunk/doc/spec/socks-extensions.txt> for
-- details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Socks.Internals (
  -- * Connections
    withSocksConnection

  -- * Data types
  , Request(..)
  , Command(..)
  , Response(..)
  , Result(..)

  -- * Serialization
  , encodeRequest
  , decodeResponse

  -- * Errors
  , SocksError(..)
  , showSocksError
  ) where

import qualified TorDNSEL.Compat.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.Dynamic (Dynamic, fromDynamic)
import Data.Typeable (Typeable)
import Network.Socket (HostAddress)
import System.IO (Handle, BufferMode(NoBuffering), hClose, hSetBuffering)

import Data.Binary (Binary(..), getWord8, putWord8)
import Data.Binary.Get (runGet)
import Data.Binary.Put (runPut, putWord32be, putByteString)

import TorDNSEL.DeepSeq
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Connections

-- | Open a Socks connection to an IP address\/domain name and port. The handle
-- will be closed if an exception occurs during the given 'IO' action. Throw a
-- 'SocksError' if the connection request fails.
withSocksConnection :: Handle -> Address -> Port -> IO a -> IO a
withSocksConnection handle addr port io = (`E.finally` hClose handle) $ do
  hSetBuffering handle NoBuffering
  B.hPut handle . encodeRequest $ Request Connect addr port
  r <- decodeResponse =<< B.hGet handle 8
  case r of
    Just (Response Granted _ _) -> io
    Just (Response result _ _)  -> E.throwDyn (SocksError result)
    _                           -> E.throwDyn SocksProtocolError

--------------------------------------------------------------------------------
-- Data types

-- | A Socks4a request.
data Request = Request
  { -- | The Socks4 command code (with Tor extensions).
    soCommand :: {-# UNPACK #-} !Command,
    -- | The requested destination: either an IPv4 address or a domain name.
    soReqDest :: {-# UNPACK #-} !Address,
    -- | The requested destination port.
    soReqPort :: {-# UNPACK #-} !Port }

-- A Socks4a command (with Tor extensions).
data Command
  = Connect    -- ^ Connect to the requested destination.
  | Resolve    -- ^ Resolve a domain name.
  | ConnectDir -- ^ Establish a secure connection to a Tor directory.

-- | A Socks4 response.
data Response = Response
  { soResult   :: {-# UNPACK #-} !Result      -- ^ The result code.
  , soRespAddr :: {-# UNPACK #-} !HostAddress -- ^ The destination address.
  , soRespPort :: {-# UNPACK #-} !Port        -- ^ The destination port.
  }

instance DeepSeq Response where
  deepSeq (Response a b c) = deepSeq a . deepSeq b $ deepSeq c

-- | A Socks4 result code.
data Result
  = Granted           -- ^ Request granted
  | Failed            -- ^ Request rejected or failed
  | IdentdUnreachable -- ^ Request rejected because SOCKS server cannot connect
                      -- to identd on the client
  | IdentdMismatch    -- ^ Request rejected because the client program and
                      -- identd report different user-ids
  deriving Eq

instance Show Result where
  show Granted           = "Request granted"
  show Failed            = "Request rejected or failed"
  show IdentdUnreachable = "Request rejected because SOCKS server cannot \
                           \connect to identd on the client"
  show IdentdMismatch    = "Request rejected because the client program and \
                           \identd report different user-ids"

instance DeepSeq Result where deepSeq = seq

--------------------------------------------------------------------------------
-- Serialization

-- | Encode a Socks4 request.
encodeRequest :: Request -> ByteString
encodeRequest = B.concat . L.toChunks . runPut . putRequest
  where
    putRequest req = do
      putWord8 4
      putWord8 $ case soCommand req of
        Connect    -> 1
        Resolve    -> 0xf0
        ConnectDir -> 0xf2
      put $ soReqPort req
      case soReqDest req of
        IPv4Addr addr -> do
          put addr
          putWord8 0
        Addr addr -> do
          putWord32be 1
          putWord8 0
          putByteString addr
          putWord8 0

-- | Decode a Socks4 response.
decodeResponse :: ByteString -> IO (Maybe Response)
decodeResponse resp = do
  r <- E.tryJust syncExceptions
                 (E.evaluate $!! runGet getResponse (L.fromChunks [resp]))
  return $ either (const Nothing) Just r
  where
    getResponse = do
      0 <- getWord8
      cd <- getWord8
      let res = case cd of
            90 -> Granted
            91 -> Failed
            92 -> IdentdUnreachable
            93 -> IdentdMismatch
            _  -> error "unknown socks4 result code"
      port <- get
      addr <- get
      return $! Response res addr port

--------------------------------------------------------------------------------
-- Errors

-- | A Socks error.
data SocksError
  = SocksError {-# UNPACK #-} !Result -- ^ A known Socks error code.
  | SocksProtocolError -- ^ The response doesn't follow the Socks protocol.
  deriving Typeable

instance Show SocksError where
  showsPrec _ (SocksError result) = cat "Socks error: " result
  showsPrec _ SocksProtocolError  = cat "Socks protocol error"

-- | Boilerplate conversion of a dynamically typed 'SocksError' to a string.
showSocksError :: Dynamic -> Maybe String
showSocksError = fmap (show :: SocksError -> String) . fromDynamic
