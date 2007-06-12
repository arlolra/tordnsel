{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Socks.Internals
-- Copyright   : (c) tup 2007
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
-- See <https://tor.eff.org/svn/trunk/doc/spec/socks-extensions.txt> for
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
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.Typeable (Typeable)
import Network.Socket (HostAddress, Socket, socketToHandle)
import System.IO
  ( Handle, IOMode(ReadWriteMode), BufferMode(NoBuffering)
  , hClose, hSetBuffering )

import Data.Binary (Binary(..), getWord8, putWord8, Word16)
import Data.Binary.Get (runGet)
import Data.Binary.Put (runPut, putByteString)

import TorDNSEL.DeepSeq

--------------------------------------------------------------------------------
-- Connections

-- | Open a Socks connection to an IP address\/domain name and port. The handle
-- will be closed if an exception occurs during the given 'IO' action. Throw a
-- 'SocksError' if the connection request fails.
withSocksConnection
  :: Socket -> ByteString -> Word16 -> (Handle -> IO a) -> IO a
withSocksConnection sock domain port io =
  E.bracket (socketToHandle sock ReadWriteMode) hClose $ \handle -> do
    hSetBuffering handle NoBuffering
    B.hPut handle . encodeRequest $ Request Connect (Right domain) port
    r <- decodeResponse =<< B.hGet handle 8
    case r of
      Just (Response Granted _ _) -> io handle
      Just (Response result _ _)  -> E.throwDyn (SocksError result)
      _                           -> E.throwDyn SocksProtocolError

--------------------------------------------------------------------------------
-- Data types

-- | A Socks4a request.
data Request = Request
  { -- | The Socks4 command code (with Tor extensions).
    soCommand :: {-# UNPACK #-} !Command,
    -- | The requested destination: either an IPv4 address or a domain name.
    soReqDest :: {-# UNPACK #-} !(Either HostAddress ByteString),
    -- | The requested destination port.
    soReqPort :: {-# UNPACK #-} !Word16 }

-- A Socks4a command (with Tor extensions).
data Command
  = Connect    -- ^ Connect to the requested destination.
  | Resolve    -- ^ Resolve a domain name.
  | ConnectDir -- ^ Establish a secure connection to a Tor directory.

-- | A Socks4 response.
data Response = Response
  { soResult   :: {-# UNPACK #-} !Result      -- ^ The result code.
  , soRespAddr :: {-# UNPACK #-} !HostAddress -- ^ The destination address.
  , soRespPort :: {-# UNPACK #-} !Word16      -- ^ The destination port.
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
      put $ either id (const 1) (soReqDest req)
      putWord8 0
      case soReqDest req of
        Right domain -> putByteString domain >> putWord8 0
        _            -> return ()

-- | Decode a Socks4 response.
decodeResponse :: ByteString -> IO (Maybe Response)
decodeResponse resp = do
  r <- E.try (E.evaluate $!! runGet getResponse (L.fromChunks [resp]))
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
  showsPrec _ (SocksError result) = shows "Socks error: " . shows result
  showsPrec _ SocksProtocolError  = shows "Socks protocol error"
