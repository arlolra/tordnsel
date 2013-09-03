-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Socks
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (dynamic exceptions, newtype deriving)
--
-- Making a TCP connection using the SOCKS4A protocol. Support for various
-- Tor extensions to SOCKS is sketched out.
--
-- See <https://www.torproject.org/svn/trunk/doc/spec/socks-extensions.txt> for
-- details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Socks (
  -- * Connections
    withSocksConnection

  -- * Errors
  , SocksError(..)
  ) where

import TorDNSEL.Socks.Internals
