-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Server
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards)
--
-- Implements a DNS server thread that answers DNS queries for exit list
-- information.
--
-----------------------------------------------------------------------------

module TorDNSEL.DNS.Server (
    DNSConfig(..)
  , ResponseType(..)
  , bindUDPSocket
  , DNSServer
  , startDNSServer
  , reconfigureDNSServer
  , terminateDNSServer
  , ttl
  ) where

import TorDNSEL.DNS.Server.Internals
