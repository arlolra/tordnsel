-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Handler
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards)
--
-- Handling DNS queries for exit list information.
--
-----------------------------------------------------------------------------

module TorDNSEL.DNS.Handler (DNSConfig(..), dnsHandler, ttl) where

import TorDNSEL.DNS.Handler.Internals
