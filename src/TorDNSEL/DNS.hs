-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (imprecise exceptions, pattern guards)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Decoding and encoding the subset of DNS necessary for running a DNSBL
-- server.
--
-- See RFC 1035 and RFC 2308 for details.
--
-----------------------------------------------------------------------------

module TorDNSEL.DNS (
    -- * I\/O
    runServer
  , recvMessageFrom
  , sendMessageTo

  -- * Data types
  , Message(..)
  , Question(..)
  , ResourceRecord(..)
  , DomainName(..)
  , Label(..)
  , RCode(..)
  , OpCode(..)
  , Type(..)
  , Class(..)
  ) where

import TorDNSEL.DNS.Internals
