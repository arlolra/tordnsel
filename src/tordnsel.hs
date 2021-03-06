-----------------------------------------------------------------------------
-- |
-- Module      : Main
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, STM, extended exceptions,
--                             pattern guards, FFI, GHC primitives)
--
-- Implements a DNSBL-style interface providing information about whether a
-- client for a network service is likely connecting through a Tor exit node.
--
-- See <https://gitweb.torproject.org/tordnsel.git/tree/doc/torel-design.txt> for
-- details.
--
-----------------------------------------------------------------------------

module Main (main) where

import TorDNSEL.Main
