-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitTest.Server
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions, pattern guards,
--                             bang patterns, GHC primitives)
--
-- A thread that accepts test connections we have initiated through exit nodes
-- to determine the IP addresses exit nodes make connections through.
--
-----------------------------------------------------------------------------

module TorDNSEL.ExitTest.Server (
    ExitTestServer
  , ExitTestServerConfig(..)
  , startExitTestServer
  , reconfigureExitTestServer
  , terminateExitTestServer
  ) where

import TorDNSEL.ExitTest.Server.Internals
