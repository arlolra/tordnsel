-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitTest.Initiator
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, STM, extended exceptions,
--                             pattern guards, rank-2 types, GHC primitives)
--
-- A thread that initiates test connections through exit nodes to determine the
-- IP addresses they exit through.
--
-----------------------------------------------------------------------------

module TorDNSEL.ExitTest.Initiator (
    ExitTestInitiator
  , ExitTestInitiatorConfig(..)
  , startExitTestInitiator
  , notifyNewDirInfo
  , scheduleNextExitTest
  , reconfigureExitTestInitiator
  , terminateExitTestInitiator
  ) where

import TorDNSEL.ExitTest.Initiator.Internals
