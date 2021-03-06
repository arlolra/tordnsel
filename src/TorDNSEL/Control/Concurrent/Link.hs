-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Control.Concurrent.Link
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             pattern guards)
--
-- Implements linked threads and monitors for error handling, attempting to
-- closely reproduce their behavior in Erlang.
--
-- Based on Joe Armstrong's /Making reliable distributed systems in the
-- presence of software errors/.
-- <http://www.sics.se/~joe/thesis/armstrong_thesis_2003.pdf>
--
-----------------------------------------------------------------------------

module TorDNSEL.Control.Concurrent.Link (
    ThreadId
  , myThreadId
  , withLinksDo
  , forkIO
  , forkLinkIO
  , linkThread
  , unlinkThread
  , monitorThread
  , demonitorThread
  , withMonitor
  , exit
  , throwTo
  , killThread
  , setTrapExit
  , unsetTrapExit
  , ExitReason(..)
  , exitReason
  , isAbnormal
  , throwAbnormal
  , extractReason
  , fromExitSignal
  , LinkException(..)
  ) where

import TorDNSEL.Control.Concurrent.Link.Internals
