-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Log
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             type synonym instances)
--
-- Implements a logger thread and functions to log messages, reconfigure the
-- logger, and terminate the logger.
--
-----------------------------------------------------------------------------

module TorDNSEL.Log (
    LogConfig(..)
  , LogTarget(..)
  , Severity(..)
  , LogType
  , log
  , startLogger
  , reconfigureLogger
  , terminateLogger
  ) where

import Prelude hiding (log)
import TorDNSEL.Log.Internals
