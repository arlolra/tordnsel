-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Log
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             type synonym instances, overlapping instances,
--                             foreign function interface)
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
  , Logger
  , startLogger
  , reconfigureLogger
  , terminateLogger
  , SysLogOptions(..)
  , SysLogFacility(..)
  , openSystemLogger
  , closeSystemLogger
  ) where

import Prelude hiding (log)
import TorDNSEL.Log.Internals
