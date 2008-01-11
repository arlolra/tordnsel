-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Statistics
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (GHC primitives)
--
-- Making load information available external to the process.
--
-----------------------------------------------------------------------------

module TorDNSEL.Statistics (
    StatsConfig(..)
  , StatsServer
  , startStatsServer
  , reconfigureStatsServer
  , terminateStatsServer
  , incrementBytes
  , incrementResponses
  ) where

import TorDNSEL.Statistics.Internals
