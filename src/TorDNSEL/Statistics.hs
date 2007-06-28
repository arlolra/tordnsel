-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Statistics
-- Copyright   : (c) tup 2007
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
    StatsHandle
  , openStatsListener
  , unlinkStatsSocket
  , incrementBytes
  , incrementResponses
  ) where

import TorDNSEL.Statistics.Internals
