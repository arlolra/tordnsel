{-# LANGUAGE CPP #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Compat.Exception
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, bang patterns, concurrency,
--                             STM, FFI)
--
-- Ensure compatibility between several GHC versions on exception handling.
--
-----------------------------------------------------------------------------

module TorDNSEL.Compat.Exception (
    module Exception
  ) where

#if __GLASGOW_HASKELL__ == 610
import Control.OldException as Exception
#else
import Control.Exception as Exception
#endif
