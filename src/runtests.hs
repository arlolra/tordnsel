-----------------------------------------------------------------------------
-- |
-- Module      : Main
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- Unit tests.
--
-----------------------------------------------------------------------------

-- #hide
module Main (main) where

import Test.HUnit (runTestTT, Test(..))

import qualified TorDNSEL.Config.Tests as Config
import qualified TorDNSEL.Directory.Tests as Directory
import qualified TorDNSEL.DNS.Tests as DNS
import qualified TorDNSEL.DNS.Handler.Tests as DNS.Handler

main = runTestTT . TestList $
  [Config.tests, Directory.tests, DNS.tests, DNS.Handler.tests]
