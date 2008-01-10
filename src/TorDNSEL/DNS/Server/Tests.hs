-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Server.Tests
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- DNS handler tests.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.DNS.Server.Tests (tests) where

import qualified Data.ByteString.Char8 as B
import Test.HUnit (Test(..), (@=?))

import TorDNSEL.DNS
import TorDNSEL.DNS.Server.Internals
import TorDNSEL.NetworkState
import TorDNSEL.Util

tests = TestList . map TestCase $
  [ dropAuthZone authZone queryName @=? Just query
  , parseExitListQuery query @=? query' ]
  where
    query = toLabels ["ip-port","1","2","3","4","80","10","0","0","1"]
    queryName = toName [ "1","0","0","10","80","4","3","2","1"
                       ,"ip-port","torhosts","example","com" ]
    authZone = DomainName $ map (Label . B.pack) ["com","example","torhosts"]
    toLabels = map $ Label . B.pack
    toName = DomainName . toLabels
    query' = do
      qAddr <- inet_atoh $ B.pack "10.0.0.1"
      dAddr <- inet_atoh $ B.pack "1.2.3.4"
      return $ IPPort { queryAddr = qAddr, destAddr = dAddr, destPort = 80 }
