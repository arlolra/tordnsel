-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Tests
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (imprecise exceptions)
--
-- DNS tests.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.DNS.Tests (tests) where

import Control.Monad (replicateM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base as B
import qualified Data.ByteString.Lazy as L
import Test.HUnit (Test(..), (@=?))

import Data.Binary.Get (runGet, skip)

import TorDNSEL.DNS.Internals

tests = TestList . map TestCase $
  [ (Just q @=?) =<< decodeMessage query
  , (Just r @=?) =<< decodeMessage aResponse
  , (Just r' @=?) =<< decodeMessage soaResponse
  , (Just nsr @=?) =<< decodeMessage nsResponse
  , (Nothing @=?) =<< decodeMessage cyclicPtrs
  , (Nothing @=?) =<< decodeMessage cyclicPtrs'
  , query @=? encodeMessage q
  , aResponse @=? encodeMessage r
  , soaResponse @=? encodeMessage (unsafeDecodeMessage soaResponse)
  , nsResponse @=? encodeMessage (unsafeDecodeMessage nsResponse)
  , compNames' @=? compNames
  , decompNames' @=? decompNames ]

q = Message 0x8eba False StandardQuery False False True False False False
      NoError (Question name TA IN) [] [] []

r = Message 0x8eba True StandardQuery False False True True False False
      NoError (Question name TA IN) [ A name 223 0xd86d7087
                                    , A name 223 0x425eea0d ] [] []

r' = Message 0x8eba True StandardQuery False False True True False False
       NXDomain (Question name' TA IN) []
       [ SOA (toName ["dnsbl","sorbs","net"]) 829
             (toName ["rbldns0","sorbs","net"])
             (toName ["dns","isux","com"]) 1180727520 7200 7200 604800 3600 ] []

nsr = Message 0x8eba True StandardQuery True False False False False False
        NoError (Question exitlist TA IN)
        [A exitlist 1800 0x7f000001] [NS exitlist 1800 exitlistNS] []
  where
    exitlist = toName ["exitlist","torproject","org"]
    exitlistNS = toName ["exitlist-ns","torproject","org"]

name = toName ["yahoo","com"]
name' = toName ["1","0","0","127","dnsbl","sorbs","net"]

decompNames = runGet (skip 12 >> replicateM 4 (getPacket (Packet compNames)))
                     (L.fromChunks [compNames])

decompNames' = [name1, name2, name3, name4]

compNames = B.replicate 12 0 `B.append` B.concat [b1,b2,b3,b4]
  where
    len = sum . map B.length
    (b1,t1) = compressName 12 name1 emptyTargetMap
    (b2,t2) = compressName (B.length b1) name2 t1
    (b3,t3) = compressName (len [b1,b2]) name3 t2
    (b4,_) = compressName (len [b1,b2,b3]) name4 t3

compNames' = B.pack . map B.c2w $
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
  \\x03\x77\x77\x77\x05\x79\x61\x68\x6f\x6f\x03\x63\x6f\x6d\
  \\x00\x04\x6d\x61\x69\x6c\xc0\x10\x04\x6d\x61\x69\x6c\x06\
  \\x67\x6f\x6f\x67\x6c\x65\xc0\x16\xc0\x0c"

name1 = toName ["www","yahoo","com"]
name2 = toName ["mail","yahoo","com"]
name3 = toName ["mail","google","com"]
name4 = toName ["www","yahoo","com"]

toName = DomainName . map (Label . B.pack . map B.c2w)

query = toPacket $
  "\x8e\xba\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x79\
  \\x61\x68\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

aResponse = toPacket $
  "\x8e\xba\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x05\x79\
  \\x61\x68\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\
  \\x0c\x00\x01\x00\x01\x00\x00\x00\xdf\x00\x04\xd8\x6d\x70\
  \\x87\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xdf\x00\x04\x42\
  \\x5e\xea\x0d"

soaResponse = toPacket $
  "\x8e\xba\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00\x01\x31\
  \\x01\x30\x01\x30\x03\x31\x32\x37\x05\x64\x6e\x73\x62\x6c\
  \\x05\x73\x6f\x72\x62\x73\x03\x6e\x65\x74\x00\x00\x01\x00\
  \\x01\xc0\x16\x00\x06\x00\x01\x00\x00\x03\x3d\x00\x2c\x07\
  \\x72\x62\x6c\x64\x6e\x73\x30\xc0\x1c\x03\x64\x6e\x73\x04\
  \\x69\x73\x75\x78\x03\x63\x6f\x6d\x00\x46\x60\x78\xe0\x00\
  \\x00\x1c\x20\x00\x00\x1c\x20\x00\x09\x3a\x80\x00\x00\x0e\
  \\x10"

nsResponse = toPacket $
  "\x8e\xba\x84\x00\x00\x01\x00\x01\x00\x01\x00\x00\x08\x65\
  \\x78\x69\x74\x6c\x69\x73\x74\x0a\x74\x6f\x72\x70\x72\x6f\
  \\x6a\x65\x63\x74\x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\
  \\x0c\x00\x01\x00\x01\x00\x00\x07\x08\x00\x04\x7f\x00\x00\
  \\x01\xc0\x0c\x00\x02\x00\x01\x00\x00\x07\x08\x00\x0e\x0b\
  \\x65\x78\x69\x74\x6c\x69\x73\x74\x2d\x6e\x73\xc0\x15"

cyclicPtrs = toPacket $
  "\x8e\xba\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\xc0\x12\
  \\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01"

cyclicPtrs' = toPacket $
  "\x8e\xba\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01\x61\
  \\xc0\x0c"

toPacket = Packet . B.pack . map B.c2w
