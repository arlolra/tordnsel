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

import qualified Data.ByteString as B
import qualified Data.ByteString.Base as B
import Test.HUnit (Test(..), (@=?))

import TorDNSEL.DNS.Internals

tests = TestList . map TestCase $
  [ decodeMessage dnsQuery >>= (@=? Just q)
  , decodeMessage dnsResponse >>= (@=? Just r)
  , decodeMessage circularPtrs >>= (@=? Nothing)
  , decodeMessage circularPtrs' >>= (@=? Nothing)
  , encodeMessage q @=? dnsQuery
  , encodeMessage r @=? dnsResponse' ]

q = Message 0x8eba Query StandardQuery False False True False NoError
      (Question name A IN) []

r = Message 0x8eba Response StandardQuery False False True True NoError
      (Question name A IN) [ Answer name 223 0xd86d7087
                           , Answer name 223 0x425eea0d ]

name = DomainName $ map (Label . B.pack . map B.c2w) ["yahoo","com"]

dnsQuery = Packet . B.pack . map B.c2w $
  "\x8e\xba\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x79\
  \\x61\x68\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

dnsResponse = Packet . B.pack . map B.c2w $
  "\x8e\xba\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x05\x79\
  \\x61\x68\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\
  \\x0c\x00\x01\x00\x01\x00\x00\x00\xdf\x00\x04\xd8\x6d\x70\
  \\x87\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xdf\x00\x04\x42\
  \\x5e\xea\x0d"

dnsResponse' = Packet . B.pack . map B.c2w $
  "\x8e\xba\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x05\x79\x61\
  \\x68\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x05\x79\x61\
  \\x68\x6f\x6f\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x00\
  \\xdf\x00\x04\xd8\x6d\x70\x87\x05\x79\x61\x68\x6f\x6f\x03\x63\
  \\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x00\xdf\x00\x04\x42\x5e\
  \\xea\x0d"

circularPtrs = Packet . B.pack . map B.c2w $
  "\x8e\xba\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\xc0\x12\
  \\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01"

circularPtrs' = Packet . B.pack . map B.c2w $
  "\x8e\xba\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01\x61\xc0\x0c"
