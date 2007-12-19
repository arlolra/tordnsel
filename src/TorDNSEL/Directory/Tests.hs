{-# OPTIONS_GHC -fglasgow-exts #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Directory.Tests
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (GHC primitives)
--
-- Directory tests.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.Directory.Tests (tests) where

import qualified Data.ByteString.Char8 as B
import Test.HUnit (Test(..), (@=?))

import TorDNSEL.Directory.Internals
import TorDNSEL.Document
import TorDNSEL.Util

tests = TestList [TestCase descriptorParses, fingerprint, TestCase exitPolicy]

exitPolicy = do
  let Just [ip1,ip2,ip3] = mapM (inet_atoh . B.pack) ips
      Just policy = parseExitPolicy $ parseDocument doc
  False @=? exitPolicyAccepts ip1 80 policy
  False @=? exitPolicyAccepts ip2 80 policy
  True @=? exitPolicyAccepts ip3 81 policy
  where
    ips = ["192.169.64.11","192.168.64.11","18.244.0.188"]
    doc = map B.pack ["reject *:80","accept 18.244.0.18:*"]

fingerprint = TestList . map TestCase $
  [ Just rid @=? decodeBase16RouterID base16
  , Just rid @=? decodeBase64RouterID base64
  , base16 @=? encodeBase16RouterID rid ]
  where
    base16 = b 40 "ffcb46db1339da84674c70d7cb586434c4370441"#
    base64 = b 27 "/8tG2xM52oRnTHDXy1hkNMQ3BEE"#
    rid = RtrId $ b 20 "\255\203\70\219\19\57\218\132\103\76\112\
                        \\215\203\88\100\52\196\55\4\65"#

descriptorParses =
  "[Right " ++ parsed ++ ",Right " ++ parsed ++ "]" @=? parse descriptor
  where
    parse = show . parseDescriptors . parseDocument . concat . replicate 2
    parsed =
      "41f0476c9cf03f2e233218bdff8ac1ae981533e0 128.2.141.33 2007-03-31 \
      \21:34:31 UTC\n\
      \Reject 0.0.0.0/0.0.0.0:22-22\n\
      \Reject 0.0.0.0/0.0.0.0:1433-1433\n\
      \Reject 0.0.0.0/255.0.0.0:0-65535\n\
      \Reject 169.254.0.0/255.255.0.0:0-65535\n\
      \Reject 127.0.0.0/255.0.0.0:0-65535\n\
      \Reject 192.168.0.0/255.255.0.0:0-65535\n\
      \Reject 10.0.0.0/255.0.0.0:0-65535\n\
      \Reject 172.16.0.0/255.240.0.0:0-65535\n\
      \Reject 0.0.0.0/0.0.0.0:25-25\n\
      \Reject 0.0.0.0/0.0.0.0:119-119\n\
      \Reject 0.0.0.0/0.0.0.0:135-139\n\
      \Reject 0.0.0.0/0.0.0.0:445-445\n\
      \Reject 0.0.0.0/0.0.0.0:465-465\n\
      \Reject 0.0.0.0/0.0.0.0:587-587\n\
      \Reject 0.0.0.0/0.0.0.0:1214-1214\n\
      \Reject 0.0.0.0/0.0.0.0:4661-4666\n\
      \Reject 0.0.0.0/0.0.0.0:6346-6429\n\
      \Reject 0.0.0.0/0.0.0.0:6699-6699\n\
      \Reject 0.0.0.0/0.0.0.0:6881-6999\n\
      \Reject 18.244.0.188/255.255.255.255:0-65535\n\
      \Reject 18.244.0.0/255.255.0.0:0-65535\n\
      \Reject 2.0.0.0/2.2.2.2:80-80\n\
      \Reject 192.168.0.0/255.255.0.0:22-25\n\
      \Accept 0.0.0.0/0.0.0.0:0-65535\n"

descriptor = map B.pack . lines $
  "router err 128.2.141.33 9001 0 9030\n\
  \platform Tor 0.1.0.17 on FreeBSD i386\n\
  \published 2007-03-31 21:34:31\n\
  \opt fingerprint 41F0 476C 9CF0 3F2E 2332 18BD FF8A C1AE 9815 33E0\n\
  \uptime 17107892\n\
  \bandwidth 655360 5242880 1058812\n\
  \onion-key\n\
  \-----BEGIN RSA PUBLIC KEY-----\n\
  \MIGJAoGBAKNBq+8CxyPIDsGGonsp9OBMNmC94eQUTTPlVGMDxRV0qFfzYtovz57X\n\
  \7npYyzWlsU3weEKUqk3+UYmyS+U06EI9+Etz7vhVXe356zd5k3fkYPjGUXU45bj8\n\
  \+OcYhApzvX/j6fRwapsQk7S8RZqfO77NaKQ85D/7qeRE9hCsvMRhAgMBAAE=\n\
  \-----END RSA PUBLIC KEY-----\n\
  \signing-key\n\
  \-----BEGIN RSA PUBLIC KEY-----\n\
  \MIGJAoGBAKxqBfUbMpMJlVKtYD1QAM7UPF2Hw1MicwC9zjw26aZy/UUDmao8k19y\n\
  \OqWCU6XXSb7tCOoYDZFSWFIppicheEsmfECedmVaLEUbErk91TDvRRb7+kiEKct5\n\
  \ytGnGdfhMCYtYKXzsLfSIugEvMFD2NnBruXkElcMUEh14SiXcKcDAgMBAAE=\n\
  \-----END RSA PUBLIC KEY-----\n\
  \opt write-history 2007-03-31 21:22:58 (900 s) 578066987,587622813,584835445,\
  \585201742,583211095,586682433,583562316,584206429,582016504,587287646,\
  \582824061,580548866,590060637,585749427,583572871,583131506,575793840,\
  \584378396,584858249,586256553,585316361,582975382,585566000,581052747,\
  \588428807,588500251,585015083,582672236,589143715,583398130,585325958,\
  \581557976,587611801,586869163,577796929,580764308,576024953,575814158,\
  \581489264,577220925,580617597,580494023,577898711,581044860,582480308,\
  \586770246,585741144,585112466,578520932,589939305,585118500,581594211,\
  \584314299,586802619,585424813,588355421,581204276,586667140,580343006,\
  \574772982,578801170,572328358,577198014,581826945,584808492,579516723,\
  \582360193,579688773,588133393,586554075,583320577,580513818,585804666,\
  \587476584,584928993,587470441,581390632,587168041,580638174,577111850,\
  \556641250,566782715,567894740,582289206,587447049,585628823,585015986,\
  \583607829,582999559,588123116,582090786,585689862,584317240,585496760,\
  \586431179,584636699\n\
  \opt read-history  2007-03-31 21:22:58 (900 s) 588538109,583787270,584790398,\
  \585815935,582849016,586020989,584538527,584364009,585132020,584593814,\
  \583913463,579796976,588724452,585225708,584576947,583925760,584581120,\
  \584581120,583927107,583470806,584929234,586013155,582995684,585994885,\
  \583863376,586918848,586141820,584504579,585777315,572326730,588758861,\
  \584584423,583042876,584650910,588014788,583925624,584590996,584568943,\
  \583928826,583923603,583924851,584587209,583933139,583913069,584580343,\
  \584635188,583801885,585864769,584677998,585274294,582737669,587055654,\
  \584940084,586157113,581114030,583691821,574164042,588116573,584041691,\
  \583932984,583917816,584584538,570829358,587858639,583923787,584178524,\
  \583659303,583927832,583493567,586299024,585259417,583930733,584487500,\
  \585325127,583831156,585099111,581674496,585904120,585755796,583916625,\
  \583926055,584588480,583257441,583929009,581410903,586798516,582247162,\
  \587301864,584134617,585798361,585028528,584081569,585513948,583263200,\
  \584122227,587115385\n\
  \contact Serge Egelman <egelman@cs.cmu.edu>\n\
  \reject *:22\n\
  \reject *:1433\n\
  \reject 0.0.0.0/255.0.0.0:*\n\
  \reject 169.254.0.0/255.255.0.0:*\n\
  \reject 127.0.0.0/255.0.0.0:*\n\
  \reject 192.168.0.0/255.255.0.0:*\n\
  \reject 10.0.0.0/255.0.0.0:*\n\
  \reject 172.16.0.0/255.240.0.0:*\n\
  \reject *:25\n\
  \reject *:119\n\
  \reject *:135-139\n\
  \reject *:445\n\
  \reject *:465\n\
  \reject *:587\n\
  \reject *:1214\n\
  \reject *:4661-4666\n\
  \reject *:6346-6429\n\
  \reject *:6699\n\
  \reject *:6881-6999\n\
  \reject 18.244.0.188:*\n\
  \reject 18.244.0.188/16:*\n\
  \reject 18.244.0.188/2.2.2.2:80\n\
  \reject 192.168.0.1/255.255.00.0:22-25\n\
  \accept *:*\n\
  \router-signature\n\
  \-----BEGIN SIGNATURE-----\n\
  \ZU5RMHBifs+wm0DAouBbp/5u6eI3z+WeI3VGSxc7XMC0mInYY+GUPSl0GYqxQEOs\n\
  \4qonLxMM7g98hWs3jDyV81iSLbzlx22COYag5mDNLSdjRNfaE+b3Z8nYYzQsqDJm\n\
  \A7sL/7x8hhU9xnDCfFyjzkL1XfZHxBIiASfksNyuoiU=\n\
  \-----END SIGNATURE-----"
