-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Config.Tests
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- Config tests.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.Config.Tests (tests) where

import Control.Arrow ((***))
import Data.Char (toLower)
import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import Test.HUnit (Test(..), (@=?))

import TorDNSEL.Config.Internals

tests = TestList . map TestCase $
  [ Just config @=? parseConfigFile configFile
  , Just config' @=? parseConfigArgs configArgs ]

config' = toConfig
  [ "User"       ~> "nobody"
  , "ConfigFile" ~> "/etc/tordnsel.conf" ]

configArgs = ["--User", "nobody", "-f", "/etc/tordnsel.conf"]

config = toConfig
  [ "AuthoritativeZone"      ~> "exitlist.example.com."
  , "DomainName"             ~> "exitlist-ns.example.com."
  , "Address"                ~> "18.0.0.1"
  , "SOARName"               ~> "hostmaster.example.com."
  , "ChangeRootDirectory"    ~> "/var/lib/tordnsel"
  , "EnableActiveTesting"    ~> "True"
  , "DNSListenAddress"       ~> "127.0.0.1:53"
  , "Group"                  ~> "tordnsel"
  , "PIDFile"                ~> "/var/run/tordnsel.pid"
  , "RunAsDaemon"            ~> "True"
  , "StateDirectory"         ~> "/state"
  , "TestDestinationAddress" ~> "18.0.0.1:80,443,110,53,22,5190,6667,9030"
  , "TestListenAddress"      ~> "10.0.0.1:80,443,110,53,22,5190,6667,9030"
  , "TorControlAddress"      ~> "127.0.0.1:9051"
  , "TorControlPassword"     ~> "password"
  , "TorSocksAddress"        ~> "127.0.0.1:9050"
  , "User"                   ~> "tordnsel" ]

configFile = B.pack
  "## Answer queries authoritatively for this DNS zone. For example, if this\n\
  \## is set to \"exitlist.example.com.\", your server would accept queries of\n\
  \## the form \"1.0.0.10.80.4.3.2.1.ip-port.exitlist.example.com.\". This\n\
  \## option is required.\n\
  \AuthoritativeZone exitlist.example.com.\n\
  \\n\
  \## This name server's own domain name, for use in NS and SOA records. This\n\
  \## option is required.\n\
  \DomainName exitlist-ns.example.com.\n\
  \\n\
  \## The IP address that will be returned in response to requests for the A\n\
  \## record matching our authoritative zone. If you don't specify this\n\
  \## option, no A record will be returned for the authoritative zone.\n\
  \Address 18.0.0.1\n\
  \\n\
  \## Use this email address in the RNAME field of SOA records. Usually, this\n\
  \## should be something like \"hostmaster@example.com\" in the form of a\n\
  \## fully-qualified domain name. This option is required.\n\
  \SOARName hostmaster.example.com.\n\
  \\n\
  \## Bind the name server to this IP address and UDP port. If you want to\n\
  \## bind to all interfaces, you might set the address to \"0.0.0.0\". This\n\
  \## port is bound before dropping privileges. Leave it commented to use the\n\
  \## default.\n\
  \DNSListenAddress 127.0.0.1:53\n\
  \\n\
  \## Make Tor controller connections to this IP address and TCP port. You'll\n\
  \## need to set this as your ControlListenAddress or ControlPort in Tor's\n\
  \## torrc. Leave it commented to use the default.\n\
  \TorControlAddress 127.0.0.1:9051\n\
  \\n\
  \## Detach from the controlling terminal and run in the background as a\n\
  \## daemon. The default is \"False\".\n\
  \RunAsDaemon True\n\
  \\n\
  \## The password you used to generate the HashedControlPassword in Tor's\n\
  \## torrc. This is only required when you have a HashedControlPassword.\n\
  \TorControlPassword password\n\
  \\n\
  \## The user name to which you want to drop privileges. This option requires\n\
  \## root privileges.\n\
  \User tordnsel\n\
  \\n\
  \## The group name to which you want to drop privileges. This option also\n\
  \## requires root privileges.\n\
  \Group tordnsel\n\
  \\n\
  \## Call chroot(2) to change our root directory. This option also requires\n\
  \## root privileges.\n\
  \ChangeRootDirectory /var/lib/tordnsel\n\
  \\n\
  \## Write our PID to the specified file before chrooting or dropping\n\
  \## privileges. This file won't be removed on exit.\n\
  \PIDFile /var/run/tordnsel.pid\n\
  \\n\
  \## Enable active test connections through exit nodes to determine their\n\
  \## exit IP addresses. The default is \"False\".\n\
  \EnableActiveTesting True\n\
  \\n\
  \## Store exit test results in this directory. This should be an absolute\n\
  \## path accessible inside the chroot (if one is configured).\n\
  \##\n\
  \## This example assumes you've specified ChangeRootDirectory.\n\
  \StateDirectory /state\n\
  \\n\
  \## Make exit test connections through Tor's SocksPort on this IP address\n\
  \## and TCP port. Leave it commented to use the default.\n\
  \TorSocksAddress 127.0.0.1:9050\n\
  \\n\
  \## Bind the exit test listeners to this IP address and these TCP ports.\n\
  \## These ports are bound before dropping privileges. Don't use the loopback\n\
  \## interface for TestListenAddress if you're redirecting connections with\n\
  \## iptables because your redirected packets will be dropped as martians.\n\
  \## This option is only required when EnableActiveTesting is specified.\n\
  \TestListenAddress 10.0.0.1:80,443,110,53,22,5190,6667,9030\n\
  \\n\
  \## Make exit test connections to this IP address and these TCP ports. These\n\
  \## should be publicly accessible from Tor exit nodes. This option is only\n\
  \## required when EnableActiveTesting is specified.\n\
  \TestDestinationAddress 18.0.0.1:80,443,110,53,22,5190,6667,9030"

toConfig = M.fromList . map ((B.pack . map toLower) *** B.pack)

(~>) = (,)
