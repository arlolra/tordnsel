{-# LANGUAGE OverloadedStrings  #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Config.Tests
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
  , "ConfigFile" ~> "/srv/tordnsel/tordnsel.conf" ]

configArgs = ["--User", "nobody", "-f", "/srv/tordnsel/tordnsel.conf"]

config = toConfig
  [ "ZoneOfAuthority"        ~> "exitlist.example.com."
  , "DomainName"             ~> "exitlist-ns.example.com."
  , "SOARName"               ~> "hostmaster.example.com."
  , "StateDirectory"         ~> "/state/"
  , "RuntimeDirectory"       ~> "/srv/tordnsel/run/"
  , "DNSListenAddress"       ~> "127.0.0.1:53"
  , "Address"                ~> "10.0.0.1"
  , "TorControlAddress"      ~> "127.0.0.1:9051"
  , "TorControlPassword"     ~> "password"
  , "Log"                    ~> "notice file /srv/tordnsel/log/"
  , "RunAsDaemon"            ~> "True"
  , "User"                   ~> "tordnsel"
  , "Group"                  ~> "tordnsel"
  , "ChangeRootDirectory"    ~> "/srv/tordnsel/"
  , "PIDFile"                ~> "/srv/tordnsel/run/tordnsel.pid"
  , "EnableActiveTesting"    ~> "True"
  , "TorSocksAddress"        ~> "127.0.0.1:9050"
  , "TestListenAddress"      ~> "10.0.0.1:80,443,110,53,22,5190,6667,9030"
  , "TestDestinationAddress" ~> "10.0.0.1:80,443,110,53,22,5190,6667,9030" ]

configFile =
  "## torndsel.conf.sample\n\
  \## Sample configuration file for TorDNSEL.\n\
  \\n\
  \################ Required options #########################################\n\
  \##\n\
  \## These options have no default values. They must be uncommented and\n\
  \## changed for your system.\n\
  \\n\
  \## Answer queries authoritatively for this DNS zone. For example, if this\n\
  \## is set to \"exitlist.example.com.\", your server would accept queries of\n\
  \## the form \"1.0.0.10.80.4.3.2.1.ip-port.exitlist.example.com.\".\n\
  \ZoneOfAuthority exitlist.example.com.\n\
  \\n\
  \## This name server's own domain name, for use in NS and SOA records.\n\
  \DomainName exitlist-ns.example.com.\n\
  \\n\
  \## Use this email address in the RNAME field of SOA records. Usually, this\n\
  \## should be something like \"hostmaster@example.com\" in the form of a\n\
  \## fully-qualified domain name. This option is required.\n\
  \SOARName hostmaster.example.com.\n\
  \\n\
  \## Store exit test results in this directory. This should be an absolute\n\
  \## path accessible inside the chroot (if one is configured).\n\
  \#StateDirectory /srv/tordnsel/state/\n\
  \## This line is equivalent to the previous line if you've specified\n\
  \## ChangeRootDirectory as /srv/tordnsel/.\n\
  \StateDirectory /state/\n\
  \\n\
  \## Place the statistics and reconfigure sockets in this directory before\n\
  \## chrooting or dropping privileges.\n\
  \RuntimeDirectory /srv/tordnsel/run/\n\
  \\n\
  \################ Optional options #########################################\n\
  \##\n\
  \## These options either have sensible default values or can be left\n\
  \## unspecifed. You will probably need to uncomment and change some of\n\
  \## these.\n\
  \\n\
  \## Bind the name server to this IP address and UDP port. If you want to\n\
  \## bind to all interfaces, you might set the address to \"0.0.0.0\". This\n\
  \## port is bound before dropping privileges. Leave it commented to use the\n\
  \## default.\n\
  \DNSListenAddress 127.0.0.1:53\n\
  \\n\
  \## The IP address that will be returned in response to requests for the A\n\
  \## record matching our zone of authority. If you don't specify this option,\n\
  \## no A record will be returned for the zone of authority.\n\
  \Address 10.0.0.1\n\
  \\n\
  \## Make Tor controller connections to this IP address and TCP port. You'll\n\
  \## need to set this as your ControlListenAddress or ControlPort in Tor's\n\
  \## torrc. Leave it commented to use the default.\n\
  \TorControlAddress 127.0.0.1:9051\n\
  \\n\
  \## The password you used to generate the HashedControlPassword in Tor's\n\
  \## torrc. This is only required when you have a HashedControlPassword.\n\
  \TorControlPassword password\n\
  \\n\
  \## Send log messages of at least a minimum severity to a specified stream,\n\
  \## to the system logger, or to a file. Valid severity levels are debug,\n\
  \## info, notice, warn, and error. If you specify a log file, it should\n\
  \## be accessible from inside the chroot (if one is configured), and\n\
  \## writable after dropping privileges. This may only be specified once. The\n\
  \## default is \"notice stdout\".\n\
  \#Log notice stdout\n\
  \#Log info stderr\n\
  \#Log warn syslog\n\
  \Log notice file /srv/tordnsel/log/\n\
  \\n\
  \## Detach from the controlling terminal and run in the background as a\n\
  \## daemon. The default is \"False\".\n\
  \RunAsDaemon True\n\
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
  \ChangeRootDirectory /srv/tordnsel/\n\
  \\n\
  \## Write our PID to the specified file before chrooting or dropping\n\
  \## privileges. This file won't be removed on exit.\n\
  \PIDFile /srv/tordnsel/run/tordnsel.pid\n\
  \\n\
  \################ Active testing options ###################################\n\
  \##\n\
  \## These options are only necessary if you want to enable active testing\n\
  \## through exit nodes for a more accurate exit list.\n\
  \\n\
  \## Enable active test connections through exit nodes to determine their\n\
  \## exit IP addresses. Enabling this will result in a more accurate view\n\
  \## exit nodes' IP addresses, at the expense of putting a much greater load\n\
  \## on your local Tor process and the Tor network itself. The default is\n\
  \## \"False\".\n\
  \EnableActiveTesting True\n\
  \\n\
  \## Make exit test connections through Tor's SocksPort on this IP address\n\
  \## and TCP port. Leave it commented to use the default.\n\
  \TorSocksAddress 127.0.0.1:9050\n\
  \\n\
  \## Bind the exit test listeners to this IP address and these TCP ports.\n\
  \## These ports are bound before dropping privileges. Don't use the loopback\n\
  \## interface for TestListenAddress if you're redirecting connections with\n\
  \## iptables because your redirected packets will be dropped as martians.\n\
  \## This option is only required when EnableActiveTesting is set to True.\n\
  \TestListenAddress 10.0.0.1:80,443,110,53,22,5190,6667,9030\n\
  \\n\
  \## Make exit test connections to this IP address and these TCP ports. These\n\
  \## should be publicly accessible from Tor exit nodes. This option is only\n\
  \## required when EnableActiveTesting is set to True.\n\
  \TestDestinationAddress 10.0.0.1:80,443,110,53,22,5190,6667,9030\n"

toConfig = M.fromList . map ((B.pack . map toLower) *** B.pack)

(~>) = (,)
