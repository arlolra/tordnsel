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
  [ "User"       ~> "_tordnsel"
  , "ConfigFile" ~> "/etc/tordnsel.conf" ]

configArgs = ["--User", "_tordnsel", "-f", "/etc/tordnsel.conf"]

config = toConfig
  [ "AuthoritativeZone"      ~> "torhosts.example.com."
  , "SOARName"               ~> "hostmaster.example.com."
  , "ChangerootDirectory"    ~> "/var/empty"
  , "ConcurrentExitTests"    ~> "128"
  , "ConfigFile"             ~> "/etc/tordnsel/tordnsel.conf"
  , "DNSListenAddress"       ~> "127.0.0.1:53"
  , "Group"                  ~> "_tordnsel"
  , "PIDFile"                ~> "/var/run/tordnsel.pid"
  , "RunAsDaemon"            ~> "True"
  , "StateDirectory"         ~> "/var/lib/tordnsel"
  , "TestDestinationAddress" ~> "18.0.0.1:80,443,110,53,22,5190,6667,9030"
  , "TestListenAddress"      ~> "10.0.0.1:80,443,110,53,22,5190,6667,9030"
  , "TorControlAddress"      ~> "127.0.0.1:9051"
  , "TorControlPassword"     ~> "password"
  , "TorDataDirectory"       ~> "/var/lib/tor"
  , "TorSocksAddress"        ~> "127.0.0.1:9050"
  , "User"                   ~> "_tordnsel" ]

configFile = B.pack
  "## Answer queries authoritatively for this DNS zone. For example, if this\n\
  \## is set to \"torhosts.example.com.\", your server would accept queries of\n\
  \## the form \"1.0.0.10.80.4.3.2.1.ip-port.torhosts.example.com.\". This\n\
  \## option is required.\n\
  \AuthoritativeZone torhosts.example.com.\n\
  \\n\
  \## Use this email address in the RNAME field of SOA records. Usually,\n\
  \## this should be something like \"hostmaster@example.com\". Replace the\n\
  \## \"@\" with a \".\".\n\
  \SOARName hostmaster.example.com.\n\
  \\n\
  \## Bind the name server to this IP address and UDP port. If you want to\n\
  \## bind to all interfaces, you might set the address to \"0.0.0.0\". This\n\
  \## port is bound before dropping privileges. Leave it commented to use\n\
  \## the default.\n\
  \DNSListenAddress 127.0.0.1:53\n\
  \\n\
  \## Make Tor controller connections to this IP address and TCP port.\n\
  \## You'll need to set this as your ControlListenAddress or ControlPort in\n\
  \## Tor's torrc. Leave it commented to use the default.\n\
  \TorControlAddress 127.0.0.1:9051\n\
  \\n\
  \## Detach from the controlling terminal and run in the background as a\n\
  \## daemon. The default is \"False\".\n\
  \RunAsDaemon True\n\
  \\n\
  \## Tor's data directory. Only specify this when you're using Tor's\n\
  \## CookieAuthentication for controller connections. The control auth\n\
  \## cookie is read before chrooting or dropping privileges.\n\
  \TorDataDirectory /var/lib/tor\n\
  \\n\
  \## The password you used to generate the HashedControlPassword in Tor's\n\
  \## torrc. This is only required when you have a HashedControlPassword.\n\
  \TorControlPassword password\n\
  \\n\
  \## The user name to which you want to drop privileges. This option\n\
  \## requires root privileges.\n\
  \User _tordnsel\n\
  \\n\
  \## The group name to which you want to drop privileges. This option also\n\
  \## requires root privileges.\n\
  \Group _tordnsel\n\
  \\n\
  \## Call chroot(2) to change our root directory. This option also requires\n\
  \## root privileges.\n\
  \ChangeRootDirectory /var/empty\n\
  \\n\
  \## Write our PID to the specified file before chrooting or dropping\n\
  \## privileges. This file won't be removed on exit.\n\
  \PIDFile /var/run/tordnsel.pid\n\
  \\n\
  \## Include another config file, using options in this file when duplicates\n\
  \## are encountered. You probably don't want to do this.\n\
  \ConfigFile /etc/tordnsel/tordnsel.conf\n\
  \\n\
  \## Make at most this number of concurrent test connections through exit\n\
  \## nodes. By default this is set to 0, that is, we don't perform any\n\
  \## tests. If this is set higher than about (FD_SETSIZE-80)/2, the runtime\n\
  \## will crash due to limitations of select(2). Setting it higher than the\n\
  \## number of exit nodes has no benefit, so a reasonable maximum might be\n\
  \## 384.\n\
  \ConcurrentExitTests 128\n\
  \\n\
  \## Store exit test results in this directory. This path should be\n\
  \## accessible and writable from inside the chroot (if configured) after\n\
  \## dropping privileges. This option is only required when\n\
  \## ConcurrentExitTests is greater than 0.\n\
  \StateDirectory /var/lib/tordnsel\n\
  \\n\
  \## Make exit test connections through Tor's SocksPort on this IP address\n\
  \## and TCP port. Leave it commented to use the default.\n\
  \TorSocksAddress 127.0.0.1:9050\n\
  \\n\
  \## Bind the exit test listeners to this IP address and these TCP ports.\n\
  \## These ports are bound before dropping privileges. This option is only\n\
  \## required when ConcurrentExitTests is greater than 0.\n\
  \TestListenAddress 10.0.0.1:80,443,110,53,22,5190,6667,9030\n\
  \\n\
  \## Make exit test connections to this IP address and these TCP ports.\n\
  \## These should be publicly accessible from Tor exit nodes. This option\n\
  \## is only required when ConcurrentExitTests is greater than 0.\n\
  \TestDestinationAddress 18.0.0.1:80,443,110,53,22,5190,6667,9030\n"

toConfig = M.fromList . map ((B.pack . map toLower) *** B.pack)

(~>) = (,)
