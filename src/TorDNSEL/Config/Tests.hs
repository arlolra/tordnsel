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

import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import Test.HUnit (Test(..), (@=?))

import TorDNSEL.Config.Internals

tests = TestList . map TestCase $
  [ Just config @=? parseConfigFile configFile
  , Just config' @=? parseConfigArgs configArgs ]

toConfig = M.fromList . map (\(k,v) -> (B.pack k, B.pack v))

config' = toConfig $
  [ ("user", "_tordnsel")
  , ("configfile", "/etc/tordnsel.conf") ]

config = toConfig $
  [ ("authoritativezone", "torhosts.example.com")
  , ("changerootdirectory", "/var/empty")
  , ("configfile", "/etc/tordnsel/tordnsel.conf")
  , ("dnslistenaddress", "127.0.0.1:53")
  , ("group", "nobody")
  , ("pidfile", "/var/run/tordnsel.pid")
  , ("runasdaemon", "True")
  , ("torcontroladdress", "127.0.0.1:9051")
  , ("torcontrolpassword", "password")
  , ("tordatadirectory", "/var/lib/tor")
  , ("user", "nobody") ]

configArgs = ["-User", "_tordnsel", "-f", "/etc/tordnsel.conf"]

configFile = B.pack
  "## The DNS zone for which this name server is authoritative. For example,\n\
  \## if this is set to \"torhosts.example.com\", your server would accept\n\
  \## queries of the form \"1.0.0.10.80.4.3.2.1.ip-port.torhosts.example.com\".\
  \\n## This option is required.\n\
  \AuthoritativeZone   \ttorhosts.example.com  # comment\n\
  \\n\
  \## The IP address and UDP port the name server will bind to. If you want\n\
  \## to bind to all interfaces, you might set the address to \"0.0.0.0\".\n\
  \## This port is bound before dropping privileges. Leave it commented to use\
  \\n## the default.\n\
  \DNSListenAddress 127.0.0.1:53\n\
  \\n\
  \## The IP address and TCP port on which Tor is listening for controller\n\
  \## connections. You'll need to set this as your ControlListenAddress or\n\
  \## ControlPort in Tor's torrc. Leave it commented to use the default.\n\
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
  \User nobody\n\
  \\n\
  \## The group name to which you want to drop privileges. This option also\n\
  \## requires root privileges.\n\
  \Group nobody\n\
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
  \ConfigFile /etc/tordnsel/tordnsel.conf\n"
