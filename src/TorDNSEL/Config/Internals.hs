{-# LANGUAGE PatternGuards #-}
{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Config.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Parsing configuration options passed on the command line and present in
-- config files.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Config.Internals (
    Config(..)
  , TestConfig(..)
  , ConfigValue(..)
  , parseConfigFile
  , parseConfigArgs
  , knownConfigItems
  , makeConfig
  , toItem
  , b
  ) where

import Control.Arrow ((***), second)
import Control.Monad (liftM, liftM2, unless, ap)
import Data.Char (isSpace, toLower)
import Data.Maybe (catMaybes)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Set as S
import Data.Set (Set)
import Network.Socket (HostAddress, SockAddr(SockAddrInet))

import GHC.Prim (Addr#)

import TorDNSEL.Util
import TorDNSEL.DNS
import TorDNSEL.Log

-- | Configuration options.
data Config = Config
  { cfStateDirectory      :: FilePath -- ^ Where to store exit test results.
  , cfDNSListenAddress    :: SockAddr -- ^ Address to bind the DNS listener.
    -- | Address to connect to the Tor controller interface.
  , cfTorControlAddress   :: SockAddr
    -- | Address Tor is listening on for SOCKS connections, through which we
    -- make exit tests.
  , cfTorSocksAddress     :: SockAddr
  , cfAuthoritativeZone   :: DomainName -- ^ DNS zone we're authoritative for.
  , cfDomainName          :: DomainName -- ^ Name for our own NS record.
  , cfSOARName            :: DomainName -- ^ RNAME we return in our SOA record.
  , cfRunAsDaemon         :: Bool -- ^ Should we daemonize on startup?
  , cfLogConfig           :: LogConfig -- ^ Minimum log severity and log target.
  , cfConfigFile          :: Maybe FilePath -- ^ Config file location.
  , cfTestConfig          :: Maybe TestConfig -- ^ Exit test config.
    -- | A record to return for our zone of authority.
  , cfAddress             :: Maybe HostAddress
    -- | Where to look for the Tor control auth cookie.
  , cfTorDataDirectory    :: Maybe FilePath
    -- | The password used for Tor controller auth.
  , cfTorControlPassword  :: Maybe ByteString
  , cfUser                :: Maybe String -- ^ User name to run under.
  , cfGroup               :: Maybe String -- ^ Group name to run under.
  , cfChangeRootDirectory :: Maybe FilePath -- ^ Directory to chroot to.
  , cfPIDFile             :: Maybe FilePath -- ^ Where to record our PID.
  } deriving Show

-- | Exit test configuration options.
data TestConfig = TestConfig
  { -- | Address and ports to bind the exit test listeners.
    tcfTestListenAddress      :: (HostAddress, [Port])
    -- | Address and ports to which we make exit test connections.
  , tcfTestDestinationAddress :: (HostAddress, [Port])
  } deriving Show

-- | Config items we know about.
knownConfigItems :: Set ByteString
knownConfigItems
  = S.fromList . map toItem $
  [ "StateDirectory"
  , "DNSListenAddress"
  , "TorControlAddress"
  , "TorSocksAddress"
  , "AuthoritativeZone"
  , "DomainName"
  , "SOARName"
  , "RunAsDaemon"
  , "Log"
  , "ConfigFile"
  , "EnableActiveTesting"
  , "TestListenAddress"
  , "TestDestinationAddress"
  , "Address"
  , "TorDataDirectory"
  , "TorControlPassword"
  , "User"
  , "Group"
  , "ChangeRootDirectory"
  , "PIDFile" ]

-- | Merge in default config options, check for missing options, and parse
-- individual config values.
makeConfig :: Monad m => ConfigMap -> m Config
makeConfig conf =
  return Config `app`
    "StateDirectory"# `app`
    "DNSListenAddress"# `app`
    "TorControlAddress"# `app`
    "TorSocksAddress"# `app`
    "AuthoritativeZone"# `app`
    "DomainName"# `app`
    "SOARName"# `app`
    "RunAsDaemon"# `app`
    "Log"# `app`
    "ConfigFile"# `ap`
    testConf `app`
    "Address"# `app`
    "TorDataDirectory"# `app`
    "TorControlPassword"# `app`
    "User"# `app`
    "Group"# `app`
    "ChangeRootDirectory"# `app`
    "PIDFile"#
  where
    conf' = M.union conf . M.fromList . map (toItem *** toItem) $
      [ "DNSListenAddress"    ~> "127.0.0.1:53"
      , "TorControlAddress"   ~> "127.0.0.1:9051"
      , "RunAsDaemon"         ~> "False"
      , "EnableActiveTesting" ~> "False"
      , "TorSocksAddress"     ~> "127.0.0.1:9050"
      , "Log"                 ~> "notice stdout" ]
    (~>) = (,)
    f `app` addr = f `ap` parse (b addr) conf'
    testConf = do
      concTests <- parse (b "EnableActiveTesting"#) conf'
      if concTests
        then liftM Just $ return TestConfig `app` "TestListenAddress"#
                                            `app` "TestDestinationAddress"#
        else return Nothing

-- | Configuration information represented as a map from config item to unparsed
-- config value.
type ConfigMap = Map ByteString ByteString

-- | Lookup a config value by config item, 'fail'ing in the monad when the item
-- isn't present.
lookupValue :: Monad m => ByteString -> ConfigMap -> m ByteString
lookupValue item conf
  | Just val <- M.lookup (B.map toLower item) conf = return val
  | otherwise = fail ("Missing config option " ++ show item ++ " is required.")

-- | Prepend a \"parsing failed\" message to a failure reason.
prependOnFail :: Monad m => ByteString -> Either String a -> m a
prependOnFail item = onFailure (("Parsing " ++ show item ++ " failed: ") ++)

-- | Values used in config files and passed as command line arguments.
class ConfigValue a where
  -- | Parse a config value, failing in the monad if parsing fails.
  parse :: Monad m => ByteString -> ConfigMap -> m a

instance ConfigValue a => ConfigValue (Maybe a) where
  parse = (return .) . parse

instance ConfigValue ByteString where
  parse = lookupValue

instance ConfigValue String where
  parse = (liftM B.unpack .) . lookupValue

instance ConfigValue Int where
  parse item conf = lookupValue item conf >>= prependOnFail item . readInt

instance ConfigValue Integer where
  parse item conf = lookupValue item conf >>= prependOnFail item . readInteger

instance ConfigValue Bool where
  parse item conf = do
    val <- lookupValue item conf
    case B.map toLower val of
      lc | lc == b "true"#  -> return True
         | lc == b "false"# -> return False
         | otherwise -> fail $ "Parsing " ++ show item ++ " failed: Got " ++
                               show val ++ ", expecting \"True\" or \"False\"."

instance ConfigValue SockAddr where
  parse item conf = do
    val <- lookupValue item conf
    prependOnFail item $ do
      let (addr:port:rest) = B.split ':' val
      unless (':' `B.elem` val && null rest) $
        fail ("Invalid address/port " ++ show val ++ ".")
      addr' <- inet_atoh addr
      Port port' <- parsePort port
      return $! SockAddrInet (fromIntegral port') (htonl addr')

instance ConfigValue (HostAddress, [Port]) where
  parse item conf = do
    val <- lookupValue item conf
    prependOnFail item $ do
      let (addr:ports:rest) = B.split ':' val
      unless (':' `B.elem` val && null rest) $
        fail ("Invalid address/ports " ++ show val ++ ".")
      liftM2 (,) (inet_atoh addr) (mapM parsePort $ B.split ',' ports)

instance ConfigValue HostAddress where
  parse item conf = lookupValue item conf >>= prependOnFail item . inet_atoh

instance ConfigValue LogConfig where
  parse item conf = do
    val <- lookupValue item conf
    onFailure (("Parsing log option " ++ show val ++ " failed: ") ++) $ do
      let (severity,(target,file)) = second (second (B.dropWhile isSpace) .
            B.break isSpace . B.dropWhile isSpace) . B.break isSpace $ val
      severity' <- case B.map toLower severity of
        lc | lc == b "debug"#  -> return Debug
           | lc == b "info"#   -> return Info
           | lc == b "notice"# -> return Notice
           | lc == b "warn"#   -> return Warn
           | lc == b "error"#  -> return Error
           | otherwise -> fail $ "Invalid log severity " ++ show severity ++
                                 ". Expecting \"debug\", \"info\", \"notice\", \
                                 \\"warn\", or \"error\"."
      target' <- case B.map toLower target of
        lc | lc == b "stdout"# -> return ToStdOut
           | lc == b "stderr"# -> return ToStdErr
           | lc == b "file"#   -> if B.null file
                                    then fail "Log file name is missing."
                                    else return . ToFile . B.unpack $ file
           | otherwise -> fail $ "Invalid log target " ++ show target ++ ". Exp\
                                 \ecting \"stdout\", \"stderr\", or \"file\"."
      return LogConfig { minSeverity = severity'
                       , logTarget   = target'
                       , logEnabled  = True }

instance ConfigValue DomainName where
  parse item conf = (DomainName . map Label . reverse . dropWhile B.null .
    reverse . B.split '.' . B.map toLower) `liftM` lookupValue item conf

-- | Parse a config file, skipping comments and failing in the monad if an
-- unknown config item is present.
parseConfigFile :: Monad m => ByteString -> m ConfigMap
parseConfigFile = liftM (M.fromList . catMaybes) . mapM parseLine . B.lines
  where
    parseLine line
      | B.null line' = return Nothing
      | item `S.notMember` knownConfigItems
      = fail ("Unknown config option " ++ show item ++ ".")
      | otherwise    = return $ Just (item, value)
      where
        (item,value) = (B.map toLower *** B.dropWhile isSpace) .
                        B.break isSpace $ line'
        (line',_) = B.spanEnd isSpace . B.takeWhile (/= '#') $ line

-- | Given a list of command line arguments, return a map from config item to
-- option, failing in the monad if an unknown item was provided.
parseConfigArgs :: Monad m => [String] -> m ConfigMap
parseConfigArgs = liftM M.fromList . mapM parseArg . splitPairs
  where
    parseArg ["-f",option] = return (b "configfile"#, B.pack option)
    parseArg [item,option]
      | S.member lcItem knownConfigItems = return (lcItem, B.pack option)
      | otherwise = fail ("Unknown config option " ++ show item' ++ ".")
      where
        lcItem = B.pack . map toLower $ item'
        item' = dropWhile (== '-') item
    splitPairs = takeWhile isPair . map (take 2) . iterate (drop 2)
    isPair [_,_] = True
    isPair _     = False

-- | Canonicalize a config item.
toItem :: String -> ByteString
toItem = B.pack . map toLower

-- | An alias for packAddress.
b :: Addr# -> ByteString
b = B.packAddress
