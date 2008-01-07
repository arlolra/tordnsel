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
import Control.Monad (liftM, liftM2, ap)
import Control.Monad.Error (MonadError(..))
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
  , "TorControlPassword"
  , "User"
  , "Group"
  , "ChangeRootDirectory"
  , "PIDFile" ]

-- | Merge in default config options, check for missing options, and parse
-- individual config values.
makeConfig :: MonadError ShowS m => ConfigMap -> m Config
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

-- | Lookup a config value by config item. 'throwError' in the monad when the
-- item isn't present.
lookupValue :: MonadError ShowS m => ByteString -> ConfigMap -> m ByteString
lookupValue item conf
  | Just val <- M.lookup (B.map toLower item) conf = return val
  | otherwise = throwError $ cat "Missing config option " item " is required."

-- | Prepend a \"parsing failed\" message to a failure reason.
prependOnFail :: MonadError ShowS m => ByteString -> m a -> m a
prependOnFail item = prependError (cat "Parsing \"" item "\" failed: ")

-- | Values used in config files and passed as command line arguments.
class ConfigValue a where
  -- | Parse a config value. 'throwError' in the monad if parsing fails.
  parse :: MonadError ShowS m => ByteString -> ConfigMap -> m a

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
         | otherwise -> throwError $ cat "Parsing \"" item "\" failed: Got "
                                     (esc maxBoolLen val) ", expecting \"True\"\
                                     \ or \"False\"."
    where maxBoolLen = 32

instance ConfigValue SockAddr where
  parse item conf = do
    val <- lookupValue item conf
    prependOnFail item $
      case B.split ':' val of
        [addr,port] -> do
          addr' <- inet_atoh addr
          Port port' <- parsePort port
          return $! SockAddrInet (fromIntegral port') (htonl addr')
        _ -> throwError $ cat "Malformed address/port " (esc maxAddrLen val) '.'
    where maxAddrLen = 32

instance ConfigValue (HostAddress, [Port]) where
  parse item conf = do
    val <- lookupValue item conf
    prependOnFail item $
      case B.split ':' val of
        [addr,ports] -> liftM2 (,) (inet_atoh addr)
                                   (mapM parsePort $ B.split ',' ports)
        _ -> throwError $ cat "Malformed address/ports "
                              (esc maxAddrLen val) '.'
    where maxAddrLen = 256

instance ConfigValue HostAddress where
  parse item conf = lookupValue item conf >>= prependOnFail item . inet_atoh

instance ConfigValue LogConfig where
  parse item conf = do
    val <- lookupValue item conf
    prependError (cat "Parsing log option " (esc maxLogLen val)
                      " failed: ") $ do
      let (severity,(target,file)) = second (second (B.dropWhile isSpace) .
            B.break isSpace . B.dropWhile isSpace) . B.break isSpace $ val
      severity' <- case B.map toLower severity of
        lc | lc == b "debug"#  -> return Debug
           | lc == b "info"#   -> return Info
           | lc == b "notice"# -> return Notice
           | lc == b "warn"#   -> return Warn
           | lc == b "error"#  -> return Error
           | otherwise -> throwError $ cat "Invalid log severity "
               (esc maxSeverityLen severity) ". Expecting \"debug\", \"info\", \
               \\"notice\", \"warn\", or \"error\"."
      target' <- case B.map toLower target of
        lc | lc == b "stdout"# -> return ToStdOut
           | lc == b "stderr"# -> return ToStdErr
           | lc == b "file"# ->
               if B.null file then throwError ("Log file name is missing." ++)
                              else return . ToFile . B.unpack $ file
           | otherwise -> throwError $ cat "Invalid log target "
               (esc maxTargetLen target) ". Expecting \"stdout\", \"stderr\", \
               \or \"file\"."
      return LogConfig { minSeverity = severity'
                       , logTarget   = target'
                       , logEnabled  = True }
    where
      maxLogLen = 512
      maxSeverityLen = 32
      maxTargetLen = 32

instance ConfigValue DomainName where
  parse item conf = (DomainName . map Label . reverse . dropWhile B.null .
    reverse . B.split '.' . B.map toLower) `liftM` lookupValue item conf

-- | Parse a config file, skipping comments. 'throwError' in the monad if an
-- unknown config item is present.
parseConfigFile :: MonadError ShowS m => ByteString -> m ConfigMap
parseConfigFile = liftM (M.fromList . catMaybes) . mapM parseLine . B.lines
  where
    parseLine line
      | B.null line' = return Nothing
      | lcItem `S.notMember` knownConfigItems
      = throwError $ cat "Unknown config option " (esc maxOptionLen item) '.'
      | otherwise    = return $ Just (lcItem, value)
      where
        lcItem = B.map toLower item
        (item,value) = second (B.dropWhile isSpace) . B.break isSpace $ line'
        (line',_) = B.spanEnd isSpace . B.takeWhile (/= '#') $ line
        maxOptionLen = 64

-- | Given a list of command line arguments, return a map from config item to
-- option. 'throwError' in the monad if an unknown item was provided.
parseConfigArgs :: MonadError ShowS m => [String] -> m ConfigMap
parseConfigArgs = liftM M.fromList . mapM parseArg . splitPairs
  where
    parseArg ["-f",option] = return (b "configfile"#, B.pack option)
    parseArg [item,option]
      | S.member lcItem knownConfigItems = return (lcItem, B.pack option)
      | otherwise = throwError $ cat "Unknown config option "
                                     (esc maxOptionLen $ B.pack item') '.'
      where
        lcItem = B.pack . map toLower $ item'
        item' = dropWhile (== '-') item
        maxOptionLen = 64
    splitPairs = takeWhile isPair . map (take 2) . iterate (drop 2)
    isPair [_,_] = True
    isPair _     = False

-- | Canonicalize a config item.
toItem :: String -> ByteString
toItem = B.pack . map toLower

-- | An alias for packAddress.
b :: Addr# -> ByteString
b = B.packAddress
