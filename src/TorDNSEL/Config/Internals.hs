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
    Config
  , ConfigValue(..)
  , parseConfig
  , parseConfigFile
  , parseConfigArgs
  , knownConfigItems
  , fillInConfig
  , toItem
  , b
  ) where

import Control.Arrow ((***))
import Control.Monad (liftM, liftM2, when, unless)
import Data.Char (isSpace, toLower)
import Data.Maybe (catMaybes)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import qualified Data.Map as M
import Data.Map (Map, (!))
import qualified Data.Set as S
import Data.Set (Set)
import Network.Socket (HostAddress, SockAddr(SockAddrInet))

import GHC.Prim (Addr#)

import TorDNSEL.Util

-- | Config items we know about.
knownConfigItems :: Set ByteString
knownConfigItems
  = S.fromList . map toItem $
  [ "ConfigFile"
  , "DNSListenAddress"
  , "TorControlAddress"
  , "AuthoritativeZone"
  , "DomainName"
  , "Address"
  , "SOARName"
  , "TorDataDirectory"
  , "TorControlPassword"
  , "User"
  , "Group"
  , "ChangeRootDirectory"
  , "PIDFile"
  , "RunAsDaemon"
  , "ConcurrentExitTests"
  , "StateDirectory"
  , "TorSocksAddress"
  , "TestListenAddress"
  , "TestDestinationAddress" ]

-- | Check for required config options and fill in defaults for absent options.
fillInConfig :: Monad m => Config -> m Config
fillInConfig conf = do
  mapM_ (checkForItem " is a required option.")
    ["AuthoritativeZone", "DomainName", "SOARName", "StateDirectory"]
  concTests <- parse $ conf' ! b "concurrentexittests"#
  when (concTests > (0 :: Int)) .
    mapM_ (checkForItem " is required for exit tests.") $
      ["TestListenAddress", "TestDestinationAddress"]
  return conf'
  where
    conf' = M.union conf . M.fromList . map (toItem *** toItem) $
      [ "DNSListenAddress"    ~> "127.0.0.1:53"
      , "TorControlAddress"   ~> "127.0.0.1:9051"
      , "RunAsDaemon"         ~> "False"
      , "ConcurrentExitTests" ~> "0"
      , "TorSocksAddress"     ~> "127.0.0.1:9050" ]
    (~>) = (,)
    checkForItem msg item = when (toItem item `M.notMember` conf') $
      fail (item ++ msg)

-- | Configuration information represented as a map from config item to unparsed
-- config value.
type Config = Map ByteString ByteString

-- | Values used in config files and passed as command line arguments.
class ConfigValue a where
  -- | Parse a config value, failing in the monad if parsing fails.
  parse :: Monad m => ByteString -> m a

instance ConfigValue ByteString where
  parse = return

instance ConfigValue String where
  parse = return . B.unpack

instance ConfigValue Int where
  parse = readInt

instance ConfigValue Bool where
  parse bs
    | bs' == b "true"#  = return True
    | bs' == b "false"# = return False
    | otherwise
    = fail ("Parse " ++ show bs ++ " failed, expecting \"True\" or \"False\".")
    where bs' = B.map toLower bs

instance ConfigValue SockAddr where
  parse bs = do
    unless (':' `B.elem` bs) $
      fail ("Address/port " ++ show bs ++ " is invalid.")
    addr' <- inet_atoh addr
    port' <- readInt port
    unless (0 <= port' && port' <= 0xffff) $
      fail ("Port " ++ show port ++ " is invalid.")
    return $! SockAddrInet (fromIntegral port') (htonl addr')
    where [addr,port] = B.split ':' bs

instance ConfigValue (HostAddress, [Port]) where
  parse bs = do
    unless (':' `B.elem` bs) $
      fail ("Address/ports " ++ show bs ++ " is invalid.")
    liftM2 (,) (inet_atoh addr) (mapM parsePort ports)
    where
      [addr,rest] = B.split ':' bs
      ports = B.split ',' rest

instance ConfigValue HostAddress where
  parse = inet_atoh

-- | Given config options, merge the config file located at the ConfigFile
-- value with the current options. We give preference to the current options
-- when items are duplicated. Included config files are merged recursively.
parseConfig :: Config -> IO Config
parseConfig conf
  | (Just fp,conf') <- lookupDelete (b "configfile"#) conf =
    B.readFile (B.unpack fp) >>= exitLeft . parseConfigFile
                             >>= parseConfig . M.union conf'
  | otherwise = return conf
  where lookupDelete = M.updateLookupWithKey (const $ const Nothing)

-- | Parse a config file, skipping comments and failing in the monad if an
-- unknown config item is present.
parseConfigFile :: Monad m => ByteString -> m Config
parseConfigFile = liftM (M.fromList . catMaybes) . mapM parseLine . B.lines
  where
    parseLine line
      | B.null line' = return Nothing
      | item `S.notMember` knownConfigItems
      = fail ("Unknown config option: " ++ show item)
      | otherwise    = return $ Just (item, option)
      where
        option = B.dropWhile isSpace rest
        item = B.map toLower first
        (first,rest) = B.break isSpace line'
        (line',_) = B.spanEnd isSpace . B.takeWhile (/= '#') $ line

-- | Given a list of command line arguments, return a map from config item to
-- option, failing in the monad if an unknown item was provided.
parseConfigArgs :: Monad m => [String] -> m Config
parseConfigArgs = liftM M.fromList . mapM parseArg . splitPairs
  where
    parseArg ["-f",option] = return (b "configfile"#, B.pack option)
    parseArg [item,option]
      | ("--",rest) <- splitAt 2 item
      , item' <- B.pack $ map toLower rest
      , item' `S.member` knownConfigItems
      = return (item', B.pack option)
    parseArg [item,_] = fail ("Unknown config option: " ++ show item)
    splitPairs = takeWhile isPair . map (take 2) . iterate (drop 2)
    isPair [_,_] = True
    isPair _     = False

-- | Canonicalize a config item.
toItem :: String -> ByteString
toItem = B.pack . map toLower

-- | An alias for packAddress.
b :: Addr# -> ByteString
b = B.packAddress
