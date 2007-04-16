{-# LANGUAGE PatternGuards, ForeignFunctionInterface #-}
{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Config.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, FFI, GHC primitives)
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
  , b
  , htonl
  ) where

import Control.Monad (liftM, when, unless)
import Data.Char (isSpace, toLower)
import Data.Maybe (catMaybes)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import qualified Data.Map as M
import Data.Map (Map)
import qualified Data.Set as S
import Data.Set (Set)
import Data.Word (Word32)
import Network.Socket (SockAddr(SockAddrInet))

import GHC.Prim (Addr#)

import TorDNSEL.Util

-- | Config items we know about.
knownConfigItems :: Set ByteString
knownConfigItems
  = S.fromList . map (B.pack . map toLower) $
  [ "ConfigFile"
  , "DNSListenAddress"
  , "TorControlAddress"
  , "AuthoritativeZone"
  , "TorDataDirectory"
  , "TorControlPassword"
  , "User"
  , "Group"
  , "ChangeRootDirectory"
  , "PIDFile"
  , "RunAsDaemon" ]

-- | Check for required config options and fill in defaults for absent options.
fillInConfig :: Config -> IO Config
fillInConfig conf = do
  when (b "authoritativezone"# `M.notMember` conf) $
    fail "AuthoritativeZone is a required option."
  return . M.union conf . M.fromList $
    [ (b "dnslistenaddress"#,  b "127.0.0.1:53"#)
    , (b "torcontroladdress"#, b "127.0.0.1:9051"#)
    , (b "runasdaemon"#,       b "false"#) ]

-- | Configuration information represented as a map from config item to unparsed
-- config value.
type Config = Map ByteString ByteString

-- | Values used in config files and passed as command line arguments.
class ConfigValue a where
  -- | Parse a config value, failing in the monad if parsing fails.
  parse :: Monad m => ByteString -> m a

instance ConfigValue ByteString where
  parse = return

instance ConfigValue Bool where
  parse bs
    | bs' == b "true"#  = return True
    | bs' == b "false"# = return False
    | otherwise
    = fail ("parse " ++ show bs ++ " failed, expecting \"True\" or \"False\"")
    where bs' = B.map toLower bs

instance ConfigValue SockAddr where
  parse bs = do
    () <- unless (':' `B.elem` bs) $
      fail ("invalid address/port: " ++ show bs)
    addr' <- inet_atoh addr
    port' <- readInt port
    () <- unless (0 <= port' && port' <= 0xffff) $
      fail ("port \"" ++ show port' ++ "\" is invalid")
    return $! SockAddrInet (fromIntegral port') (htonl addr')
    where [addr,port] = B.split ':' bs

-- | Given config options, merge the config file located at the ConfigFile
-- value with the current options. We give preference to the current options
-- when items are duplicated. Included config files are merged recursively.
parseConfig :: Config -> IO Config
parseConfig conf
  | (Just fp,conf') <- lookupDelete (b "configfile"#) conf
  = B.readFile (B.unpack fp) >>= parseConfigFile >>= parseConfig . M.union conf'
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
      = fail ("unknown config option: " ++ show item)
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
    parseArg [item,option]
      | item == "-f" = return (b "configfile"#, B.pack option)
      | ("--",rest) <- splitAt 2 item, item' <- B.pack $ map toLower rest
      , item' `S.member` knownConfigItems = return (item', B.pack option)
      | otherwise = fail ("unknown config option: " ++ show item)
    splitPairs = takeWhile isPair . map (take 2) . iterate (drop 2)
    isPair [_,_] = True
    isPair _     = False

-- | An alias for packAddress.
b :: Addr# -> ByteString
b = B.packAddress

foreign import ccall unsafe "htonl" htonl :: Word32 -> Word32
