{-# LANGUAGE PatternGuards #-}
{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Handler.Internals
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Handling DNS queries for exit list information.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.DNS.Handler.Internals (
    dnsHandler
  , dropAuthZone
  , parseExitListQuery
  , ttl
  , b
  ) where

import Control.Monad (guard)
import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString.Char8 as B
import Data.Char (toLower)
import Data.List (foldl')
import Data.Maybe (isNothing)
import Data.Word (Word32)

import GHC.Prim (Addr#)

import TorDNSEL.Util
import TorDNSEL.DNS
import TorDNSEL.NetworkState

-- | Given our authoritative zone and a DNS query, parse the exit list query
-- contained therein and generate an appropriate DNS response based on our
-- knowledge of the current state of the Tor network.
dnsHandler
  :: NetworkState -> DomainName -> ResourceRecord -> Message
  -> IO (Maybe Message)
{-# INLINE dnsHandler #-}
-- XXX profiling info is old
-- Profiling shows about 33% of time is spent in this handler for positive
-- results, with 33% spent in deserialization and 33% in serialization.
dnsHandler netState authZone soa msg
  -- draft-arends-dnsext-qr-clarification-00
  | msgQR msg                      = return Nothing
  | msgOpCode msg /= StandardQuery = return notImpl -- RFC 3425
  -- draft-koch-dns-unsolicited-queries-01
  | isNothing mbQLabels            = return refused
  | qc /= IN                       = return nxDomain
  | Just [] <- mbQLabels
  = if qt == TSOA || qt == TAny then return soaResp
                                else return noData -- RFC 2308
  | Just qLabels <- mbQLabels
  , Just query   <- parseExitListQuery qLabels = do
      isExit <- isExitNode netState query
      if isExit || isTest query then
        if qt == TA || qt == TAny
          then return positive -- draft-irtf-asrg-dnsbl-02
          else return noData
        else return nxDomain
  | otherwise                      = return nxDomain
  where
    isTest q = queryAddr q == 0x7f000002
    mbQLabels = dropAuthZone authZone (qName question)
    positive = Just r { msgAA = True, msgRCode = NoError, msgAuthority = []
                      , msgAnswers = [A (qName question) ttl 0x7f000002] }
    noData   = Just r { msgAA = True, msgRCode = NoError, msgAnswers = []
                      , msgAuthority = [soa] }
    nxDomain = Just r { msgAA = True, msgRCode = NXDomain, msgAnswers = []
                      , msgAuthority = [soa] }
    notImpl  = Just r { msgAA = False, msgRCode = NotImplemented
                      , msgAnswers = [], msgAuthority = [soa] }
    refused  = Just r { msgAA = False, msgRCode = Refused
                      , msgAnswers = [], msgAuthority = [soa] }
    soaResp  = Just r { msgAA = True, msgRCode = NoError, msgAnswers = [soa]
                      , msgAuthority = [] }
    r = msg { msgQR = False, msgTC = False, msgRA = False, msgAD = False
            , msgAdditional = [] }
    question = msgQuestion msg
    qt = qType question
    qc = qClass question

-- | Given @authZone@, a sequence of labels ordered from top to bottom
-- representing our authoritative zone, return @Just labels@ if @name@ is a
-- subdomain of @authZone@, where @labels@ is the lower part of @name@ ordered
-- from top to bottom. Otherwise, return Nothing.
--
-- For example:
--
-- >  dropAuthZone \"com.example.torhosts\"
-- >               \"1.0.0.10.80.4.3.2.1.ip-port.torhosts.example.com\"
--
-- would return
--
-- >  Just \"ip-port.1.2.3.4.80.10.0.0.1\"
dropAuthZone :: DomainName -> DomainName -> Maybe [Label]
{-# INLINE dropAuthZone #-}
dropAuthZone (DomainName authZone) (DomainName name) =
  dropAuthZone' authZone (reverse name)
  where
    dropAuthZone' (Label x:xs) (Label y:ys)
      | x == B.map toLower y = dropAuthZone' xs ys
    dropAuthZone' [] ys      = Just ys
    dropAuthZone' _  _       = Nothing

-- | Parse an exit list query from a sequence of labels ordered from top to
-- bottom representing the query portion of a domain name, e.g.
-- @\"ip-port.{IP2}.{port}.{IP1}\"@.
parseExitListQuery :: [Label] -> Maybe ExitListQuery
{-# INLINE parseExitListQuery #-}
parseExitListQuery labels = do
  (queryType:ip2,port:ip1) <- return . splitAt 5 . map unLabel $ labels
  guard $ length ip1 == 4 && B.map toLower queryType == b 7 "ip-port"#
  [ip1',ip2'] <- mapM ((toAddress =<<) . mapM readInt) [ip1, ip2]
  port'       <- toPort =<< readInt port
  return $! IPPort { queryAddr = ip1', destAddr = ip2', destPort = port' }
  where
    toAddress l = do
      guard $ all (\o -> 0 <= o && o <= 0xff) l
      return $! foldl' (.|.) 0 . zipWith shiftL l' $ [24,16..]
      where l' = map fromIntegral l
    toPort p = do
      guard $ 0 <= p && p <= 0xffff
      return $! fromIntegral p

-- | The time-to-live set for caching.
ttl :: Word32
ttl = 60 * 30

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
