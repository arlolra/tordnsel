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
    DNSConfig(..)
  , ResponseType(..)
  , dnsHandler
  , dropAuthZone
  , parseExitListQuery
  , ttl
  , b
  ) where

import Control.Monad (guard, liftM2)
import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString.Char8 as B
import Data.Char (toLower)
import Data.List (foldl')
import Data.Maybe (isNothing, maybeToList)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word32)

import GHC.Prim (Addr#)

import TorDNSEL.Util
import TorDNSEL.DNS
import TorDNSEL.NetworkState

-- | The DNS handler configuration data.
data DNSConfig
  = DNSConfig
  { dnsAuthZone :: !DomainName     -- ^ The zone we're authoritative for.
  , dnsMyName   :: !DomainName     -- ^ The domain name where we're located.
  , dnsSOA      :: !ResourceRecord -- ^ Our SOA record.
  , dnsNS       :: !ResourceRecord -- ^ Our own NS record.
  -- | The A record we return for our authoritative zone.
  , dnsA        :: !(Maybe ResourceRecord)
  -- | A statistics tracking action invoked with each response.
  , dnsStats    :: !(ResponseType -> IO ())
  }

-- | The response type reported in statistics. 'Positive' and 'Negative' are for
-- valid DNSEL queries.
data ResponseType = Positive | Negative | Other

-- | A stateful wrapper for 'dnsResponse'.
dnsHandler :: DNSConfig -> Network -> Message -> IO (Maybe Message)
dnsHandler c net msg
  -- draft-arends-dnsext-qr-clarification-00
  | msgQR msg = return Nothing
  | otherwise = do
      (typ,resp) <- liftM2 (dnsResponse c msg) getPOSIXTime
                                               (readNetworkState net)
      dnsStats c typ
      return $ Just resp

-- | Given our config data and a DNS query, parse the exit list query contained
-- therein and generate an appropriate DNS response based on our knowledge of
-- the current state of the Tor network.
dnsResponse :: DNSConfig -> Message -> POSIXTime -> NetworkState
            -> (ResponseType, Message)
{-# INLINE dnsHandler #-}
dnsResponse c msg now ns
  | msgOpCode msg /= StandardQuery -- RFC 3425
  = (Other, r { msgAA = False, msgRCode = NotImplemented
              , msgAnswers = [], msgAuthority = [dnsSOA c] })
  -- draft-koch-dns-unsolicited-queries-01
  | isNothing mbQLabels
  = (Other, r { msgAA = False, msgRCode = Refused
              , msgAnswers = [], msgAuthority = [dnsSOA c] })
  | qc /= IN = (Other, nxDomain)
  -- a request matching our authoritative zone
  | Just [] <- mbQLabels = case qt of
      TA | Just a <- dnsA c
           -> (Other, noErr { msgAnswers = [a], msgAuthority = [dnsNS c] })
      TNS  -> (Other, noErr { msgAnswers = [dnsNS c], msgAuthority = [] })
      TSOA -> (Other, noErr { msgAnswers = [dnsSOA c]
                            , msgAuthority = [dnsNS c] })
      TAny -> (Other, noErr { msgAnswers = [dnsSOA c, dnsNS c] ++
                              maybeToList (dnsA c), msgAuthority = [dnsNS c] })
      _    -> (Other, noErr { msgAnswers = [], msgAuthority = [dnsSOA c] })
  | Just qLabels <- mbQLabels
  , Just query   <- parseExitListQuery qLabels
  = if isTest query || isExitNode now ns query
      then if qt == TA || qt == TAny
        -- draft-irtf-asrg-dnsbl-02
        then (Positive, noErr { msgAnswers = [positive]
                              , msgAuthority = [dnsNS c] })
        -- RFC 2308
        else (Other, noErr { msgAnswers = [], msgAuthority = [dnsSOA c] })
      else (Negative, nxDomain)
  | otherwise = (Other, nxDomain)
  where
    isTest q = queryAddr q == 0x7f000002
    mbQLabels = dropAuthZone (dnsAuthZone c) (qName question)
    positive = A (qName question) ttl 0x7f000002
    noErr = r { msgAA = True, msgRCode = NoError }
    nxDomain = r { msgAA = True, msgRCode = NXDomain, msgAnswers = []
                 , msgAuthority = [dnsSOA c] }
    r = msg { msgQR = True, msgTC = False, msgRA = False, msgAD = False
            , msgAdditional = [] }
    question = msgQuestion msg
    (qt,qc) = (qType question, qClass question)

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
ttl = 30 * 60

-- | An alias for unsafePackAddress.
b :: Int -> Addr# -> B.ByteString
b = B.unsafePackAddress
