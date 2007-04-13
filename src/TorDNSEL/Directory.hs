-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Directory
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, GHC primitives)
--
-- Parsing and processing router descriptors, exit policies, and router
-- status entries from the Tor directory protocol, version 2. We only
-- parse information necessary for running the exit list server.
--
-- See <http://tor.eff.org/svn/trunk/doc/spec/dir-spec.txt> for details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Directory (
  -- * Router descriptors
    Descriptor(..)
  , parseDescriptor
  , parseDescriptors

  -- * Router status entries
  , RouterStatus(..)
  , parseRouterStatus
  , parseRouterStatuses

  -- * Identity fingerprints
  , Fingerprint
  , decodeBase16Fingerprint
  , encodeBase16Fingerprint

  -- * Exit policies
  , ExitPolicy
  , exitPolicyAccepts

  -- * Document meta-format
  , Document
  , Item
  , parseDocument
  ) where

import TorDNSEL.Directory.Internals
