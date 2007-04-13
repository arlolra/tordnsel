-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Control
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             GHC primitives)
--
-- Interfacing with Tor using the Tor control protocol, version 1. We support
-- fetching router descriptors and router status entries, including those sent
-- in asynchronous events that Tor generates when it receives new information
-- from directories.
--
-- See <http://tor.eff.org/svn/trunk/doc/spec/control-spec.txt> for details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Control (
  -- * Connections
    Connection
  , withConnection
  , openConnection
  , waitForConnection
  , closeConnection

  -- * Commands
  , authenticate
  , fetchDescriptor
  , fetchAllDescriptors
  , fetchRouterStatus
  , fetchNetworkStatus
  , setFetchUselessDescriptors

  -- * Asynchronous events
  , EventHandler
  , registerEventHandlers
  , newDescriptors
  , newNetworkStatus

  -- * Errors
  , TorControlError(..)
  ) where

import TorDNSEL.Control.Internals
