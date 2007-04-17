-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DeepSeq
-- Copyright   : (c) tup 2007
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- Deep strict evaluation.
--
-----------------------------------------------------------------------------

module TorDNSEL.DeepSeq (
    DeepSeq(..)
  , ($!!)
  ) where

import Data.ByteString (ByteString)
import Data.List (foldl')
import Data.Word (Word16, Word32)

-- | Deep strict evaluation. This is mainly used here to force any exceptional
-- values contained in a data structure to show themselves.
class DeepSeq a where
  deepSeq :: a -> b -> b

infixr 0 `deepSeq`, $!!

instance DeepSeq Bool where deepSeq = seq
instance DeepSeq Word16 where deepSeq = seq
instance DeepSeq Word32 where deepSeq = seq
instance DeepSeq ByteString where deepSeq = seq
instance DeepSeq a => DeepSeq [a] where
  deepSeq = flip . foldl' . flip $ deepSeq

-- | Strict application, defined in terms of 'deepSeq'.
($!!) :: DeepSeq a => (a -> b) -> a -> b
f $!! x = x `deepSeq` f x
