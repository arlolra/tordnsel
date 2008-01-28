-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DistinctQueue
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- A FIFO queue of distinct elements.
--
-----------------------------------------------------------------------------

module TorDNSEL.DistinctQueue (
    DistinctQueue
  , empty
  , null
  , enqueue
  , dequeue
  , isConsistent
  ) where

import Prelude hiding (null)
import qualified Data.Foldable as Foldable
import qualified Data.Sequence as Seq
import Data.Sequence (Seq, (<|), viewr, ViewR(..))
import qualified Data.Set as Set
import Data.Set (Set)

-- | A FIFO queue of distinct elements.
data Ord a => DistinctQueue a = DistinctQueue !(Seq a) !(Set a)

-- | The empty distinct queue.
empty :: Ord a => DistinctQueue a
empty = DistinctQueue Seq.empty Set.empty

-- | Is this the empty distinct queue?
null :: Ord a => DistinctQueue a -> Bool
null (DistinctQueue q _) = Seq.null q

-- | Add an element to the left end of the queue, if the element isn't already
-- present in the queue.
enqueue :: Ord a => a -> DistinctQueue a -> DistinctQueue a
enqueue x oldQ@(DistinctQueue q set)
  | x `Set.notMember` set = DistinctQueue (x <| q) (Set.insert x set)
  | otherwise             = oldQ

-- | Remove an element from the right end of the queue, returning the element
-- and the rest of the queue. Return 'Nothing' if this is the empty queue.
--
-- With a list of distinct elements, the following identity holds:
--
-- >  nub == id ==> unfoldr dequeue . foldl (flip enqueue) empty == id
dequeue :: Ord a => DistinctQueue a -> Maybe (a, DistinctQueue a)
dequeue (DistinctQueue q set) =
  case viewr q of
    q' :> x -> Just (x, DistinctQueue q' (Set.delete x set))
    EmptyR  -> Nothing

-- | An invariant: is the queue internally consistent?
isConsistent :: Ord a => DistinctQueue a -> Bool
isConsistent (DistinctQueue q set) =
  Seq.length q == Set.size set && Foldable.all (`Set.member` set) q
