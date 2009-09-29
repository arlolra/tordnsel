{-# LANGUAGE PatternGuards, FlexibleContexts #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Document
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Parsing the document meta-format used by the Tor directory protocol,
-- version 2.
--
-- See <https://www.torproject.org/svn/trunk/doc/spec/dir-spec-v2.txt> for details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Document (
    Document
  , Item(..)
  , Object(..)
  , parseDocument
  , parseSubDocs
  , findArg
  ) where

import Control.Arrow (first, (***))
import Control.Monad.Error (MonadError(throwError))
import Data.Char (isSpace)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.List (find, unfoldr)

import TorDNSEL.Util

-- | A document consisting of a sequence of one or more items.
type Document = [Item]

-- | An item consisting of a keyword, possibly arguments, and zero or more
-- objects.
data Item = Item
  { iKey :: {-# UNPACK #-} !ByteString         -- ^ Keyword
  , iArg :: {-# UNPACK #-} !(Maybe ByteString) -- ^ Arguments
  , iObj :: {-# UNPACK #-} ![Object]           -- ^ Objects
  } deriving Show

-- | An object consisting of a keyword and a block of base64-encoded data.
data Object = Object
  { objKey  :: {-# UNPACK #-} !ByteString -- ^ Keyword
  , objData :: {-# UNPACK #-} !ByteString -- ^ Base64-encoded data
  } deriving Show

-- | Parse a 'Document' from a list of lines.
parseDocument :: [ByteString] -> Document
parseDocument = unfoldr parseDocument' where
  parseDocument' []     = Nothing
  parseDocument' (x:xs) = Just . first (Item key args) . parseObjects $ xs
    where
      (key,x') = B.break isSpace . dropOpt $ x
      dropOpt = if B.pack "opt " `B.isPrefixOf` x then B.drop 4 else id
      args | B.null x' = Nothing
           | otherwise   = Just . B.dropWhile isSpace $ x'

-- | Parse a list of 'Object's from a list of lines, returning the remaining
-- lines.
parseObjects :: [ByteString] -> ([Object], [ByteString])
parseObjects = unfoldAccumR parseObjects' where
  parseObjects' (x:xs)
    | B.pack "-----BEGIN " `B.isPrefixOf` x, B.pack "-----" `B.isSuffixOf` x
    = Left . ((Object key . B.unlines) *** drop 1) . break (== endLine) $ xs
    where key = B.take (B.length x - 16) . B.drop 11 $ x
          endLine = B.pack "-----END " `B.append` key `B.append` B.pack "-----"
  parseObjects' xs = Right xs

-- | Break a document into sub-documents each beginning with an item that has
-- the keyword @firstKey@. Apply @parseDoc@ to each sub-document, returning
-- either an error message or the parsed document.
parseSubDocs :: ByteString -> (Document -> Either ShowS a) -> Document
             -> [Either ShowS a]
parseSubDocs firstKey parseDoc = unfoldr parseSubDocs' where
  parseSubDocs' []     = Nothing
  parseSubDocs' (x:xs) = Just (parseDoc (x : items), xs')
    where (items,xs') = break ((firstKey ==) . iKey) xs

-- | Return the arguments from the first item whose key matches the given key.
-- 'throwError' in the monad if no such item is found.
findArg :: MonadError ShowS m => ByteString -> Document -> m ByteString
findArg bs items
  | Just item <- find ((bs ==) . iKey) items, Just arg <- iArg item = return arg
  | otherwise = throwError $ cat "Item " bs " not found."
