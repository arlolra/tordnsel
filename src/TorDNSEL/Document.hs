{-# LANGUAGE PatternGuards #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Document
-- Copyright   : (c) tup 2007
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
-- See <https://tor.eff.org/svn/trunk/doc/spec/dir-spec-v2.txt> for details.
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

import Data.Char (isSpace)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.List (find)

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
parseDocument []     = []
parseDocument (x:xs) = Item key arguments objects : parseDocument xs'
  where
    b = B.unsafePackAddress
    (key,x') = B.break isSpace . dropOpt $ x
    arguments | B.null x' = Nothing
              | otherwise = Just . B.dropWhile isSpace $ x'
    (xs',objects) = parseObjects xs
    dropOpt | b 4 "opt "# `B.isPrefixOf` x = B.drop 4
            | otherwise                    = id

    parseObjects :: [ByteString] -> ([ByteString], [Object])
    parseObjects (y:ys)
      | b 11 "-----BEGIN "# `B.isPrefixOf` y, b 5 "-----"# `B.isSuffixOf` y
      = (ys'', Object oKey (B.unlines objLines) : objects')
      where
        oKey = B.take (B.length y - 16) . B.drop 11 $ y
        endLine = b 9 "-----END "# `B.append` oKey `B.append` b 5 "-----"#
        (objLines, ys') = break (== endLine) ys
        (ys'',objects') = parseObjects . drop 1 $ ys'
    parseObjects ys = (ys, [])

-- | Break a document into sub-documents each beginning with an item that has
-- the keyword @firstKey@. Apply @parseDoc@ to each sub-document, returning the
-- parsed document in the result if @parseDoc subDocument@ matches @Just _@.
parseSubDocs :: ByteString -> (Document -> Maybe doc) -> Document -> [doc]
parseSubDocs _        _        []    = []
parseSubDocs firstKey parseDoc (x:xs)
  | Just doc <- parseDoc (x : items) = doc : docs
  | otherwise                        = docs
  where
    (items,xs') = break ((firstKey ==) . iKey) xs
    docs = parseSubDocs firstKey parseDoc xs'

-- | Return the arguments from the first item whose key satisfies the given
-- predicate. 'fail' in the monad if no such item is found.
findArg :: Monad m => (ByteString -> Bool) -> Document -> m ByteString
findArg p items
  | Just item <- find (p . iKey) items, Just arg <- iArg item = return arg
  | otherwise = fail "findArg: item doesn't exist"
