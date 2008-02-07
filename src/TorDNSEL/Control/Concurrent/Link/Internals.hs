{-# LANGUAGE PatternGuards #-}
{-# OPTIONS_GHC -fno-ignore-asserts #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Control.Concurrent.Link.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             pattern guards)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Implements linked threads and monitors for error handling, attempting to
-- closely reproduce their behavior in Erlang.
--
-- Based on Joe Armstrong's /Making reliable distributed systems in the
-- presence of software errors/.
-- <http://www.sics.se/~joe/thesis/armstrong_thesis_2003.pdf>
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Control.Concurrent.Link.Internals where

import qualified Control.Concurrent as C
import Control.Concurrent.MVar
  (MVar, newMVar, withMVar, modifyMVar, modifyMVar_)
import qualified Control.Exception as E
import Control.Monad (unless)
import qualified Data.Foldable as F
import qualified Data.Map as M
import qualified Data.Set as S
import Data.Dynamic (Dynamic, fromDynamic, toDyn, Typeable)
import Data.List (nub)
import Data.Unique (Unique, newUnique)
import System.Exit (ExitCode(ExitSuccess))
import System.IO (hPutStrLn, hFlush, stderr)
import System.IO.Unsafe (unsafePerformIO)

import TorDNSEL.Util

-- | An abstract type representing a handle to a linkable thread. Holding a
-- 'ThreadId', unlike a 'C.ThreadId', won't prevent a dead thread from being
-- garbage collected.
newtype ThreadId = Tid Unique
  deriving (Eq, Ord)

-- | Return the 'ThreadId' of the calling thread.
myThreadId :: IO ThreadId
myThreadId = do
  me <- C.myThreadId
  withMVar threadMap $ \tm -> return $! ident (state tm M.! me)

type StateModifier =
  M.Map C.ThreadId ThreadState ->  M.Map C.ThreadId ThreadState

-- | Holds the 'ThreadId' to 'C.ThreadId' mappings and 'ThreadState' for every
-- running thread.
data ThreadMap = ThreadMap
  { ids   :: !(M.Map ThreadId C.ThreadId)
  , state :: !(M.Map C.ThreadId ThreadState) }

-- | State necessary for supporting links and monitors.
data ThreadState = ThreadState
  { ident     :: !ThreadId
  , signal    :: !(ThreadId -> ExitReason -> IO ())
  , links     :: !(S.Set C.ThreadId)
  , monitors  :: !(M.Map Unique (ExitReason -> IO (), StateModifier))
  , ownedMons :: !(S.Set (C.ThreadId, Unique)) }

-- | A mutable variable holding the link and monitor state.
threadMap :: MVar ThreadMap
{-# NOINLINE threadMap #-}
threadMap = unsafePerformIO . newMVar $ ThreadMap M.empty M.empty

-- | Assert various invariants of the global link and monitor state, printing a
-- message to stdout if any assertions fail.
assertThreadMap :: ThreadMap -> IO ()
assertThreadMap tm =
  E.handleJust E.assertions (putStr . ("assertThreadMap: " ++)) $
    E.assert (M.size (ids tm) > 0) $
    E.assert (M.size (ids tm) == M.size (state tm)) $
    E.assert (M.elems (ids tm) == nub (M.elems (ids tm))) $
    E.assert (all (`M.member` state tm) (M.elems (ids tm))) $
    E.assert (F.and (M.mapWithKey (\tid tid' ->
               tid == ident (state tm M.! tid'))
               (ids tm))) $
    E.assert (F.all (F.all (`M.member` state tm) . links) (state tm)) $
    E.assert (F.and (M.mapWithKey (\tid ts ->
               F.all (S.member tid . links . (state tm M.!))
                     (links ts))
               (state tm))) $
    E.assert (F.all (F.all (\(tid,monId) ->
               (M.member monId . monitors) `fmap` M.lookup tid (state tm)
                 == Just True) . ownedMons)
               (state tm)) $
    return ()

-- | An internal type used to transmit the originating 'ThreadId' in an
-- asynchronous exception to a linked thread.
data ExitSignal = ExitSignal !ThreadId !ExitReason
  deriving Typeable

-- | Extract the 'ExitReason' from an 'ExitSignal' contained within a
-- dynamically-typed exception. If the exception doesn't contain an
-- 'ExitSignal', tag it with 'Just'.
extractReason :: E.Exception -> ExitReason
extractReason (E.DynException dyn)
  | Just (ExitSignal _ e) <- fromDynamic dyn = e
extractReason e                              = Just e

-- | Extract an exit signal from an 'E.Exception' if it has the right type.
fromExitSignal :: Typeable a => E.Exception -> Maybe (ThreadId, a)
fromExitSignal (E.DynException d)
  | Just (ExitSignal tid (Just (E.DynException d'))) <- fromDynamic d
  = (,) tid `fmap` fromDynamic d'
fromExitSignal _ = Nothing

-- | The default action used to signal a thread. Abnormal 'ExitReason's are
-- sent to the thread and normal exits are ignored.
defaultSignal :: C.ThreadId -> ThreadId -> ExitReason -> IO ()
defaultSignal dst src e@(Just _) = E.throwDynTo dst $ ExitSignal src e
defaultSignal _   _      Nothing = return ()

-- | Initialize the state supporting links and monitors. Use the given function
-- to display an uncaught exception. It is an error to call this function
-- outside the main thread, or to call any other functions in this module
-- outside this function.
withLinksDo :: (E.Exception -> String) -> IO a -> IO ()
withLinksDo showE io = E.block $ do
  E.setUncaughtExceptionHandler . const . return $ ()
  main <- C.myThreadId
  mainId <- Tid `fmap` newUnique
  let initialState = ThreadState
        { ident     = mainId
        , signal    = defaultSignal main
        , links     = S.empty
        , monitors  = M.empty
        , ownedMons = S.empty }
  modifyMVar_ threadMap $ \tm -> return $!
    E.assert (M.size (ids tm) == 0) $
    E.assert (M.size (state tm) == 0) $
    tm { ids   = M.insert mainId main (ids tm)
       , state = M.insert main initialState (state tm) }
  -- Don't bother propagating signals from the main thread
  -- since it's about to exit.
  (E.unblock io >> return ()) `E.catch` \e ->
    case extractReason e of
      Nothing                            -> return ()
      Just (E.ExitException ExitSuccess) -> return ()
      Just e' -> do
        hPutStrLn stderr ("*** Exception: " ++ showE e')
        hFlush stderr
        E.throwIO e'

-- | Evaluate the given 'IO' action in a new thread, returning its 'ThreadId'.
forkIO :: IO a -> IO ThreadId
forkIO = forkLinkIO' False

-- | Like 'forkIO', except a link is atomically established between the new
-- thread and the calling thread.
forkLinkIO :: IO a -> IO ThreadId
forkLinkIO = forkLinkIO' True

forkLinkIO' :: Bool -> IO a -> IO ThreadId
forkLinkIO' shouldLink io = E.block $ do
  parent <- C.myThreadId
  childId <- Tid `fmap` newUnique
  modifyMVar_ threadMap $ \tm -> do
    assertThreadMap tm
    child <- forkHandler $ do
      child <- C.myThreadId
      e <- either extractReason (const Nothing) `fmap` E.try (E.unblock io)
      -- modifyMVar is interruptible (a misfeature in this case), so an async
      -- exception could be delivered here. Forking an anonymous thread should
      -- avoid this race since nobody can throwTo it.
      forkHandler $ do
        withMVar threadMap assertThreadMap
        (signalAll,notifyAll) <- modifyMVar threadMap $ \tm1 -> return $!
          let s = state tm1 M.! child
              unlinkAll = flip (F.foldl' (flip (child `unlinkFrom`))) (links s)
              deleteMonitors =
                flip (F.foldl' (\a (_,cleanup) -> cleanup a)) (monitors s) .
                flip (F.foldl' (\a (tid,monId) ->
                  M.adjust (\ts -> ts {monitors = M.delete monId (monitors ts)})
                           tid a)) (ownedMons s)
              newIds = M.delete childId (ids tm1)
              newState = M.delete child . deleteMonitors . unlinkAll $ state tm1
              signalThread ex tid = signal (state tm1 M.! tid) childId ex
              signalAll ex = F.mapM_ (forkHandler . signalThread ex) (links s)
              notifyAll ex = F.mapM_ (forkHandler . ($ ex) . fst) (monitors s)
          in (tm1 { ids = newIds, state = newState }, (signalAll, notifyAll))
        withMVar threadMap assertThreadMap
        notifyAll e
        signalAll e

    let (linkedThrs, linkToParent)
          | shouldLink = (S.singleton parent, child `linkTo` parent)
          | otherwise  = (S.empty, id)
        initialState = ThreadState
          { ident     = childId
          , signal    = defaultSignal child
          , links     = linkedThrs
          , monitors  = M.empty
          , ownedMons = S.empty }

    return $!
      tm { ids   = M.insert childId child $ ids tm
         , state = M.insert child initialState . linkToParent $ state tm }

  withMVar threadMap assertThreadMap
  return childId
  where
    forkHandler = C.forkIO . ignore . (>> return ()) . E.block
    ignore = E.handle . const . return $ ()

-- | Establish a bidirectional link between the calling thread and a given
-- thread. If either thread terminates, an exit signal will be sent to the other
-- thread, causing it to terminate and propagate the signal further if it isn't
-- trapping signals. If the given thread doesn't exist, an exit signal of
-- 'NonexistentThread' will be sent to the calling thread.
linkThread :: ThreadId -> IO ()
linkThread tid = do
  me <- C.myThreadId
  mbSignalSelf <- modifyMVar threadMap $ \tm -> return $!
    case M.lookup tid (ids tm) of
      Just tid'
        | tid' == me -> (tm, Nothing)
        | otherwise -> (tm { state = linkTogether me tid' $ state tm }, Nothing)
      Nothing ->
        let s = state tm M.! me
        in (tm, Just . signal s (ident s) . Just . E.DynException . toDyn $
                NonexistentThread)
  whenJust mbSignalSelf id
  where linkTogether x y = (x `linkTo` y) . (y `linkTo` x)

-- | Dissolve a link between the calling thread and a given thread, if a link
-- exists.
unlinkThread :: ThreadId -> IO ()
unlinkThread tid = do
  me <- C.myThreadId
  modifyMVar_ threadMap $ \tm -> return $!
    case M.lookup tid (ids tm) of
      Just tid' | tid' /= me -> tm { state = breakLinks me tid' $ state tm }
      _                      -> tm
  where breakLinks x y = (x `unlinkFrom` y) . (y `unlinkFrom` x)

linkTo, unlinkFrom :: C.ThreadId -> C.ThreadId -> StateModifier
(linkTo, unlinkFrom) = (adjustLinks S.insert, adjustLinks S.delete)
  where adjustLinks f tid = M.adjust $ \ts -> ts { links = tid `f` links ts }

-- | An abstract type representing a handle to a particular monitoring of one
-- thread by another.
data Monitor = Monitor !ThreadId !Unique
  deriving (Eq, Ord)

-- | The reason a thread was terminated. @Nothing@ means the thread exited
-- normally. @Just exception@ contains the reason for an abnormal exit.
type ExitReason = Maybe E.Exception

-- | Start monitoring the given thread, invoking an 'IO' action with the
-- 'ExitReason' when the thread dies. Return a handle to the monitor, which can
-- be passed to 'demonitorThread'. If the thread doesn't exist, the action will
-- be immediately called with 'NonexistentThread'. The calling thread becomes
-- the monitor's owner; if it dies, the monitoring will be cancelled.
monitorThread :: ThreadId -> (ExitReason -> IO ()) -> IO Monitor
monitorThread tid notify = do
  me <- C.myThreadId
  mon@(Monitor _ monId) <- Monitor tid `fmap` newUnique
  let cleanup tid' = M.adjust (\ts ->
        ts { ownedMons = S.delete (tid', monId) (ownedMons ts) }) me
      addMon tid' ts = ts { monitors = M.insert monId (notify, cleanup tid')
                                                (monitors ts) }
      addOwned tid' ts = ts {ownedMons = S.insert (tid', monId) (ownedMons ts)}
  exists <- modifyMVar threadMap $ \tm -> return $!
    case M.lookup tid (ids tm) of
      Nothing   -> (tm, False)
      Just tid' -> (tm { state = M.adjust (addMon tid') tid' .
                                 M.adjust (addOwned tid') me $ state tm }, True)
  unless exists $
    notify . Just . E.DynException . toDyn $ NonexistentThread
  return mon

-- | Cancel a monitor, if it is currently active.
demonitorThread :: Monitor -> IO ()
demonitorThread (Monitor tid monId) = do
  me <- C.myThreadId
  modifyMVar_ threadMap $ \tm -> return $!
    case M.lookup tid (ids tm) of
      Nothing   -> tm
      Just tid' -> tm { state = M.adjust deleteMon tid' .
                                M.adjust (deleteOwned tm) me $ state tm }
  where
    deleteMon      ts = ts { monitors = M.delete monId (monitors ts) }
    deleteOwned tm ts = ts { ownedMons = S.delete (ids tm M.! tid, monId)
                                                  (ownedMons ts) }

-- | Like 'monitorThread', except an 'IO' action is invoked after the monitoring
-- has started, and the monitor is safely released after the action returns,
-- even if the action throws an exception.
withMonitor :: ThreadId -> (ExitReason -> IO ()) -> IO a -> IO a
withMonitor tid notify =
  E.bracket (monitorThread tid notify) demonitorThread . const

-- | Terminate the calling thread with the given 'ExitReason'.
exit :: ExitReason -> IO a
exit e = E.throwDyn . flip ExitSignal e =<< myThreadId

-- | Send an exit signal with an 'ExitReason' to a thread. If the 'ExitReason'
-- is 'Nothing', the signal will be ignored unless the target thread is trapping
-- signals. Otherwise, the target thread will either exit with the same
-- 'ExitReason' or be notified of the signal depending on whether it is trapping
-- signals. If the target thread doesn't exist, do nothing.
throwTo :: ThreadId -> ExitReason -> IO ()
throwTo tid e = do
  me <- C.myThreadId
  mbSignal <- withMVar threadMap $ \tm ->
    let me' = ident (state tm M.! me)
    in if tid == me'
         -- special case: an exception thrown to oneself is untrappable
         then E.throwDyn $ ExitSignal me' e
         else return $ do tid' <- M.lookup tid (ids tm)
                          return $ signal (state tm M.! tid') me'
  -- since signal can block, we don't want to hold a lock on threadMap
  whenJust mbSignal ($ e)

-- | A variant of 'throwTo' for dynamically typed 'ExitReason's.
throwDynTo :: Typeable a => ThreadId -> a -> IO ()
throwDynTo tid = throwTo tid . Just . E.DynException . toDyn

-- | Send an untrappable exit signal to a thread, if it exists.
killThread :: ThreadId -> IO ()
killThread tid = do
  me <- C.myThreadId
  mbSignal <- withMVar threadMap $ \tm -> return $ do
    tid' <- M.lookup tid (ids tm)
    return .
      E.throwDynTo tid' $ ExitSignal (ident (state tm M.! me))
                                     (Just (E.AsyncException E.ThreadKilled))
  whenJust mbSignal id

-- | Redirect exit signals destined for the calling thread to the given 'IO'
-- action. Exit signals contain the 'ThreadId' of the immediate sender and the
-- original 'ExitReason'.
setTrapExit :: (ThreadId -> ExitReason -> IO ()) -> IO ()
setTrapExit notify = do
  me <- C.myThreadId
  modifyMVar_ threadMap $ \tm -> return $!
    tm { state = M.adjust (\ts -> ts { signal = notify }) me (state tm) }

-- | Deliver exit signals destined for the calling thread normally, that is,
-- exit signals will terminate the calling thread and propagate to any threads
-- linked to the calling thread.
unsetTrapExit :: IO ()
unsetTrapExit = setTrapExit . defaultSignal =<< C.myThreadId

-- | An exception related to links or monitors.
data LinkException = NonexistentThread -- ^ 
  deriving (Eq, Typeable)

instance Show LinkException where
  show NonexistentThread = "Attempt to link to nonexistent thread"

-- | Boilerplate conversion of a dynamically typed 'LinkException' to a string.
showLinkException :: Dynamic -> Maybe String
showLinkException = fmap (show :: LinkException -> String) . fromDynamic
