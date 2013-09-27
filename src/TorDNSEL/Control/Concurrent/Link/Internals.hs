{-# LANGUAGE CPP #-}
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

import qualified Control.Exception as E
import qualified Control.Concurrent as C
import Control.Concurrent.MVar
  (MVar, newMVar, withMVar, modifyMVar, modifyMVar_)
import GHC.Conc (setUncaughtExceptionHandler)
import System.Exit (ExitCode)
import Control.Monad (unless)
import Data.Functor
import qualified Data.Foldable as F
import qualified Data.Map as M
import qualified Data.Set as S
--  import Data.Dynamic (Dynamic, fromDynamic, toDyn, Typeable)
import Data.Typeable (Typeable)
import Data.List (nub)
import Data.Unique (Unique, newUnique)
import System.IO (hPutStrLn, hFlush, stderr)
import System.IO.Unsafe (unsafePerformIO)

import TorDNSEL.Util

-- | An abstract type representing a handle to a linkable thread. Holding a
-- 'ThreadId', unlike a 'C.ThreadId', won't prevent a dead thread from being
-- garbage collected.
newtype ThreadId = Tid Unique
  deriving (Eq, Ord)

-- ( Else an orphaned Show Unique... )
instance Show ThreadId where show _ = "#<thread>"

-- | Return the 'ThreadId' of the calling thread.
myThreadId :: IO ThreadId
myThreadId = do
  me <- C.myThreadId
  withMVar threadMap $ \tm -> return $! ident (state tm M.! me)

type StateModifier =
  M.Map C.ThreadId ThreadState -> M.Map C.ThreadId ThreadState

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

-- | Erase 'threadMap', making it possible to re-run 'withLinksDo'. For
-- debugging only, as it loses track of threads.
unsafeResetThreadMap :: IO ()
unsafeResetThreadMap =
  modifyMVar_ threadMap $ const . return $ ThreadMap M.empty M.empty

-- | Assert various invariants of the global link and monitor state, printing a
-- message to stdout if any assertions fail.
assertThreadMap :: ThreadMap -> IO ()
assertThreadMap tm =
  E.handle (\(E.AssertionFailed msg) -> putStrLn $ "assertThreadMap: " ++ msg) $
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
  deriving (Show, Typeable)

instance E.Exception ExitSignal

-- | Extract the 'ExitReason' from an 'ExitSignal' contained within an
-- exception. If the exception doesn't contain an 'ExitReason', it becomes the
-- exit reason itself.
extractReason :: E.SomeException -> ExitReason
extractReason (E.fromException -> Just (ExitSignal _ e)) = e
extractReason e                                          = AbnormalExit e

-- | Extract a particular exception type from an 'ExitSignal', if present.
fromExitSignal :: E.Exception e => ExitSignal -> Maybe (ThreadId, e)
fromExitSignal (ExitSignal tid (AbnormalExit e))
  | Just e' <- E.fromException e = Just (tid, e')
fromExitSignal _ = Nothing

-- | The default action used to signal a thread. Abnormal 'ExitReason's are
-- sent to the thread and normal exits are ignored.
defaultSignal :: C.ThreadId -> ThreadId -> ExitReason -> IO ()
defaultSignal _   _   NormalExit = return ()
defaultSignal dst src e          = E.throwTo dst $ ExitSignal src e

-- | Initialize the state supporting links and monitors. It is an error to call
-- this function outside the main thread, or to call any other functions in this
-- module outside this function.
withLinksDo :: IO a -> IO ()
withLinksDo io = E.mask $ \restore -> do
  setUncaughtExceptionHandler . const . return $ ()
  main   <- C.myThreadId
  mainId <- Tid `fmap` newUnique
  let initialState = ThreadState
        { ident     = mainId
        , signal    = defaultSignal main
        , links     = S.empty
        , monitors  = M.empty
        , ownedMons = S.empty }
  modifyMVar_ threadMap $ \tm ->
    E.assert (M.size (ids tm) == 0) $
    E.assert (M.size (state tm) == 0) $
    return $! initialState `seq`
      tm { ids   = M.insert mainId main (ids tm)
         , state = M.insert main initialState (state tm) }
  -- Don't bother propagating signals from the main thread
  -- since it's about to exit.
  (() <$ restore io) `E.catch` \(e :: E.SomeException) ->
    case extractReason e of
      NormalExit -> return ()
      AbnormalExit (E.fromException -> Just e') ->
        E.throwIO (e' :: ExitCode)
      AbnormalExit e' -> do
        hPutStrLn stderr ("*** Exception: " ++ show e')
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
forkLinkIO' shouldLink io = E.mask $ \restore -> do
  parent  <- C.myThreadId
  childId <- Tid `fmap` newUnique
  modifyMVar_ threadMap $ \tm -> do
#ifdef DEBUG
    assertThreadMap tm
#endif
    child <- forkHandler $ do
      child <- C.myThreadId
      e     <- either (extractReason :: E.SomeException -> ExitReason)
                      (const NormalExit)
                `fmap` E.try (restore io)
      -- modifyMVar is interruptible (a misfeature in this case), so an async
      -- exception could be delivered here. Forking an anonymous thread should
      -- avoid this race since nobody can throwTo it.
      forkHandler $ do
#ifdef DEBUG
        withMVar threadMap assertThreadMap
#endif
        (signalAll,notifyAll) <- modifyMVar threadMap $ \tm1 ->
          let s = state tm1 M.! child
              unlinkAll = flip (F.foldl' (flip (child `unlinkFrom`))) (links s)
              deleteMonitors =
                flip (F.foldl' (\a (_,cleanup) -> cleanup a)) (monitors s) .
                flip (F.foldl' (\a (tid,monId) ->
                  adjust' (\ts -> ts {monitors = M.delete monId (monitors ts)})
                          tid a)) (ownedMons s)
              newIds = M.delete childId (ids tm1)
              newState = M.delete child . deleteMonitors . unlinkAll $ state tm1
              signalThread ex tid = signal (state tm1 M.! tid) childId ex
              signalAll ex = F.mapM_ (forkHandler . signalThread ex) (links s)
              notifyAll ex = F.mapM_ (forkHandler . ($ ex) . fst) (monitors s)
              tm1' = tm1 { ids = newIds, state = newState }
          in tm1' `seq` return (tm1', (signalAll, notifyAll))
#ifdef DEBUG
        withMVar threadMap assertThreadMap
#endif
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

    return $! initialState `seq`
      tm { ids   = M.insert childId child $ ids tm
         , state = M.insert child initialState . linkToParent $ state tm }

#ifdef DEBUG
  withMVar threadMap assertThreadMap
#endif
  return childId

  where
    forkHandler a = E.mask_ . C.forkIO $
      (() <$ a) `E.catch` \(_ :: E.SomeException) -> return ()

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
        | otherwise  -> (tm', Nothing)
        where !tm' = tm { state = linkTogether me tid' $ state tm }
      Nothing -> (tm, Just . signal s tid $ exitReason NonexistentThread)
        where s = state tm M.! me
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
  where adjustLinks f tid = adjust' $ \ts -> ts { links = tid `f` links ts }

-- | An abstract type representing a handle to a particular monitoring of one
-- thread by another.
data Monitor = Monitor !ThreadId !Unique
  deriving (Eq, Ord)

-- | The reason a thread was terminated.
data ExitReason = NormalExit | AbnormalExit E.SomeException
  deriving (Show)

-- | Construct an 'ExitReason' from any 'E.Exception'.
exitReason :: E.Exception e => e -> ExitReason
exitReason = AbnormalExit . E.toException

isAbnormal :: ExitReason -> Bool
isAbnormal (AbnormalExit _) = True
isAbnormal _                = False

-- | Check the exit reason and re-throw it if it's an 'AbnormalExit'.
throwAbnormal :: ExitReason -> IO ()
throwAbnormal NormalExit       = return ()
throwAbnormal (AbnormalExit e) = E.throwIO e

-- | Start monitoring the given thread, invoking an 'IO' action with the
-- 'ExitReason' when the thread dies. Return a handle to the monitor, which can
-- be passed to 'demonitorThread'. If the thread doesn't exist, the action will
-- be immediately called with 'NonexistentThread'. The calling thread becomes
-- the monitor's owner; if it dies, the monitoring will be cancelled.
monitorThread :: ThreadId -> (ExitReason -> IO ()) -> IO Monitor
monitorThread tid notify = do
  me <- C.myThreadId
  mon@(Monitor _ monId) <- Monitor tid `fmap` newUnique
  let cleanup tid' = flip adjust' me $ \ts ->
        ts { ownedMons = S.delete (tid', monId) (ownedMons ts) }
      addMon tid' ts = ts { monitors = M.insert monId (notify, cleanup tid')
                                                (monitors ts) }
      addOwned tid' ts = ts {ownedMons = S.insert (tid', monId) (ownedMons ts)}
  exists <- modifyMVar threadMap $ \tm -> return $!
    case M.lookup tid (ids tm) of
      Nothing   -> (tm, False)
      Just tid' -> (tm', True)
        where !tm' = tm { state = adjust' (addMon tid') tid' .
                                  adjust' (addOwned tid') me $ state tm }
  unless exists $
    notify $ exitReason NonexistentThread
  return mon

-- | Cancel a monitor, if it is currently active.
demonitorThread :: Monitor -> IO ()
demonitorThread (Monitor tid monId) = do
  me <- C.myThreadId
  modifyMVar_ threadMap $ \tm -> return $!
    case M.lookup tid (ids tm) of
      Nothing   -> tm
      Just tid' -> tm { state = adjust' deleteMon tid' .
                                adjust' (deleteOwned tm) me $ state tm }
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
exit e = E.throwIO . (`ExitSignal` e) =<< myThreadId

-- | Send an exit signal with an 'ExitReason' to a thread. If the 'ExitReason'
-- is 'NormalExit', the signal will be ignored unless the target thread is trapping
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
         then E.throwIO $ ExitSignal me' e
         else return $ do tid' <- M.lookup tid (ids tm)
                          return $ signal (state tm M.! tid') me'
  -- since signal can block, we don't want to hold a lock on threadMap
  whenJust mbSignal ($ e)

-- | Send an untrappable exit signal to a thread, if it exists.
killThread :: ThreadId -> IO ()
killThread tid = do
  me <- C.myThreadId
  mbSignal <- withMVar threadMap $ \tm -> return $ do
    tid' <- M.lookup tid (ids tm)
    return . E.throwTo tid' $ ExitSignal (ident (state tm M.! me))
                                         (exitReason E.ThreadKilled)
  whenJust mbSignal id

-- | Redirect exit signals destined for the calling thread to the given 'IO'
-- action. Exit signals contain the 'ThreadId' of the immediate sender and the
-- original 'ExitReason'.
setTrapExit :: (ThreadId -> ExitReason -> IO ()) -> IO ()
setTrapExit notify = do
  me <- C.myThreadId
  modifyMVar_ threadMap $ \tm -> return $!
    tm { state = adjust' (\ts -> ts { signal = notify }) me (state tm) }

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

instance E.Exception LinkException
