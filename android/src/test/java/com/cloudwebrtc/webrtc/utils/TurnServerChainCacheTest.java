package com.cloudwebrtc.webrtc.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Test;

import com.cloudwebrtc.webrtc.utils.TurnServerChainCache.Result;

/** Deterministic scheduling tests; real TLS is covered by TurnServerChainsTest. */
public class TurnServerChainCacheTest {
  private static long ms(long value) {
    return TimeUnit.MILLISECONDS.toNanos(value);
  }

  private static final class QueueExecutor implements Executor {
    final Queue<Runnable> tasks = new ArrayDeque<>();

    @Override
    public void execute(Runnable task) {
      tasks.add(task);
    }

    void drain() {
      while (!tasks.isEmpty()) {
        tasks.remove().run();
      }
    }
  }

  @Test
  public void cacheOnlyReadsDoNotCreateOrStartWork() {
    QueueExecutor executor = new QueueExecutor();
    AtomicInteger calls = new AtomicInteger();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      calls.incrementAndGet();
      return Result.FAILURE;
    }, System::nanoTime, executor, ms(2300), 8);

    cache.get("cold", 0);
    cache.get("cold", -1);
    assertTrue(executor.tasks.isEmpty());
    assertEquals(0, calls.get());
    cache.warm("queued");
    cache.get("queued", 0);
    assertEquals(0, calls.get());
    cache.get("queued", ms(100));
    executor.drain();
    assertEquals(1, calls.get());
  }

  @Test
  public void queueDelayDoesNotConsumeTheLookupAllowance() {
    AtomicLong now = new AtomicLong();
    AtomicLong seenDeadline = new AtomicLong();
    QueueExecutor executor = new QueueExecutor();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      seenDeadline.set(due);
      return Result.FAILURE;
    }, now::get, executor, ms(2300), 8);
    cache.warm("queued");
    now.set(ms(4000));
    executor.drain();
    assertEquals(ms(6300), seenDeadline.get());
  }

  @Test
  public void staleAndRejectedWarmUpsRemainRetryable() {
    AtomicLong now = new AtomicLong();
    AtomicInteger calls = new AtomicInteger();
    QueueExecutor executor = new QueueExecutor();
    TurnServerChainCache.Loader loader = (endpoint, due) -> {
      calls.incrementAndGet();
      return Result.FAILURE;
    };
    TurnServerChainCache cache = new TurnServerChainCache(loader, now::get, executor, ms(2300), 8);
    cache.warm("stale");
    now.set(ms(16000));
    executor.drain();
    assertEquals(0, calls.get());
    cache.get("stale", ms(100));
    assertEquals(1, calls.get());

    TurnServerChainCache rejected = new TurnServerChainCache(loader, now::get,
            task -> { throw new RejectedExecutionException(); }, ms(2300), 8);
    rejected.warm("rejected");
    rejected.get("rejected", ms(100));
    assertEquals(2, calls.get());
  }

  @Test
  public void callerTimeoutIsRetryableButEndpointFailureIsCachedFromCompletion() {
    AtomicLong now = new AtomicLong();
    AtomicInteger calls = new AtomicInteger();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      if (calls.incrementAndGet() == 1) {
        return Result.RETRY;
      }
      now.addAndGet(ms(500));
      return Result.FAILURE;
    }, now::get, new QueueExecutor(), ms(2300), 8);
    cache.get("host", ms(1000));
    cache.get("host", ms(1000));
    assertEquals(2, calls.get());
    now.set(ms(60200)); // Under a minute since completion, over a minute since entry creation.
    cache.get("host", ms(1000));
    assertEquals(2, calls.get());
    now.set(ms(60501));
    cache.get("host", ms(1000));
    assertEquals(3, calls.get());
  }

  @Test
  public void anAuthenticatedEmptyChainGetsTheSuccessTtl() {
    AtomicLong now = new AtomicLong();
    AtomicInteger calls = new AtomicInteger();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      calls.incrementAndGet();
      return Result.learned(Collections.emptyList());
    }, now::get, new QueueExecutor(), ms(2300), 8);
    cache.get("host", ms(100));
    now.set(ms(61000));
    cache.get("host", ms(100));
    assertEquals(1, calls.get());
    now.set(TimeUnit.MINUTES.toNanos(31));
    cache.get("host", ms(100));
    assertEquals(2, calls.get());
  }

  @Test
  public void evictionCannotRunAnObsoleteQueuedTask() {
    QueueExecutor executor = new QueueExecutor();
    AtomicInteger calls = new AtomicInteger();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      assertEquals("new", endpoint);
      calls.incrementAndGet();
      return Result.FAILURE;
    }, System::nanoTime, executor, ms(2300), 1);
    cache.warm("old");
    cache.warm("new");
    executor.drain();
    assertEquals(1, calls.get());
  }

  @Test
  public void concurrentWaiterCannotReplaceTheOwnersDeadlineOrDuplicateWork() throws Exception {
    CountDownLatch loading = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger calls = new AtomicInteger();
    AtomicLong deadline = new AtomicLong();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      calls.incrementAndGet();
      deadline.set(due);
      loading.countDown();
      await(release);
      return Result.learned(Collections.emptyList());
    }, System::nanoTime, new QueueExecutor(), ms(2300), 1);
    FutureTask<?> owner = new FutureTask<>(() -> cache.get("host", ms(2000)));
    Thread thread = new Thread(owner);
    thread.start();
    try {
      assertTrue(loading.await(2, TimeUnit.SECONDS));
      long ownedDeadline = deadline.get();
      long began = System.nanoTime();
      cache.get("host", ms(20));
      assertTrue(System.nanoTime() - began < ms(500));
      cache.warm("another"); // A full cache must not evict the active lookup.
      assertEquals(1, calls.get());
      assertEquals(ownedDeadline, deadline.get());
    } finally {
      release.countDown();
      thread.join(2000);
    }
    owner.get(1, TimeUnit.SECONDS);
    cache.get("host", ms(100));
    assertEquals(1, calls.get());
  }

  @Test
  public void interruptedWaiterDoesNotCancelSharedWork() throws Exception {
    CountDownLatch loading = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      loading.countDown();
      await(release);
      return Result.learned(Collections.emptyList());
    }, System::nanoTime, new QueueExecutor(), ms(2300), 8);
    Thread owner = new Thread(() -> cache.get("host", ms(3000)));
    owner.start();
    assertTrue(loading.await(2, TimeUnit.SECONDS));
    FutureTask<Boolean> interrupted = new FutureTask<>(() -> {
      cache.get("host", ms(2000));
      return Thread.currentThread().isInterrupted();
    });
    Thread waiter = new Thread(interrupted);
    waiter.start();
    waiter.interrupt();
    try {
      assertTrue(interrupted.get(1, TimeUnit.SECONDS));
      assertTrue(owner.isAlive());
    } finally {
      release.countDown();
      owner.join(2000);
      waiter.join(2000);
    }
    assertFalse(owner.isAlive());
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(3, TimeUnit.SECONDS)) {
        throw new AssertionError("test loader was not released");
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    }
  }

  @Test
  public void aLongerWaiterCanRetryAfterTheOwnersBudgetRunsOut() throws Exception {
    CountDownLatch loading = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger calls = new AtomicInteger();
    TurnServerChainCache cache = new TurnServerChainCache((endpoint, due) -> {
      if (calls.incrementAndGet() == 1) {
        loading.countDown();
        await(release);
        return Result.RETRY;
      }
      return Result.learned(Collections.emptyList());
    }, System::nanoTime, new QueueExecutor(), ms(2300), 8);
    Thread owner = new Thread(() -> cache.get("host", ms(1)));
    owner.start();
    FutureTask<?> waiter = new FutureTask<>(() -> cache.get("host", ms(2000)));
    Thread joining = new Thread(waiter);
    try {
      assertTrue(loading.await(2, TimeUnit.SECONDS));
      joining.start();
      Thread.sleep(20); // Let the owner's much smaller budget expire.
    } finally {
      release.countDown();
      owner.join(2000);
      joining.join(2000);
    }
    waiter.get(1, TimeUnit.SECONDS);
    assertEquals("retry the caller-local timeout, without duplicating the active lookup", 2, calls.get());
  }
}
