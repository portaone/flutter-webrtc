package com.cloudwebrtc.webrtc.utils;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Owns shared lookups; TLS and trust decisions belong to the loader. */
final class TurnServerChainCache {
  interface Clock {
    long nanoTime();
  }

  interface Loader {
    Result load(String endpoint, long deadline);
  }

  /** A caller running out of time is not a failed endpoint attempt. */
  static final class Result {
    static final Result RETRY = new Result(Collections.emptyList(), 0);
    static final Result FAILURE = new Result(Collections.emptyList(), TimeUnit.MINUTES.toNanos(1));

    final List<X509Certificate> certificates;
    final long ttl;

    private Result(List<X509Certificate> certificates, long ttl) {
      this.certificates = Collections.unmodifiableList(new ArrayList<>(certificates));
      this.ttl = ttl;
    }

    static Result learned(List<X509Certificate> certificates) {
      return new Result(certificates, TimeUnit.MINUTES.toNanos(30));
    }
  }

  private static final long QUEUE_TTL = TimeUnit.SECONDS.toNanos(15);
  private final Map<String, Entry> entries = new LinkedHashMap<>();
  private final Loader loader;
  private final Clock clock;
  private final Executor warmer;
  private final long warmBudget;
  private final int capacity;

  TurnServerChainCache(Loader loader, Clock clock, Executor warmer, long warmBudget, int capacity) {
    this.loader = loader;
    this.clock = clock;
    this.warmer = warmer;
    this.warmBudget = warmBudget;
    this.capacity = capacity;
  }

  void warm(String endpoint) {
    Entry entry;
    synchronized (entries) {
      if (find(endpoint) != null) {
        return;
      }
      entry = create(endpoint);
    }
    if (entry != null) {
      try {
        warmer.execute(entry);
      } catch (RejectedExecutionException busy) {
        // Never retain work that nobody will run. A concurrent caller may already own it.
        discardQueued(entry);
      }
    }
  }

  List<X509Certificate> get(String endpoint, long waitNanos) {
    long deadline = clock.nanoTime() + Math.max(0, waitNanos);
    // A longer-lived waiter may retry work abandoned by its short-lived owner, once.
    for (int attempt = 0; attempt < 2; attempt++) {
      boolean canWait = deadline - clock.nanoTime() > 0 && !Thread.currentThread().isInterrupted();
      Entry entry;
      synchronized (entries) {
        entry = find(endpoint);
        if (entry == null && canWait) {
          entry = create(endpoint);
        }
      }
      if (entry == null) {
        return Collections.emptyList();
      }
      // Cache-only reads cannot enqueue work or change an existing lookup's deadline.
      if (!canWait) {
        return entry.finished().certificates;
      }
      try {
        FutureTask<Result> task = entry.start(deadline);
        Result result = task.get(Math.max(0, deadline - clock.nanoTime()), TimeUnit.NANOSECONDS);
        if (result != Result.RETRY) {
          return result.certificates;
        }
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        break;
      } catch (ExecutionException | TimeoutException unavailable) {
        // Other waiters keep their result and their deadline.
        break;
      }
    }
    return Collections.emptyList();
  }

  // Membership is guarded by entries; network work never runs under this lock.
  private Entry find(String endpoint) {
    Entry entry = entries.get(endpoint);
    if (entry != null && entry.expired(clock.nanoTime())) {
      entries.remove(endpoint);
      removeQueued(entry);
      return null;
    }
    return entry;
  }

  private Entry create(String endpoint) {
    long now = clock.nanoTime();
    for (Iterator<Entry> it = entries.values().iterator(); it.hasNext(); ) {
      Entry entry = it.next();
      if (entry.expired(now)) {
        it.remove();
        removeQueued(entry);
      }
    }
    if (entries.size() >= capacity) {
      // Evict finished/queued work only. Evicting an active lookup could duplicate its socket.
      for (Iterator<Entry> it = entries.values().iterator(); it.hasNext(); ) {
        Entry entry = it.next();
        if (entry.evictable()) {
          it.remove();
          removeQueued(entry);
          break;
        }
      }
    }
    if (entries.size() >= capacity) {
      return null;
    }
    Entry entry = new Entry(endpoint, now);
    entries.put(endpoint, entry);
    return entry;
  }

  private void discardQueued(Entry entry) {
    synchronized (entries) {
      if (entries.get(entry.endpoint) == entry && entry.discard()) {
        entries.remove(entry.endpoint);
        removeQueued(entry);
      }
    }
  }

  private void removeQueued(Entry entry) {
    if (warmer instanceof ThreadPoolExecutor) {
      ((ThreadPoolExecutor) warmer).remove(entry);
    }
  }

  private final class Entry implements Runnable {
    final String endpoint;
    final long queuedAt;
    private FutureTask<Result> task;
    private boolean discarded;
    private volatile long completedAt;

    Entry(String endpoint, long queuedAt) {
      this.endpoint = endpoint;
      this.queuedAt = queuedAt;
    }

    @Override
    public void run() {
      if (clock.nanoTime() - queuedAt >= QUEUE_TTL) {
        discardQueued(this);
      } else {
        start(clock.nanoTime() + warmBudget);
      }
    }

    FutureTask<Result> start(final long deadline) {
      FutureTask<Result> running;
      boolean owner = false;
      synchronized (this) {
        if (task == null) {
          owner = true;
          // The first owner captures an immutable deadline. Joining callers cannot overwrite it.
          task = new FutureTask<>(() -> {
            try {
              return discarded || deadline - clock.nanoTime() <= 0
                      ? Result.RETRY : loader.load(endpoint, deadline);
            } finally {
              completedAt = clock.nanoTime();
            }
          });
        }
        running = task;
      }
      if (owner) {
        removeQueued(this);
        running.run();
      }
      return running;
    }

    synchronized Result finished() {
      if (task != null && task.isDone()) {
        try {
          return task.get();
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        } catch (ExecutionException failed) {
          // Unexpected loader failures are retryable, not a cached trust verdict.
        }
      }
      return Result.RETRY;
    }

    synchronized boolean expired(long now) {
      if (task == null) {
        if (now - queuedAt >= QUEUE_TTL) {
          discarded = true;
          return true;
        }
        return false;
      }
      return task.isDone() && now - completedAt >= finished().ttl;
    }

    synchronized boolean discard() {
      if (task != null) {
        return false;
      }
      discarded = true;
      return true;
    }

    synchronized boolean evictable() {
      return discard() || task.isDone();
    }
  }
}
