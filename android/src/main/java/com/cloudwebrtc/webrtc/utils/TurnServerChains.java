package com.cloudwebrtc.webrtc.utils;

import android.os.Build;
import android.util.Log;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The intermediate certificates a `turns:` server presents, read from the server itself.
 *
 * <p>Why this exists: libwebrtc hands a certificate verifier the LEAF ALONE, so a trust store
 * holding root authorities has nothing to build a path from. The intermediates are not secret -
 * the server sends them on every handshake, to every client - so one ordinary TLS connection
 * gets them.
 *
 * <p><b>Nothing here is taken on trust from the server.</b> The connection goes through the
 * application's default {@link SSLSocketFactory}, so the chain is validated the way any other
 * connection in the application would be, under whatever network security configuration it
 * ships; and the host is checked as well. Only the intermediates of a chain that was accepted
 * are kept. A server that cannot prove itself teaches nothing.
 *
 * <p><b>What this is NOT.</b> A chain read here is material for a later decision, never the
 * decision. A failure to reach a server is a failure to learn, not a verdict about a
 * certificate: {@link TrustedCertificateVerifier} asks each policy with whatever material it
 * has, and an unreachable unrelated endpoint must not turn into a refusal.
 *
 * <p><b>A verification never queues behind speculative work.</b> The pool exists for warm-up
 * only. When a verification needs an endpoint whose lookup has not started, it runs that lookup
 * ON ITS OWN THREAD - {@link FutureTask#run} is a no-op if another thread already started it, so
 * the work still happens once. Waiting for a worker instead is what made two unrelated stalled
 * endpoints refuse a healthy server's certificate without ever connecting to it. The socket
 * timeouts are therefore sized so that a whole lookup, DNS included, fits inside the verifier's
 * budget rather than relying on a queue draining in time.
 */
public final class TurnServerChains {
  private static final String TAG = "TurnServerChains";

  /** Long enough that gathering never pays for a handshake, short enough to follow a renewal. */
  private static final long TTL_NS = TimeUnit.MINUTES.toNanos(30);

  /**
   * A failure is remembered too, or an unreachable server would cost a full timeout on every
   * certificate libwebrtc offers - and gathering offers several. Far shorter than a success:
   * the usual reason to fail is a network that was not up yet, and a half-hour memory of that
   * would outlast the problem by a long way.
   */
  private static final long FAILURE_TTL_NS = TimeUnit.MINUTES.toNanos(1);

  /**
   * A queued lookup this old is abandoned without touching the network. Whoever was waiting for
   * it has long since been answered, and running it would only hold the pool for the next one.
   */
  private static final long STALE_NS = TimeUnit.SECONDS.toNanos(15);

  /**
   * Sized so that resolve plus connect plus handshake cannot outlast the verifier's budget, since
   * a verification may run the whole lookup itself. A TURN server about to carry a call answers
   * in well under this; one that does not is better skipped than waited for, and the policies are
   * then asked with the leaf alone.
   */
  private static final int RESOLVE_TIMEOUT_MS = 700;
  private static final int CONNECT_TIMEOUT_MS = 700;
  private static final int READ_TIMEOUT_MS = 900;

  /**
   * What a warm-up, which nobody is waiting for, may spend on one endpoint.
   *
   * <p>Counted from when the task starts running, not from when it was queued: time spent
   * waiting for a worker is not time the server was given to answer. Queue age is a separate
   * question, and {@link #STALE_NS} answers it.
   */
  private static final long WARM_UP_NS = TimeUnit.MILLISECONDS.toNanos(
          RESOLVE_TIMEOUT_MS + CONNECT_TIMEOUT_MS + READ_TIMEOUT_MS);

  private static final Map<String, Entry> CACHE = new HashMap<>();

  /**
   * A small bounded pool, not one thread: one server that accepts a connection and then says
   * nothing holds its worker for the whole read timeout, and with a single worker that stalls
   * every other peer connection in the process. Bounded because this is opportunistic work -
   * far better to skip a lookup than to grow threads under a failing network.
   */
  private static final ThreadPoolExecutor LEARNERS = new ThreadPoolExecutor(
          2, 2, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(16));

  static {
    LEARNERS.allowCoreThreadTimeOut(true);
  }

  private static final class Entry implements Callable<List<X509Certificate>> {
    final FutureTask<List<X509Certificate>> chain;
    final String endpoint;
    final long startedAt;

    /**
     * When the lookup must be finished by, absolute {@link System#nanoTime}, or 0 for "whoever
     * runs it decides".
     *
     * <p>A verification that runs the lookup on its own thread writes what is left of its own
     * budget here first; a warm-up worker finds it unset and takes the full allowance from the
     * moment it starts. Volatile because those are different threads.
     */
    volatile long deadline;

    /**
     * Set when the lookup was not attempted, or was cut short, because time ran out.
     *
     * <p>That is a fact about the caller, not about the server, so it must not be remembered as
     * a failed endpoint: {@link #expired} discards such an entry at once, and the next caller
     * with time to spend gets a fresh attempt.
     */
    volatile boolean abandoned;

    Entry(String endpoint, long startedAt) {
      this.endpoint = endpoint;
      this.startedAt = startedAt;
      this.chain = new FutureTask<>(this);
    }

    @Override
    public List<X509Certificate> call() {
      if (System.nanoTime() - startedAt >= STALE_NS) {
        Log.w(TAG, "dropping a stale queued lookup for " + endpoint);
        abandoned = true;
        return Collections.emptyList();
      }

      long due = deadline;
      if (due == 0) {
        due = System.nanoTime() + WARM_UP_NS;
      }

      List<X509Certificate> learned = fetch(endpoint, due);
      if (learned == null) {
        abandoned = true;
        return Collections.emptyList();
      }
      return learned;
    }

    /** A lookup still running is never stale; an empty or failed result goes stale quickly. */
    boolean expired(long now) {
      if (!chain.isDone()) {
        return false;
      }
      if (abandoned) {
        // Nothing was learned AND nothing was decided. Keeping this would turn "the caller had
        // no time" into "the endpoint is unreachable", for every peer connection in the process.
        return true;
      }
      return now - startedAt >= (resultIsEmpty() ? FAILURE_TTL_NS : TTL_NS);
    }

    private boolean resultIsEmpty() {
      try {
        // Done, so this returns at once. A task that threw or was cancelled throws here and
        // counts as empty: it taught nothing, and is retried sooner.
        return chain.get(0, TimeUnit.MILLISECONDS).isEmpty();
      } catch (Exception e) {
        return true;
      }
    }
  }

  private TurnServerChains() { }

  /**
   * `host:port` for a `turns:` URL, or null for anything else.
   *
   * <p>Only `turns:` has a certificate to learn about: a plain `turn:` server presents none, and
   * `stun:` is not ours to connect to. The port is kept because a deployment may serve TLS
   * anywhere - 443 and 5349 are both common - and the chain has to be read from the endpoint
   * actually in use. A bracketed IPv6 literal keeps its brackets, which is what
   * {@link InetSocketAddress} wants.
   */
  public static String endpointOf(String url) {
    if (url == null || !url.startsWith("turns:")) {
      return null;
    }

    String rest = url.substring("turns:".length());
    int query = rest.indexOf('?');
    if (query >= 0) {
      rest = rest.substring(0, query);
    }
    if (rest.isEmpty()) {
      return null;
    }

    // The port is whatever follows the LAST colon, but only outside a bracketed IPv6 literal -
    // `[::1]` is all colons and none of them a port.
    int lastColon = rest.lastIndexOf(':');
    int closingBracket = rest.lastIndexOf(']');
    boolean hasPort = lastColon > closingBracket && lastColon >= 0;

    // A bare host means the default TURN-over-TLS port, the same assumption libwebrtc makes.
    return hasPort ? rest : rest + ":5349";
  }

  /**
   * The host named by an endpoint from {@link #endpointOf}, as a certificate would name it:
   * without the port, and without the brackets of an IPv6 literal.
   */
  public static String hostOf(String endpoint) {
    String host = endpoint.substring(0, endpoint.lastIndexOf(':'));
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    return host;
  }

  /**
   * Starts learning the chains for {@code endpoints} without waiting for them.
   *
   * <p>Called when the peer connection is built and whenever its configuration changes, which is
   * well before candidate gathering asks anything of the verifier - so by the time a certificate
   * arrives the answer is usually already there and {@link #intermediatesFor} waits for nothing.
   */
  public static void warm(List<String> endpoints) {
    if (endpoints == null) {
      return;
    }
    for (String endpoint : endpoints) {
      entryFor(endpoint);
    }
  }

  /**
   * The intermediates known for one endpoint, waiting at most {@code waitNanos} if they are
   * still being learned. Empty when nothing was learned, the wait ran out, or the lookup could
   * not even be queued.
   *
   * <p>Runs on libwebrtc's verification callback, so the wait is bounded - and bounded by the
   * CALLER, which spreads one deadline over every endpoint it asks about rather than paying it
   * afresh for each.
   */
  public static List<X509Certificate> intermediatesFor(String endpoint, long waitNanos) {
    if (endpoint == null) {
      return Collections.emptyList();
    }
    Entry entry = entryFor(endpoint);
    if (entry == null) {
      return Collections.emptyList();
    }

    // Run it here if nobody has: a no-op when a warm-up thread already started it, and the
    // difference between asking a policy with the chain and refusing a healthy server because
    // unrelated endpoints were holding the pool. The caller's remaining budget goes with it, so
    // running the work here can never cost more than waiting for it would have.
    //
    // A caller with nothing to spend only reads. Running the lookup on a deadline that has
    // already passed would complete the shared task with a result nobody waited for, and every
    // later caller - in any peer connection - would be handed that.
    if (waitNanos > 0 && !entry.chain.isDone()) {
      entry.deadline = System.nanoTime() + waitNanos;
      entry.chain.run();
    }

    try {
      return entry.chain.get(Math.max(0, waitNanos), TimeUnit.NANOSECONDS);
    } catch (Exception e) {
      Log.w(TAG, "no chain for " + endpoint + " in time: " + e.getClass().getSimpleName());
      return Collections.emptyList();
    }
  }

  /**
   * The running or finished lookup for one endpoint, starting it if there is none worth keeping.
   * Null when the pool is saturated, in which case nothing is cached and the next attempt tries
   * again.
   */
  private static Entry entryFor(String endpoint) {
    synchronized (CACHE) {
      // Monotonic throughout: a wall clock that steps while a handshake is in flight would make
      // a fresh entry look half an hour old, or an old one look fresh.
      final long now = System.nanoTime();

      Entry cached = CACHE.get(endpoint);
      if (cached != null && !cached.expired(now)) {
        return cached;
      }

      // Housekeeping on the way through: an endpoint a deployment stopped using would otherwise
      // sit here for the life of the process.
      for (Iterator<Entry> it = CACHE.values().iterator(); it.hasNext(); ) {
        if (it.next().expired(now)) {
          it.remove();
        }
      }

      Entry fresh = new Entry(endpoint, now);
      CACHE.put(endpoint, fresh);

      try {
        LEARNERS.execute(fresh.chain);
      } catch (RejectedExecutionException e) {
        // Left unstarted rather than dropped: a verification that needs this endpoint runs the
        // task itself, and a warm-up that cannot get a worker has lost nothing.
        Log.w(TAG, "chain learning pool is busy, leaving " + endpoint + " for whoever needs it");
      }
      return fresh;
    }
  }

  /**
   * The address of {@code host}, or null when it did not arrive in time.
   *
   * <p>On its own thread because there is no timed resolve in the platform API. The thread is
   * left to finish on its own if it is slow - interrupting it would not cancel the lookup - and
   * it is a daemon, so it never holds the process open.
   */
  private static InetAddress resolve(final String host, int timeoutMs) {
    java.util.concurrent.FutureTask<InetAddress> lookup =
            new java.util.concurrent.FutureTask<>(new Callable<InetAddress>() {
              @Override
              public InetAddress call() throws Exception {
                return InetAddress.getByName(host);
              }
            });
    Thread thread = new Thread(lookup, "turn-chain-resolve");
    thread.setDaemon(true);
    thread.start();

    try {
      return lookup.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (Exception e) {
      Log.w(TAG, "could not resolve " + host + ": " + e.getClass().getSimpleName());
      return null;
    }
  }

  /**
   * What one blocking step may take: its own allowance, or what is left before {@code deadline}
   * when that is less. Zero means there is nothing left to spend, and the caller stops.
   */
  private static int budgetMs(long deadline, int allowanceMs) {
    long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
    if (remaining <= 0) {
      return 0;
    }
    return (int) Math.min(allowanceMs, remaining);
  }

  /**
   * Learns the chain {@code endpoint} presents, spending no longer than {@code deadline}.
   *
   * <p>Every blocking step takes the smaller of its own allowance and what is left, and the step
   * is skipped altogether once nothing is left. That is what lets a verification run this work
   * on its own thread: doing it here costs no more than waiting for someone else to do it.
   *
   * <p>Returns null - NOT an empty list - when the deadline, rather than the server, ended it:
   * a step that was never attempted, or one cut short because the deadline was nearer than its
   * own allowance. The caller has learned nothing about the endpoint in that case, and
   * {@link Entry#abandoned} keeps it from being remembered as a failure.
   */
  private static List<X509Certificate> fetch(String endpoint, long deadline) {
    // endpointOf guarantees the `host:port` shape, so the split is the inverse of what it built.
    int lastColon = endpoint.lastIndexOf(':');
    String host = hostOf(endpoint);
    int port;
    try {
      port = Integer.parseInt(endpoint.substring(lastColon + 1));
    } catch (NumberFormatException e) {
      Log.w(TAG, "not a host:port endpoint, skipping: " + endpoint);
      return Collections.emptyList();
    }

    // Resolved before the socket, and on a thread of its own: `new InetSocketAddress(host, port)`
    // resolves synchronously and is NOT covered by the connect timeout, so a stalled resolver
    // would sit here for as long as it liked.
    int resolveMs = budgetMs(deadline, RESOLVE_TIMEOUT_MS);
    if (resolveMs == 0) {
      Log.w(TAG, "out of time before resolving " + host);
      return null;
    }
    // A step the deadline shortened cannot speak for the endpoint: what failed within it might
    // well have succeeded within its own allowance.
    boolean cutShort = resolveMs < RESOLVE_TIMEOUT_MS;

    InetAddress address = resolve(host, resolveMs);
    if (address == null) {
      return cutShort ? null : Collections.<X509Certificate>emptyList();
    }

    int connectMs = budgetMs(deadline, CONNECT_TIMEOUT_MS);
    if (connectMs == 0) {
      Log.w(TAG, "out of time before connecting to " + endpoint);
      return null;
    }
    cutShort |= connectMs < CONNECT_TIMEOUT_MS;

    SSLSocket socket = null;
    try {
      socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
      socket.connect(new InetSocketAddress(address, port), connectMs);

      // Measured after the connect, so a slow connect shortens the read rather than adding to
      // it. This covers the handshake too: startHandshake reads through this socket, so a server
      // that accepts the connection and then says nothing cannot hold us past the deadline.
      int readMs = budgetMs(deadline, READ_TIMEOUT_MS);
      if (readMs == 0) {
        Log.w(TAG, "out of time before the handshake with " + endpoint);
        return null;
      }
      cutShort |= readMs < READ_TIMEOUT_MS;
      socket.setSoTimeout(readMs);

      // Without a host check the chain would be validated but not tied to this server, and any
      // certificate chaining to a public authority would teach us intermediates for a server it
      // does not belong to. Two ways to get it, because the parameter is API 24 and this
      // module supports 21.
      boolean platformChecksHost = Build.VERSION.SDK_INT >= 24;
      if (platformChecksHost) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(parameters);
      }

      socket.startHandshake();

      Certificate[] presented = socket.getSession().getPeerCertificates();
      if (presented.length == 0 || !(presented[0] instanceof X509Certificate)) {
        Log.w(TAG, "no X.509 leaf from " + endpoint);
        return Collections.emptyList();
      }

      if (!platformChecksHost
              && !CertificateIdentity.covers((X509Certificate) presented[0], host)) {
        // Below API 24 the handshake validated the chain but not the name, so it is checked
        // here, by the same rule the verifier uses to choose a policy.
        Log.w(TAG, "the certificate from " + endpoint + " does not name " + host);
        return Collections.emptyList();
      }

      List<X509Certificate> intermediates = new ArrayList<>(presented.length - 1);
      // From 1: the leaf is what we are trying to verify, not an anchor for it.
      for (int i = 1; i < presented.length; i++) {
        if (presented[i] instanceof X509Certificate) {
          intermediates.add((X509Certificate) presented[i]);
        }
      }

      Log.i(TAG, "learned " + intermediates.size() + " intermediate(s) from " + endpoint);
      return intermediates;
    } catch (Exception e) {
      Log.w(TAG, "could not learn the chain from " + endpoint + ": " + e.getMessage());
      return cutShort ? null : Collections.<X509Certificate>emptyList();
    } finally {
      if (socket != null) {
        try {
          socket.close();
        } catch (Exception ignored) {
          // Nothing useful to do about a socket that will not close.
        }
      }
    }
  }
}
