package com.cloudwebrtc.webrtc.utils;

import android.os.Build;
import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.cloudwebrtc.webrtc.utils.TurnServerChainCache.Result;

/**
 * Recovers intermediates missing from libwebrtc's leaf-only certificate callback.
 *
 * <p>Each lookup uses the application's default TLS trust policy and checks the configured
 * hostname. Only intermediates from an authenticated connection are cached; they are chain
 * material, never a trust verdict. The verifier still applies every relevant host policy.
 *
 * <p>Warm-up is bounded and optional. A caller can claim queued work with its own deadline;
 * callers joining running work only wait for their remaining budget. DNS workers and cached
 * endpoints are bounded as well. A timed socket close enforces the network deadline even if a
 * server keeps sending partial TLS records within the socket's individual read timeout.
 */
public final class TurnServerChains {
  private static final String TAG = "TurnServerChains";
  private static final int RESOLVE_TIMEOUT_MS = 700;
  private static final int CONNECT_TIMEOUT_MS = 700;
  private static final int READ_TIMEOUT_MS = 900;
  private static final long LOOKUP_NS = TimeUnit.MILLISECONDS.toNanos(
          RESOLVE_TIMEOUT_MS + CONNECT_TIMEOUT_MS + READ_TIMEOUT_MS);

  private static final ThreadPoolExecutor LEARNERS = pool("turn-chain-warm", 2, 16);
  private static final ThreadPoolExecutor RESOLVERS = pool("turn-chain-dns", 2, 16);
  private static final ScheduledThreadPoolExecutor DEADLINES =
          new ScheduledThreadPoolExecutor(1, threads("turn-chain-deadline"));
  private static final TurnServerChainCache CACHE = new TurnServerChainCache(
          TurnServerChains::fetch, System::nanoTime, LEARNERS, LOOKUP_NS, 128);

  static {
    DEADLINES.setRemoveOnCancelPolicy(true);
    DEADLINES.setKeepAliveTime(30, TimeUnit.SECONDS);
    DEADLINES.allowCoreThreadTimeOut(true);
  }

  private TurnServerChains() { }

  /** Extracts host:port from a turns: URL, preserving explicit ports and IPv6 brackets. */
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

  public static void warm(List<String> endpoints) {
    if (endpoints != null) {
      for (String endpoint : endpoints) {
        if (endpoint != null) {
          CACHE.warm(endpoint);
        }
      }
    }
  }

  /** Zero/negative budgets only read completed cache entries; they never start network work. */
  public static List<X509Certificate> intermediatesFor(String endpoint, long waitNanos) {
    return endpoint == null ? Collections.emptyList() : CACHE.get(endpoint, waitNanos);
  }

  private static ThreadFactory threads(String name) {
    return task -> {
      Thread thread = new Thread(task, name);
      thread.setDaemon(true);
      return thread;
    };
  }

  private static ThreadPoolExecutor pool(String name, int workers, int queued) {
    ThreadPoolExecutor pool = new ThreadPoolExecutor(workers, workers, 30, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(queued), threads(name));
    pool.allowCoreThreadTimeOut(true);
    return pool;
  }

  private static InetAddress resolve(String host, int timeoutMs)
          throws InterruptedException, ExecutionException, TimeoutException {
    FutureTask<InetAddress> lookup = new FutureTask<>(() -> InetAddress.getByName(host));
    RESOLVERS.execute(lookup);
    try {
      return lookup.get(timeoutMs, TimeUnit.MILLISECONDS);
    } finally {
      // Native DNS may ignore interruption, but cannot grow beyond the fixed resolver pool.
      lookup.cancel(true);
      RESOLVERS.remove(lookup);
    }
  }

  private static int budgetMs(long deadline, int allowanceMs) {
    long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
    return remaining <= 0 ? 0 : (int) Math.min(allowanceMs, remaining);
  }

  private static Result fetch(String endpoint, long callerDeadline) {
    // Public callers can wait longer, but no endpoint gets an unlimited lookup allowance.
    long now = System.nanoTime();
    long deadline = now + Math.min(LOOKUP_NS, callerDeadline - now);
    boolean shortened = false;
    Socket transport = null;
    ScheduledFuture<?> closeAtDeadline = null;
    try {
      String host = hostOf(endpoint);
      int port = Integer.parseInt(endpoint.substring(endpoint.lastIndexOf(':') + 1));
      int resolveMs = budgetMs(deadline, RESOLVE_TIMEOUT_MS);
      if (resolveMs == 0) {
        return Result.RETRY;
      }
      shortened = resolveMs < RESOLVE_TIMEOUT_MS;
      InetAddress address = resolve(host, resolveMs);

      int connectMs = budgetMs(deadline, CONNECT_TIMEOUT_MS);
      if (connectMs == 0) {
        return Result.RETRY;
      }
      shortened |= connectMs < CONNECT_TIMEOUT_MS;
      transport = new Socket();
      final Socket socket = transport;
      closeAtDeadline = DEADLINES.schedule(() -> close(socket),
              Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
      transport.connect(new InetSocketAddress(address, port), connectMs);

      int readMs = budgetMs(deadline, READ_TIMEOUT_MS);
      if (readMs == 0) {
        return Result.RETRY;
      }
      shortened |= readMs < READ_TIMEOUT_MS;
      // Preserve the configured host for SNI and Android's domain-specific trust policy after DNS.
      SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
      try (SSLSocket tls = (SSLSocket) factory.createSocket(transport, host, port, true)) {
        tls.setSoTimeout(readMs);
        boolean platformChecksHost = Build.VERSION.SDK_INT >= 24;
        if (platformChecksHost) {
          SSLParameters parameters = tls.getSSLParameters();
          parameters.setEndpointIdentificationAlgorithm("HTTPS");
          tls.setSSLParameters(parameters);
        }
        tls.startHandshake();
        Certificate[] presented = tls.getSession().getPeerCertificates();
        if (presented.length == 0 || !(presented[0] instanceof X509Certificate)
                || (!platformChecksHost
                    && !CertificateIdentity.covers((X509Certificate) presented[0], host))) {
          return Result.FAILURE;
        }
        List<X509Certificate> intermediates = new ArrayList<>(presented.length - 1);
        for (int i = 1; i < presented.length; i++) {
          if (presented[i] instanceof X509Certificate) {
            intermediates.add((X509Certificate) presented[i]);
          }
        }
        return Result.learned(intermediates);
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      return Result.RETRY;
    } catch (RejectedExecutionException busy) {
      return Result.RETRY;
    } catch (Exception failure) {
      Log.w(TAG, "could not learn the chain from " + endpoint + ": " + failure.getMessage());
      boolean timedOut = failure instanceof TimeoutException || failure instanceof SocketTimeoutException;
      return deadline - System.nanoTime() <= 0 || (shortened && timedOut)
              ? Result.RETRY : Result.FAILURE;
    } finally {
      if (closeAtDeadline != null) {
        closeAtDeadline.cancel(false);
      }
      close(transport);
    }
  }

  private static void close(Socket socket) {
    if (socket != null) {
      try {
        socket.close();
      } catch (IOException ignored) {
        // Closing an expired/already-closed transport must not replace the lookup result.
      }
    }
  }
}
