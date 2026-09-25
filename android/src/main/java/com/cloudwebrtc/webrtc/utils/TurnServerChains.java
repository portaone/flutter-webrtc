package com.cloudwebrtc.webrtc.utils;

import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The intermediate certificates a `turns:` server presents, learned from the server itself.
 *
 * <p>Why this exists: libwebrtc hands a certificate verifier the LEAF ALONE, so a trust store
 * holding only root authorities - which is what a platform trust store is - can never build a
 * path to one. The missing intermediates are not secret, though. The server sends them on every
 * handshake, to every client; one ordinary TLS connection is enough to read them.
 *
 * <p><b>Nothing here is taken on trust from the server.</b> The connection goes through the
 * application's default {@link SSLSocketFactory} with endpoint identification switched on, so the
 * chain is validated the way any other connection in the application would be - authorities,
 * validity dates and hostname, under whatever network security configuration the application
 * ships. Only the intermediates of a chain that was accepted are kept, and they are then used
 * solely to let that same trust manager build a path for the leaf. A server that cannot prove
 * itself teaches us nothing.
 *
 * <p>Each endpoint is learned at most once at a time: the entry is the running task itself, so a
 * verification that arrives while the warm-up is still in flight waits for that one rather than
 * opening a second connection.
 */
public final class TurnServerChains {
  private static final String TAG = "TurnServerChains";

  /** Long enough that gathering never pays for a handshake, short enough to follow a renewal. */
  private static final long TTL_MS = 30 * 60 * 1000L;

  /**
   * A failure is remembered too, or an unreachable server would cost a full timeout on every
   * certificate libwebrtc offers - and gathering offers several. It is remembered for far less
   * time than a success: the usual reason to fail is that the network was not up yet, and a
   * thirty-minute memory of that would outlast the problem by a long way.
   */
  private static final long FAILURE_TTL_MS = 60 * 1000L;

  private static final int CONNECT_TIMEOUT_MS = 4000;
  private static final int READ_TIMEOUT_MS = 4000;

  private static final Map<String, Entry> CACHE = new HashMap<>();

  /**
   * One background thread, not a pool: learning is a rare, tiny job and a pool of threads waiting
   * on network sockets is worse than a queue of two.
   */
  private static final ExecutorService WARMER = Executors.newSingleThreadExecutor();

  private static final class Entry {
    final Future<List<X509Certificate>> chain;
    final long startedAt;

    Entry(Future<List<X509Certificate>> chain, long startedAt) {
      this.chain = chain;
      this.startedAt = startedAt;
    }

    /** A result still being fetched is never stale; an empty (or failed) one goes stale quickly. */
    boolean expired(long now) {
      if (!chain.isDone()) {
        return false;
      }
      return now - startedAt >= (resultIsEmpty() ? FAILURE_TTL_MS : TTL_MS);
    }

    private boolean resultIsEmpty() {
      try {
        // Done, so this returns at once. A task that ended in an exception or was cancelled
        // throws here instead, and counts as empty: it taught nothing, and is retried soon.
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
   * <p>Called when the peer connection is built, which is well before candidate gathering asks
   * anything of the verifier - so by the time a certificate arrives the answer is usually already
   * there and {@link #intermediatesFor} waits for nothing.
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
   * The intermediates known for one endpoint, waiting at most {@code waitMs} if they are still
   * being learned. Empty when nothing was learned or the wait ran out.
   *
   * <p>Runs on libwebrtc's verification callback, so the wait is bounded on purpose - and by the
   * caller, which spreads one deadline over every endpoint it asks about rather than paying it
   * afresh for each.
   */
  public static List<X509Certificate> intermediatesFor(String endpoint, long waitMs) {
    if (endpoint == null) {
      return Collections.emptyList();
    }
    try {
      return entryFor(endpoint).chain.get(Math.max(0, waitMs), TimeUnit.MILLISECONDS);
    } catch (Exception e) {
      Logs.w(TAG, "no chain for " + endpoint + " in time: " + e.getClass().getSimpleName());
      return Collections.emptyList();
    }
  }

  /** The running or finished lookup for one endpoint, starting it if there is none worth keeping. */
  private static Entry entryFor(final String endpoint) {
    synchronized (CACHE) {
      long now = System.currentTimeMillis();
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

      FutureTask<List<X509Certificate>> task =
              new FutureTask<>(new Callable<List<X509Certificate>>() {
                @Override
                public List<X509Certificate> call() {
                  return fetch(endpoint);
                }
              });
      Entry fresh = new Entry(task, now);
      CACHE.put(endpoint, fresh);
      WARMER.execute(task);
      return fresh;
    }
  }

  private static List<X509Certificate> fetch(String endpoint) {
    // endpointOf guarantees the `host:port` shape, so the split is the inverse of what it built.
    int lastColon = endpoint.lastIndexOf(':');
    String host = endpoint.substring(0, lastColon);
    int port;
    try {
      port = Integer.parseInt(endpoint.substring(lastColon + 1));
    } catch (NumberFormatException e) {
      Logs.w(TAG, "not a host:port endpoint, skipping: " + endpoint);
      return Collections.emptyList();
    }

    SSLSocket socket = null;
    try {
      socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
      socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
      socket.setSoTimeout(READ_TIMEOUT_MS);

      // Without this the socket verifies the chain but NOT the hostname, which would make the
      // whole exercise pointless: any certificate that chains to a public authority would teach
      // us intermediates for a server it does not belong to.
      SSLParameters parameters = socket.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      socket.setSSLParameters(parameters);

      socket.startHandshake();

      Certificate[] presented = socket.getSession().getPeerCertificates();
      List<X509Certificate> intermediates = new ArrayList<>(Math.max(0, presented.length - 1));
      // From 1: the leaf is what we are trying to verify, not an anchor for it.
      for (int i = 1; i < presented.length; i++) {
        if (presented[i] instanceof X509Certificate) {
          intermediates.add((X509Certificate) presented[i]);
        }
      }

      Logs.i(TAG, "learned " + intermediates.size() + " intermediate(s) from " + endpoint);
      return intermediates;
    } catch (Exception e) {
      Logs.w(TAG, "could not learn the chain from " + endpoint + ": " + e.getMessage());
      return Collections.emptyList();
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
