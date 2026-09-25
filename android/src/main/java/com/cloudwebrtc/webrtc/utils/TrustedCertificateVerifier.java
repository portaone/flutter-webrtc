package com.cloudwebrtc.webrtc.utils;

import android.net.http.X509TrustManagerExtensions;

import org.webrtc.SSLCertificateVerifier;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Decides whether to trust the certificate a `turns:` server presents.
 *
 * <p>libwebrtc does NOT consult the platform trust store for this. It verifies against a root
 * list compiled into the library, and that list is a snapshot old enough to carry no Let's
 * Encrypt root at all - so a TURN server secured the way most deployments secure everything
 * else is refused with a fatal `unknown_ca` alert. No relay candidate is gathered and nothing
 * reports an error, which makes the failure look like a network problem rather than a trust one.
 * The Apple builds of the same library ask the operating system instead; this makes Android
 * agree.
 *
 * <p>Installing this verifier replaces that decision instead of switching it off, which is the
 * difference between this and `tlsCertPolicy: insecure_no_check`: the certificate is still
 * checked, by the trust manager the platform hands the application - so whatever the
 * application declares in its network security configuration (pinned authorities, its own
 * anchors, debug overrides) applies here exactly as it does to every other connection it makes.
 *
 * <p>Two things make that harder than it sounds.
 *
 * <p><b>The platform trust manager insists on a hostname.</b> An application shipping
 * `network_security_config.xml` with any per-domain section is handed a `RootTrustManager`,
 * which refuses the two-argument `checkServerTrusted` outright and answers only the
 * hostname-aware form - and libwebrtc passes a verifier no hostname. The hostname is not
 * libwebrtc's to give, though: the application named its `turns:` servers itself, so the
 * candidates come from the ICE configuration, tried in turn, the ones the certificate names
 * first.
 *
 * <p><b>libwebrtc hands over ONE certificate</b> - measured, a single certificate of 912 bytes -
 * rather than the chain the server sent, so a store of root authorities has nothing to build a
 * path from. The missing intermediates are read from the server itself; see
 * {@link TurnServerChains}.
 *
 * <p>{@code trustedCertificates} lets the application supply anchors of its own. They are asked
 * first, and they are the only thing that works where the platform store cannot help: a private
 * authority, one the platform has dropped, or an Android too old to carry the issuing root.
 * Because the verifier is handed the leaf alone, a supplied anchor is most useful as the
 * ISSUER; a supplied root works as well once the intermediates have been learned from the
 * server.
 *
 * <p>The hostname check libwebrtc performs after a verifier accepts still happens - measured, a
 * `turns:` host reached by IP address is refused even though its chain was accepted - so the
 * platform's own check here is belt and braces, not the only one.
 */
public class TrustedCertificateVerifier implements SSLCertificateVerifier {
  private static final String TAG = "TrustedCertVerifier";

  /**
   * What one verification is prepared to spend waiting for intermediates still being learned,
   * across every endpoint it asks about - not per endpoint. The warm-up started when the peer
   * connection was built normally makes this zero.
   */
  private static final long VERIFY_WAIT_MS = 2500L;

  /** Anchors the application supplied; null when it supplied none that could be read. */
  private final X509TrustManager supplied;

  /** The trust manager the platform hands this application; null when none could be built. */
  private final X509TrustManagerExtensions platform;

  /** `host:port` of every `turns:` server this peer connection was configured with. */
  private final List<String> turnsEndpoints;

  private TrustedCertificateVerifier(
          X509TrustManager supplied,
          X509TrustManagerExtensions platform,
          List<String> turnsEndpoints) {
    this.supplied = supplied;
    this.platform = platform;
    this.turnsEndpoints = turnsEndpoints;
  }

  /** As {@link #create(List, List)} with no `turns:` endpoints to learn from or name. */
  public static TrustedCertificateVerifier create(List<byte[]> trustedCertificates) {
    return create(trustedCertificates, Collections.<String>emptyList());
  }

  /**
   * Builds a verifier over the platform trust manager and, ahead of it, over any
   * {@code trustedCertificates} the caller supplied (DER or PEM, one or many per entry).
   *
   * <p>Returns null - leaving libwebrtc's own decision in place - only when neither could be
   * built. A verifier REPLACES the library's verdict, so one holding no usable anchor would
   * refuse certificates the built-in list would have accepted.
   *
   * @param turnsEndpoints the `turns:` `host:port` pairs of this peer connection. They supply
   *     the hostnames the platform trust manager insists on and the servers the intermediates
   *     are learned from; without any, only supplied anchors can decide.
   */
  public static TrustedCertificateVerifier create(
          List<byte[]> trustedCertificates, List<String> turnsEndpoints) {
    X509TrustManager supplied = null;
    if (trustedCertificates != null && !trustedCertificates.isEmpty()) {
      KeyStore keyStore = keyStoreOf(trustedCertificates);
      supplied = keyStore == null ? null : trustManagerFor(keyStore);
      if (supplied == null) {
        Logs.w(TAG, "none of the supplied certificates could be read");
      }
    }

    X509TrustManagerExtensions platform = platformTrustManager();

    if (supplied == null && platform == null) {
      Logs.w(TAG, "no usable anchor, leaving verification to libwebrtc");
      return null;
    }

    List<String> endpoints = new ArrayList<>();
    if (turnsEndpoints != null) {
      endpoints.addAll(turnsEndpoints);
    }
    // Started here rather than on first use: gathering is still several steps away, so the
    // handshake is usually finished before any certificate is offered for verification.
    TurnServerChains.warm(endpoints);

    return new TrustedCertificateVerifier(supplied, platform, endpoints);
  }

  /**
   * @param certificate DER or PEM bytes of ONE certificate - see the class comment. Parsed as a
   *     collection anyway, so that a future libwebrtc handing over a chain needs no change here.
   */
  @Override
  public boolean verify(byte[] certificate) {
    if (certificate == null || certificate.length == 0) {
      Logs.w(TAG, "empty certificate, refusing");
      return false;
    }

    X509Certificate[] chain;
    try {
      chain = parse(certificate);
    } catch (Exception e) {
      Logs.w(TAG, "could not parse the certificate (" + certificate.length + " bytes), refusing", e);
      return false;
    }

    Logs.i(TAG, "verifying " + chain.length + " certificate(s), " + certificate.length
            + " bytes; leaf subject=" + chain[0].getSubjectDN()
            + " issuer=" + chain[0].getIssuerDN());

    // Supplied anchors first, on the leaf alone: they are meant to be the issuer, so this is
    // the common path for a deployment that configured them, and it costs no waiting.
    Exception refusal = supplied == null ? null : refusalOf(supplied, chain);
    if (supplied != null && refusal == null) {
      return true;
    }

    // Everything else needs the server's own chain and, for the platform, a hostname. One
    // deadline for the whole walk: a deployment listing several turns: servers must not pay it
    // once per server.
    long deadline = System.currentTimeMillis() + VERIFY_WAIT_MS;
    for (String endpoint : endpointsNamedFirst(chain[0], turnsEndpoints)) {
      String host = TurnServerChains.hostOf(endpoint);

      // The leaf alone is worth one try: the platform keeps the intermediates it has validated
      // before, so after the first success this is usually enough and no chain is needed.
      if (platform != null) {
        refusal = refusalOf(platform, chain, host);
        if (refusal == null) {
          Logs.i(TAG, "accepted by the platform for " + host);
          return true;
        }
      }

      List<X509Certificate> intermediates =
              TurnServerChains.intermediatesFor(endpoint, deadline - System.currentTimeMillis());
      if (intermediates.isEmpty()) {
        continue;
      }
      X509Certificate[] full = withIntermediates(chain, intermediates);

      if (platform != null) {
        refusal = refusalOf(platform, full, host);
        if (refusal == null) {
          Logs.i(TAG, "accepted by the platform for " + host
                  + " with the intermediates the server presents");
          return true;
        }
      }
      // A supplied ROOT reaches the leaf only through those same intermediates.
      if (supplied != null && refusalOf(supplied, full) == null) {
        Logs.i(TAG, "accepted by a supplied anchor with the intermediates the server presents");
        return true;
      }
    }

    Logs.w(TAG, "refusing" + (refusal == null ? "" : ": " + refusal.getMessage()));
    return false;
  }

  /** Null when the anchors accept the chain as a server chain; otherwise why not. */
  private static Exception refusalOf(X509TrustManager anchors, X509Certificate[] chain) {
    try {
      // The key exchange name only reaches the trust manager's own logging; libwebrtc does
      // not tell us which suite was negotiated, and no trust manager keys off it.
      anchors.checkServerTrusted(chain, "UNKNOWN");
      return null;
    } catch (Exception e) {
      return e;
    }
  }

  private static Exception refusalOf(
          X509TrustManagerExtensions platform, X509Certificate[] chain, String host) {
    try {
      platform.checkServerTrusted(chain, "UNKNOWN", host);
      return null;
    } catch (Exception e) {
      return e;
    }
  }

  /**
   * The endpoints, those whose host the leaf names ahead of the rest.
   *
   * <p>A certificate says which server it is for; asking that server's endpoint first means the
   * usual case takes one hostname check and one chain, and a deployment listing several
   * `turns:` servers does not connect to all of them for every certificate.
   */
  static List<String> endpointsNamedFirst(X509Certificate leaf, List<String> endpoints) {
    List<String> named = new ArrayList<>();
    List<String> others = new ArrayList<>();
    for (String endpoint : endpoints) {
      (names(leaf, TurnServerChains.hostOf(endpoint)) ? named : others).add(endpoint);
    }
    named.addAll(others);
    return named;
  }

  /** Whether the leaf's subject alternative names cover {@code host}, wildcards included. */
  static boolean names(X509Certificate leaf, String host) {
    Collection<List<?>> alternatives;
    try {
      alternatives = leaf.getSubjectAlternativeNames();
    } catch (Exception e) {
      return false;
    }
    if (alternatives == null) {
      return false;
    }
    String wanted = host.toLowerCase();
    for (List<?> alternative : alternatives) {
      if (alternative.size() < 2 || !(alternative.get(1) instanceof String)) {
        continue;
      }
      String name = ((String) alternative.get(1)).toLowerCase();
      if (name.equals(wanted)) {
        return true;
      }
      // `*.example.com` covers one label, the way the platform's own matcher reads it.
      if (name.startsWith("*.")) {
        int dot = wanted.indexOf('.');
        if (dot > 0 && wanted.substring(dot + 1).equals(name.substring(2))) {
          return true;
        }
      }
    }
    return false;
  }

  private static X509Certificate[] withIntermediates(
          X509Certificate[] chain, List<X509Certificate> intermediates) {
    X509Certificate[] joined = new X509Certificate[chain.length + intermediates.size()];
    System.arraycopy(chain, 0, joined, 0, chain.length);
    for (int i = 0; i < intermediates.size(); i++) {
      joined[chain.length + i] = intermediates.get(i);
    }
    return joined;
  }

  private static volatile X509TrustManagerExtensions platformTrustManager;

  /**
   * The trust manager the platform hands this application, wrapped so the hostname-aware
   * check can be reached. Built once: it does not change under a running process.
   *
   * <p>Deliberately the DEFAULT one - {@code init((KeyStore) null)} - and not the raw system
   * store. The default is what carries the application's network security configuration; the
   * raw store would honour none of it.
   */
  private static X509TrustManagerExtensions platformTrustManager() {
    X509TrustManagerExtensions built = platformTrustManager;
    if (built != null) {
      return built;
    }
    synchronized (TrustedCertificateVerifier.class) {
      if (platformTrustManager == null) {
        X509TrustManager base = trustManagerFor(null);
        if (base != null) {
          try {
            platformTrustManager = new X509TrustManagerExtensions(base);
          } catch (Exception e) {
            Logs.w(TAG, "the platform trust manager cannot be asked with a hostname", e);
          }
        }
      }
      return platformTrustManager;
    }
  }

  private static X509Certificate[] parse(byte[] certificate) throws Exception {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    Collection<? extends Certificate> parsed =
            factory.generateCertificates(new ByteArrayInputStream(certificate));

    List<X509Certificate> chain = new ArrayList<>(parsed.size());
    for (Certificate each : parsed) {
      if (each instanceof X509Certificate) {
        chain.add((X509Certificate) each);
      }
    }

    if (chain.isEmpty()) {
      throw new IllegalArgumentException("no X.509 certificate in the presented bytes");
    }

    return chain.toArray(new X509Certificate[0]);
  }

  /** Null when nothing could be read - one unreadable entry never costs the others. */
  private static KeyStore keyStoreOf(List<byte[]> certificates) {
    KeyStore keyStore;
    try {
      keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
    } catch (Exception e) {
      Logs.w(TAG, "could not create a key store for the supplied certificates", e);
      return null;
    }

    int stored = 0;
    int entry = 0;
    for (byte[] each : certificates) {
      try {
        for (X509Certificate certificate : parse(each)) {
          keyStore.setCertificateEntry("supplied-" + (stored++), certificate);
        }
      } catch (Exception e) {
        // Named by the position it was given in, because the bytes themselves say nothing
        // useful in a log. Counted rather than searched for: `List<byte[]>.indexOf` compares
        // references, so two entries holding one array would both report the first.
        Logs.w(TAG, "supplied certificate #" + entry + " could not be read", e);
      }
      entry++;
    }

    return stored == 0 ? null : keyStore;
  }

  private static X509TrustManager trustManagerFor(KeyStore keyStore) {
    try {
      TrustManagerFactory factory =
              TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      // A null key store means "the platform's own" - the one that carries the application's
      // network security configuration - and is asked for on purpose in platformTrustManager().
      factory.init(keyStore);

      for (TrustManager trustManager : factory.getTrustManagers()) {
        if (trustManager instanceof X509TrustManager) {
          return (X509TrustManager) trustManager;
        }
      }
    } catch (Exception e) {
      Logs.w(TAG, "could not build a trust manager", e);
    }
    return null;
  }
}
