package com.cloudwebrtc.webrtc.utils;

import android.util.Log;

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
 *
 * <p>Installing this verifier replaces that decision instead of switching it off, which is the
 * difference between this and `tlsCertPolicy: insecure_no_check`: the certificate is still
 * checked, just against anchors the application chose.
 *
 * <p><b>The anchor has to be the issuer, not the root.</b> libwebrtc hands {@link #verify} a
 * SINGLE certificate rather than the chain the server sent - measured, one certificate, 912
 * bytes - so there is nothing to walk up and no path to a root can be built. Whatever signed
 * the presented certificate directly is what has to be supplied.
 *
 * <p>The hostname is NOT checked here, and does not need to be: libwebrtc checks it itself once
 * a verifier has accepted. Measured - a `turns:` host reached by IP address is refused even
 * though its chain was accepted.
 *
 * <p>That is also why the system trust store cannot simply be consulted: it holds root
 * authorities, and a leaf on its own cannot reach one. The gap is closed the way the Apple
 * platforms close it for free - the missing intermediates are read from the TURN server itself,
 * over a connection the platform has verified in full. See {@link TurnServerChains}.
 *
 * <p><b>This REPLACES the library's verdict rather than widening it.</b> The compiled-in list
 * holds a handful of authorities the platform has since dropped - Baltimore CyberTrust, expired
 * in 2025; Entrust, distrusted after the 2024 incidents; older COMODO - so a deployment whose
 * TURN certificate chains to one of those stops being accepted. That is the intended direction:
 * the platform store is the one the rest of the device already trusts. Where such a deployment
 * has to keep working, {@code trustedCertificates} carries the authority explicitly.
 */
public class TrustedCertificateVerifier implements SSLCertificateVerifier {
  private static final String TAG = "TrustedCertVerifier";

  private final List<X509TrustManager> trustManagers;

  /** Empty unless the caller opted in; the endpoints whose chains may be learned. */
  private final List<String> turnsEndpoints;

  private TrustedCertificateVerifier(
          List<X509TrustManager> trustManagers, List<String> turnsEndpoints) {
    this.trustManagers = trustManagers;
    this.turnsEndpoints = turnsEndpoints;
  }

  /**
   * Builds a verifier anchored on the system trust store and, first in the order, on any
   * {@code trustedCertificates} the caller supplied (DER or PEM, one or many per entry).
   *
   * <p>Returns null - leaving libwebrtc's own decision in place - only when neither could be
   * built. A verifier REPLACES the library's verdict, so one holding no usable anchor would
   * refuse certificates the built-in list would have accepted.
   *
   * @param turnsEndpoints the `turns:` `host:port` pairs of this peer connection, used to learn
   *     the intermediates the leaf needs. Empty is fine; it only costs the system store its
   *     ability to build a path for a leaf that arrives alone.
   */
  public static TrustedCertificateVerifier create(List<byte[]> trustedCertificates) {
    return create(trustedCertificates, Collections.<String>emptyList());
  }

  /** @see #create(List) */
  public static TrustedCertificateVerifier create(
          List<byte[]> trustedCertificates, List<String> turnsEndpoints) {
    List<X509TrustManager> trustManagers = new ArrayList<>(2);

    if (trustedCertificates != null && !trustedCertificates.isEmpty()) {
      KeyStore supplied = keyStoreOf(trustedCertificates);
      X509TrustManager suppliedTrust = supplied == null ? null : trustManagerFor(supplied);
      if (suppliedTrust == null) {
        Log.w(TAG, "none of the supplied certificates could be read");
      } else {
        // Supplied anchors first: they are the ones the application asked for, so the common
        // path reaches an answer without walking through a rejection. They are also the only
        // thing that works where the system store cannot help - a private authority, an
        // authority the platform has dropped, or an Android too old to carry the issuing root.
        trustManagers.add(suppliedTrust);
      }
    }

    List<String> endpoints = new ArrayList<>();
    X509TrustManager system = systemTrustManager();
    if (system != null) {
      trustManagers.add(system);
      if (turnsEndpoints != null) {
        endpoints.addAll(turnsEndpoints);
      }
      // Started here rather than on first use: gathering is still several steps away, so the
      // handshake is usually finished before any certificate is offered for verification.
      TurnServerChains.warm(endpoints);
    }

    if (trustManagers.isEmpty()) {
      Log.w(TAG, "no usable anchor, leaving verification to libwebrtc");
      return null;
    }

    return new TrustedCertificateVerifier(trustManagers, endpoints);
  }

  /**
   * @param certificate DER or PEM bytes of ONE certificate - see the class comment. Parsed as a
   *     collection anyway, so that a future libwebrtc handing over a chain needs no change here.
   */
  @Override
  public boolean verify(byte[] certificate) {
    if (certificate == null || certificate.length == 0) {
      Log.w(TAG, "empty certificate, refusing");
      return false;
    }

    X509Certificate[] chain;
    try {
      chain = parse(certificate);
    } catch (Exception e) {
      Log.w(TAG, "could not parse the certificate (" + certificate.length + " bytes), refusing", e);
      return false;
    }

    Log.i(TAG, "verifying " + chain.length + " certificate(s), " + certificate.length
            + " bytes; leaf subject=" + chain[0].getSubjectDN()
            + " issuer=" + chain[0].getIssuerDN());

    if (refusal(chain) == null) {
      return true;
    }

    // Nothing accepted the certificate on its own. If the system store is in use, the reason is
    // almost certainly the one this class exists for - the leaf arrived without the
    // intermediates that lead to a root - so the chain the server itself presents is tried.
    if (!turnsEndpoints.isEmpty()) {
      List<X509Certificate> intermediates = TurnServerChains.intermediatesFor(turnsEndpoints);
      if (!intermediates.isEmpty()) {
        Exception refusal = refusal(withIntermediates(chain, intermediates));
        if (refusal == null) {
          Log.i(TAG, "accepted with the intermediates the TURN server presents");
          return true;
        }
        Log.w(TAG, "refusing: " + refusal.getMessage());
        return false;
      }
    }

    Log.w(TAG, "no trust anchor accepted the certificate, refusing");
    return false;
  }

  /** Null when some anchor accepted the chain; otherwise the last refusal, for the log. */
  private Exception refusal(X509Certificate[] chain) {
    Exception last = null;
    for (X509TrustManager trustManager : trustManagers) {
      try {
        // The key exchange name only reaches the trust manager's own logging; libwebrtc does
        // not tell us which suite was negotiated, and no platform manager keys off it.
        trustManager.checkServerTrusted(chain, "UNKNOWN");
        return null;
      } catch (Exception e) {
        // One anchor declining is not the verdict - the next one is still asked, and the leaf
        // alone failing is the ordinary first step, not news. Only the final refusal is logged.
        last = e;
      }
    }
    return last == null ? new IllegalStateException("no anchor available") : last;
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

  /**
   * A trust manager over the system authorities, read as a key store of their own.
   *
   * <p>Not {@code TrustManagerFactory.init((KeyStore) null)}, which is the obvious way and does
   * not work: an application shipping `network_security_config.xml` with any per-domain section
   * is handed a `RootTrustManager`, and that refuses the two-argument `checkServerTrusted`
   * outright, asking for the hostname-aware form. libwebrtc passes no hostname, and supplying
   * one from the configuration does not help either - measured: the call is then accepted and
   * fails on the missing chain instead. Reading `AndroidCAStore` sidesteps the wrapper and
   * yields an ordinary trust manager over the same authorities.
   *
   * <p>Only the `system:` aliases are copied. Android stopped trusting user-installed
   * authorities for applications targeting API 24 and above, and a media connection is not the
   * place to bring that back.
   */
  private static volatile X509TrustManager systemTrustManager;

  private static X509TrustManager systemTrustManager() {
    // Built once: the authorities do not change under a running process, and rebuilding them
    // meant reading and parsing ~150 certificates on every peer connection.
    X509TrustManager built = systemTrustManager;
    if (built != null) {
      return built;
    }
    synchronized (TrustedCertificateVerifier.class) {
      if (systemTrustManager != null) {
        return systemTrustManager;
      }
      systemTrustManager = readSystemTrustManager();
      return systemTrustManager;
    }
  }

  private static X509TrustManager readSystemTrustManager() {
    try {
      KeyStore androidCaStore = KeyStore.getInstance("AndroidCAStore");
      androidCaStore.load(null, null);

      KeyStore systemOnly = KeyStore.getInstance(KeyStore.getDefaultType());
      systemOnly.load(null, null);

      int copied = 0;
      java.util.Enumeration<String> aliases = androidCaStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!alias.startsWith("system:")) {
          continue;
        }
        Certificate certificate = androidCaStore.getCertificate(alias);
        if (certificate instanceof X509Certificate) {
          systemOnly.setCertificateEntry(alias, certificate);
          copied++;
        }
      }

      if (copied == 0) {
        Log.w(TAG, "the system trust store holds no authority this can use");
        return null;
      }
      return trustManagerFor(systemOnly);
    } catch (Exception e) {
      Log.w(TAG, "could not read the system trust store", e);
      return null;
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
      Log.w(TAG, "could not create a key store for the supplied certificates", e);
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
        Log.w(TAG, "supplied certificate #" + entry + " could not be read", e);
      }
      entry++;
    }

    return stored == 0 ? null : keyStore;
  }

  private static X509TrustManager trustManagerFor(KeyStore keyStore) {
    try {
      TrustManagerFactory factory =
              TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      // A null key store means "the platform's own", which is exactly what is wanted for that
      // anchor and must never be reached by accident - see create().
      factory.init(keyStore);

      for (TrustManager trustManager : factory.getTrustManagers()) {
        if (trustManager instanceof X509TrustManager) {
          return (X509TrustManager) trustManager;
        }
      }
    } catch (Exception e) {
      Log.w(TAG, "could not build a trust manager", e);
    }
    return null;
  }
}
