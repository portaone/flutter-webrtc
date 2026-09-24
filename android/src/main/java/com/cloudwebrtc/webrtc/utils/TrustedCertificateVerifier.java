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
 * SINGLE certificate rather than the chain the server sent - measured, one certificate, 1275
 * bytes - so there is nothing to walk up and no path to a root can be built. Whatever signed
 * the presented certificate directly is what has to be supplied.
 */
public class TrustedCertificateVerifier implements SSLCertificateVerifier {
  private static final String TAG = "TrustedCertVerifier";

  private final List<X509TrustManager> trustManagers;

  private TrustedCertificateVerifier(List<X509TrustManager> trustManagers) {
    this.trustManagers = trustManagers;
  }

  /**
   * Builds a verifier anchored on {@code trustedCertificates} (DER or PEM, one or many per
   * entry), with the platform store alongside them.
   *
   * <p>Returns null - leaving libwebrtc's own decision in place - unless at least one supplied
   * certificate could be read. That is deliberate rather than defensive: a verifier REPLACES the
   * library's verdict, so one holding no usable anchor of its own would reject certificates the
   * built-in list would have accepted, breaking deployments that work today. Doing nothing is
   * the only safe failure here.
   */
  public static TrustedCertificateVerifier create(List<byte[]> trustedCertificates) {
    if (trustedCertificates == null || trustedCertificates.isEmpty()) {
      return null;
    }

    KeyStore supplied = keyStoreOf(trustedCertificates);
    if (supplied == null) {
      Log.w(TAG, "none of the supplied certificates could be read, leaving verification to libwebrtc");
      return null;
    }

    X509TrustManager suppliedTrust = trustManagerFor(supplied);
    if (suppliedTrust == null) {
      Log.w(TAG, "no trust manager for the supplied certificates, leaving verification to libwebrtc");
      return null;
    }

    List<X509TrustManager> trustManagers = new ArrayList<>(2);

    // Android's own store first, so a certificate that chains inside it is accepted without the
    // application having to name the authority. It is only ever an addition: everything the
    // supplied anchors accept is accepted either way.
    X509TrustManager platform = trustManagerFor(null);
    if (platform != null) {
      trustManagers.add(platform);
    }

    trustManagers.add(suppliedTrust);

    return new TrustedCertificateVerifier(trustManagers);
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

    for (X509TrustManager trustManager : trustManagers) {
      try {
        // The key exchange name only reaches the trust manager's own logging; libwebrtc does
        // not tell us which suite was negotiated, and no platform manager keys off it.
        trustManager.checkServerTrusted(chain, "UNKNOWN");
        return true;
      } catch (Exception e) {
        Log.d(TAG, "anchor rejected the certificate: " + e.getMessage());
      }
    }

    Log.w(TAG, "no trust anchor accepted the certificate, refusing");
    return false;
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

    int index = 0;
    for (byte[] each : certificates) {
      try {
        for (X509Certificate certificate : parse(each)) {
          keyStore.setCertificateEntry("supplied-" + (index++), certificate);
        }
      } catch (Exception e) {
        // Named by position, because the bytes themselves say nothing useful in a log.
        Log.w(TAG, "supplied certificate #" + certificates.indexOf(each) + " could not be read", e);
      }
    }

    return index == 0 ? null : keyStore;
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
