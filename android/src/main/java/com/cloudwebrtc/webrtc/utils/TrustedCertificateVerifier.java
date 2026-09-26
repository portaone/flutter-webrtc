package com.cloudwebrtc.webrtc.utils;

import android.net.http.X509TrustManagerExtensions;
import android.util.Log;

import org.webrtc.SSLCertificateVerifier;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Decides whether to trust the certificate a `turns:` server presents.
 *
 * <p>libwebrtc does not consult the platform for this. It verifies against a root list compiled
 * into the library, and that list is a snapshot old enough to carry no Let's Encrypt root at all,
 * so a TURN server secured the way most deployments secure everything else is refused with a
 * fatal `unknown_ca` alert - silently, with no relay candidate and no error anywhere. The Apple
 * builds of the same library ask the operating system instead. This makes Android agree.
 *
 * <p>Installing this verifier REPLACES the library's verdict rather than switching it off, which
 * is the difference between this and `tlsCertPolicy: insecure_no_check`.
 *
 * <h2>What this can and cannot promise</h2>
 *
 * <p>libwebrtc tells a verifier two things less than an ordinary TLS client knows: it passes
 * {@link #verify} a SINGLE certificate rather than the chain the server sent, and it does not say
 * which host the connection was to. The chain is recovered from the server itself
 * ({@link TurnServerChains}). The host cannot be recovered - so this class works from the
 * `turns:` hosts the application itself configured, and that has a consequence worth stating
 * plainly:
 *
 * <p><b>Trust is the INTERSECTION of the policies of every configured host the certificate
 * covers.</b> On Android the host argument selects which section of `network_security_config.xml`
 * applies, so consulting one host after another until one accepts would be searching for the
 * mildest policy. Instead every covered host must accept. Policies need not be comparable -
 * different anchors, different pins, or both - so this is an intersection, not "the strictest
 * one wins".
 *
 * <p>The price is real and is not only paid by contradictory configurations. A certificate
 * covering hosts A and B, where A is pinned to another key and B is meant to be accepted through
 * ordinary platform trust, is refused here - even though a connection to B alone would be valid
 * on Android - because the callback does not say whether this was B. A deployment that needs
 * those two treated differently has to configure them on separate peer connections.
 *
 * <p>A certificate covering NO configured host is refused outright. libwebrtc would refuse it
 * moments later anyway, since it checks the host itself after a verifier accepts.
 *
 * <h2>Application-supplied anchors</h2>
 *
 * <p>{@code trustedCertificates} carries certificates the application trusts for its `turns:`
 * servers. The contract is narrow on purpose: <b>supply the certificate that DIRECTLY ISSUED the
 * server's certificate.</b> A root that signs the leaf directly qualifies; a root whose
 * intermediate is missing does not, because the chain needed to reach it is itself only
 * obtainable through trust this anchor does not grant.
 *
 * <p>A supplied issuer is an INDEPENDENT alternative to the platform, which is the point: it
 * exists for a private authority, for one the platform has dropped, and for an Android too old to
 * carry the issuing root. It therefore does NOT enforce the pins or anchors declared in
 * `network_security_config.xml`. The host is still matched before it is consulted, and libwebrtc
 * checks the host again afterwards.
 */
public class TrustedCertificateVerifier implements SSLCertificateVerifier {
  private static final String TAG = "TrustedCertVerifier";

  /**
   * What one verification spends waiting for chains still being learned, across every host it
   * asks about - not per host. The warm-up started when the peer connection was built normally
   * makes this zero.
   */
  private static final long VERIFY_WAIT_NS = TimeUnit.MILLISECONDS.toNanos(2500);

  /**
   * Everything one verification decides from, replaced as a whole and never mutated.
   *
   * <p>That is the whole concurrency argument: a callback reads the field once and then works
   * from an object nobody can change, so it can see the configuration from before an update or
   * the one from after, but never a list of hosts from one and anchors from the other.
   */
  private static final class Trust {
    final X509TrustManager supplied;
    final List<String> secureEndpoints;

    Trust(X509TrustManager supplied, List<String> secureEndpoints) {
      this.supplied = supplied;
      this.secureEndpoints = Collections.unmodifiableList(new ArrayList<>(secureEndpoints));
    }
  }

  /**
   * The platform's decision for one host, as this class needs it.
   *
   * <p>A seam, and a deliberate one: the real implementation is the trust manager Android hands
   * the application, which cannot be reached from a local JVM - its stub there answers every
   * check with silence, and silence reads as acceptance. A test that means to pin down WHICH
   * host is consulted, or that a refusal is final, therefore supplies its own policy; the
   * platform's own verdict is only ever measured on a device.
   */
  interface HostTrustPolicy {
    /** Returns normally when this host's policy accepts the chain, throws otherwise. */
    void check(X509Certificate[] chain, String host) throws Exception;
  }

  private volatile Trust trust;
  private final HostTrustPolicy platform;

  private TrustedCertificateVerifier(Trust trust, HostTrustPolicy platform) {
    this.trust = trust;
    this.platform = platform;
  }

  /** For tests: the same verifier with a policy whose answers the test controls. */
  static TrustedCertificateVerifier withPolicy(
          List<byte[]> trustedCertificates, List<String> secureEndpoints, HostTrustPolicy platform) {
    return new TrustedCertificateVerifier(
            new Trust(suppliedTrustManager(trustedCertificates),
                    secureEndpoints == null ? Collections.<String>emptyList() : secureEndpoints),
            platform);
  }

  /** As {@link #create(List, List)} with no `turns:` endpoints. */
  public static TrustedCertificateVerifier create(List<byte[]> trustedCertificates) {
    return create(trustedCertificates, Collections.<String>emptyList());
  }

  /**
   * Builds a verifier, or null when this device offers nothing to decide with - no platform
   * trust manager and no readable supplied certificate - in which case libwebrtc keeps deciding.
   *
   * <p>A verifier IS built when the endpoint list is empty, so that a peer connection created
   * before its TURN servers are known keeps one installed and
   * {@link #reconfigure(List, List)} can fill it in later.
   *
   * @param secureEndpoints `host:port` of the `turns:` servers of this peer connection, EXCLUDING
   *     any whose `tlsCertPolicy` gave verification up: those are not verified here at all and
   *     must not contribute a trust policy to the ones that are.
   */
  public static TrustedCertificateVerifier create(
          List<byte[]> trustedCertificates, List<String> secureEndpoints) {
    X509TrustManager supplied = suppliedTrustManager(trustedCertificates);
    HostTrustPolicy platform = platformPolicy();
    if (supplied == null && platform == null) {
      Log.w(TAG, "nothing to verify with on this device, leaving verification to libwebrtc");
      return null;
    }

    TrustedCertificateVerifier verifier = new TrustedCertificateVerifier(
            new Trust(supplied, secureEndpoints == null
                    ? Collections.<String>emptyList() : secureEndpoints), platform);
    TurnServerChains.warm(verifier.trust.secureEndpoints);
    return verifier;
  }

  /**
   * Replaces what this verifier decides from, for a peer connection whose configuration changed.
   *
   * <p>Called only after the native `setConfiguration` has been accepted, so a rejected update
   * leaves the previous trust in force. Removing a certificate from the list removes the trust
   * it granted, which is why the whole snapshot is replaced rather than added to.
   */
  public void reconfigure(List<byte[]> trustedCertificates, List<String> secureEndpoints) {
    Trust replacement = new Trust(
            suppliedTrustManager(trustedCertificates),
            secureEndpoints == null ? Collections.<String>emptyList() : secureEndpoints);
    this.trust = replacement;
    TurnServerChains.warm(replacement.secureEndpoints);
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

    // Read once. Everything below works from this snapshot even if the configuration changes
    // underneath - see Trust.
    Trust snapshot = this.trust;

    Log.i(TAG, "verifying " + chain.length + " certificate(s), " + certificate.length
            + " bytes; leaf subject=" + chain[0].getSubjectDN()
            + " issuer=" + chain[0].getIssuerDN());

    List<String> hosts = coveredHosts(chain[0], snapshot.secureEndpoints);
    if (hosts.isEmpty()) {
      Log.w(TAG, "the certificate covers none of the configured turns: hosts, refusing");
      return false;
    }

    // An application-supplied direct issuer is an independent answer and needs no network.
    if (snapshot.supplied != null && refusalOf(snapshot.supplied, chain) == null) {
      Log.i(TAG, "accepted by an application-supplied issuer");
      return true;
    }

    if (platform == null) {
      // Fail closed: falling through would hand the decision back to the library's own, different
      // trust policy, which is the defect this class exists to remove.
      Log.w(TAG, "no platform trust manager, refusing");
      return false;
    }

    // Platform intermediate caches, a direct root, or a completed warm-up may already suffice.
    // Cache-only reads must not start a second connection just to confirm an existing answer.
    X509Certificate[] available = withIntermediates(
            chain, learnedFor(snapshot.secureEndpoints, hosts, System.nanoTime()));
    if (acceptedByEveryHost(available, hosts)) {
      return true;
    }

    // One deadline for missing chain material, spread across all covered endpoints.
    long deadline = System.nanoTime() + VERIFY_WAIT_NS;
    X509Certificate[] full = withIntermediates(
            chain, learnedFor(snapshot.secureEndpoints, hosts, deadline));
    return !Arrays.equals(available, full) && acceptedByEveryHost(full, hosts);
  }

  private boolean acceptedByEveryHost(X509Certificate[] chain, List<String> hosts) {
    // Recheck the whole intersection after enrichment; never carry one host's verdict forward.
    for (String host : hosts) {
      try {
        platform.check(chain, host);
      } catch (Exception refusal) {
        Log.w(TAG, "the policy for " + host + " refuses the certificate: " + refusal.getMessage());
        return false;
      }
    }

    Log.i(TAG, "accepted by the policy of every covered host: " + hosts);
    return true;
  }

  /** The configured hosts this certificate is issued for, each named once however many ports. */
  static List<String> coveredHosts(X509Certificate leaf, List<String> endpoints) {
    Set<String> hosts = new LinkedHashSet<>();
    for (String endpoint : endpoints) {
      String host = TurnServerChains.hostOf(endpoint);
      // De-duplicated because a policy belongs to a host, not to a port: the same host on 443
      // and on 5349 is one policy and must be asked once.
      if (!hosts.contains(host) && CertificateIdentity.covers(leaf, host)) {
        hosts.add(host);
      }
    }
    return new ArrayList<>(hosts);
  }

  /**
   * Chain material from the endpoints of the covered hosts, within one shared deadline.
   *
   * <p>Only covered hosts are contacted: an unrelated endpoint has nothing to teach about this
   * certificate, and reaching for it would spend the deadline and the pool on nothing. Failing to
   * learn is never a refusal - the policies are asked with whatever was gathered.
   */
  private static List<X509Certificate> learnedFor(
          List<String> endpoints, List<String> hosts, long deadline) {
    List<X509Certificate> learned = new ArrayList<>();
    for (String endpoint : endpoints) {
      if (!hosts.contains(TurnServerChains.hostOf(endpoint))) {
        continue;
      }
      long remaining = deadline - System.nanoTime();
      for (X509Certificate certificate : TurnServerChains.intermediatesFor(endpoint, remaining)) {
        if (!learned.contains(certificate)) {
          learned.add(certificate);
        }
      }
    }
    return learned;
  }

  /** Null when these anchors accept the chain as a server chain; otherwise why not. */
  private static Exception refusalOf(X509TrustManager anchors, X509Certificate[] chain) {
    try {
      // The key exchange name only reaches the trust manager's own logging; libwebrtc does not
      // tell us which suite was negotiated, and no trust manager keys off it.
      anchors.checkServerTrusted(chain, "UNKNOWN");
      return null;
    } catch (Exception e) {
      return e;
    }
  }

  private static X509Certificate[] withIntermediates(
          X509Certificate[] chain, List<X509Certificate> intermediates) {
    if (intermediates.isEmpty()) {
      return chain;
    }
    X509Certificate[] joined = new X509Certificate[chain.length + intermediates.size()];
    System.arraycopy(chain, 0, joined, 0, chain.length);
    for (int i = 0; i < intermediates.size(); i++) {
      joined[chain.length + i] = intermediates.get(i);
    }
    return joined;
  }

  private static X509TrustManager suppliedTrustManager(List<byte[]> trustedCertificates) {
    if (trustedCertificates == null || trustedCertificates.isEmpty()) {
      return null;
    }
    KeyStore keyStore = keyStoreOf(trustedCertificates);
    X509TrustManager supplied = keyStore == null ? null : trustManagerFor(keyStore);
    if (supplied == null) {
      Log.w(TAG, "none of the supplied certificates could be read");
    }
    return supplied;
  }

  private static volatile HostTrustPolicy platformPolicy;

  /**
   * The trust manager the platform hands this application, wrapped so the host-aware check can
   * be reached. Built once: it does not change under a running process.
   *
   * <p>Deliberately the DEFAULT one - {@code init((KeyStore) null)} - and not the raw system
   * store. The default is what carries the application's network security configuration; reading
   * `AndroidCAStore` directly would honour none of it.
   */
  private static HostTrustPolicy platformPolicy() {
    HostTrustPolicy built = platformPolicy;
    if (built != null) {
      return built;
    }
    synchronized (TrustedCertificateVerifier.class) {
      if (platformPolicy == null) {
        X509TrustManager base = trustManagerFor(null);
        if (base != null) {
          try {
            final X509TrustManagerExtensions extensions = new X509TrustManagerExtensions(base);
            platformPolicy = new HostTrustPolicy() {
              @Override
              public void check(X509Certificate[] chain, String host) throws Exception {
                extensions.checkServerTrusted(chain, "UNKNOWN", host);
              }
            };
          } catch (Exception e) {
            Log.w(TAG, "the platform trust manager cannot be asked with a host", e);
          }
        }
      }
      return platformPolicy;
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
        // Named by the position it was given in, because the bytes themselves say nothing useful
        // in a log. Counted rather than searched for: `List<byte[]>.indexOf` compares references,
        // so two entries holding one array would both report the first.
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
      // A null key store means "the platform's own" - the one that carries the application's
      // network security configuration - and is asked for on purpose in platformTrustManager().
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
