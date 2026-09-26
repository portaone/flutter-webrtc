package com.cloudwebrtc.webrtc.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

/**
 * What the verifier decides, and - more importantly - what it refuses to decide.
 *
 * <p>Two things cannot be reached from a plain JVM and are therefore NOT claimed by any test
 * here: the platform trust manager (its Android stub answers every check with silence, which
 * would read as acceptance) and the behaviour of a per-domain network security configuration.
 * Those belong on a device. What IS testable here is everything that happens before a policy is
 * consulted - which host is chosen, whether one is chosen at all, what an
 * application-supplied issuer decides, and what the waiting costs.
 */
public class TrustedCertificateVerifierTest {
  private static byte[] bytes(String pem) {
    return pem.getBytes(StandardCharsets.UTF_8);
  }

  private static X509Certificate certificate(String pem) throws Exception {
    return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(bytes(pem)));
  }

  /**
   * A policy whose answers the test decides, and which records what it was asked.
   *
   * <p>It fails loudly when asked about a host the test did not name, because "was this host
   * consulted at all" is exactly what the interesting cases are about.
   */
  private static final class FakePolicy implements TrustedCertificateVerifier.HostTrustPolicy {
    final java.util.List<String> asked = new java.util.ArrayList<>();
    private final java.util.Set<String> accepting;

    FakePolicy(String... accepting) {
      this.accepting = new java.util.HashSet<>(Arrays.asList(accepting));
    }

    @Override
    public void check(X509Certificate[] chain, String host) throws Exception {
      asked.add(host);
      if (!accepting.contains(host)) {
        throw new java.security.cert.CertificateException("policy for " + host + " refuses");
      }
    }
  }

  /**
   * A certificate naming none of the configured `turns:` hosts is refused before any policy is
   * asked. libwebrtc would refuse it moments later anyway - it checks the host itself - so this
   * only makes the refusal immediate and the reason legible.
   */
  @Test
  public void refusesACertificateCoveringNoConfiguredHost() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.create(
            Collections.singletonList(bytes(TestPki.MID)),
            Arrays.asList("elsewhere.example.test:5349"));

    assertNotNull(verifier);
    assertFalse(verifier.verify(bytes(TestPki.LEAF)));
  }

  /**
   * An application-supplied DIRECT ISSUER decides on its own, with no network and no platform
   * policy, once the host has been matched. That is the documented contract.
   */
  @Test
  public void acceptsOnASuppliedDirectIssuer() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.create(
            Collections.singletonList(bytes(TestPki.MID)),
            Arrays.asList("localhost:5349"));

    assertNotNull(verifier);
    assertTrue(verifier.verify(bytes(TestPki.LEAF)));
  }

  /**
   * A supplied ROOT whose intermediate is missing is NOT promised to work, and does not. The
   * chain needed to reach that root can only be obtained through trust the root itself does not
   * grant - so the contract asks for the direct issuer instead of pretending otherwise.
   *
   * <p>The policy refuses everything here, so a `true` could only have come from the supplied
   * anchor - which is the thing under test.
   */
  @Test
  public void doesNotDiscoverAMissingIntermediateForASuppliedRoot() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.withPolicy(
            Collections.singletonList(bytes(TestPki.ROOT)),
            Arrays.asList("localhost:5349"),
            new FakePolicy());

    assertFalse(verifier.verify(bytes(TestPki.LEAF)));
  }

  @Test
  public void refusesEmptyAndUnparseableInput() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.create(
            Collections.singletonList(bytes(TestPki.MID)), Arrays.asList("localhost:5349"));

    assertNotNull(verifier);
    assertFalse(verifier.verify(new byte[0]));
    assertFalse(verifier.verify(null));
    assertFalse(verifier.verify("not a certificate".getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * An unreadable supplied entry costs only itself: the verifier is still built, because the
   * platform is expected to decide, and on a device it would.
   */
  @Test
  public void survivesAnUnreadableSuppliedCertificate() {
    assertNotNull(TrustedCertificateVerifier.create(
            Collections.singletonList("not a certificate".getBytes(StandardCharsets.UTF_8)),
            Arrays.asList("localhost:5349")));
  }

  /** Every configured host the certificate covers is selected, each once however many ports. */
  @Test
  public void selectsEveryCoveredHostOnce() throws Exception {
    assertEquals(
            Arrays.asList("a.example.test", "b.example.test"),
            TrustedCertificateVerifier.coveredHosts(certificate(TestPki.MULTI),
                    Arrays.asList("a.example.test:443", "a.example.test:5349",
                            "b.example.test:443", "c.example.test:443")));
  }

  /** A host the certificate does not cover is never consulted, whatever its position. */
  @Test
  public void neverSelectsAnUncoveredHost() throws Exception {
    assertEquals(
            Collections.singletonList("localhost"),
            TrustedCertificateVerifier.coveredHosts(certificate(TestPki.LEAF),
                    Arrays.asList("fallback.example.test:5349", "localhost:5349")));
  }

  /**
   * The wait for chain material is one budget for the whole verification. With a supplied issuer
   * answering first, nothing is waited for at all - even with an endpoint nothing listens on.
   */
  @Test
  public void aSuppliedIssuerAnswersWithoutWaitingOnTheNetwork() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.create(
            Collections.singletonList(bytes(TestPki.MID)), Arrays.asList("localhost:1"));

    long started = System.nanoTime();
    assertTrue(verifier.verify(bytes(TestPki.LEAF)));

    assertTrue("a supplied issuer must not wait on the network",
            System.nanoTime() - started < java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(1500));
  }

  /**
   * Trust follows the configuration. Removing a supplied certificate removes the trust it
   * granted, which is why the whole snapshot is replaced rather than added to - and why a peer
   * connection created before its TURN servers were known still keeps a verifier installed.
   */
  @Test
  public void reconfigureReplacesTrustRatherThanAddingToIt() {
    FakePolicy refusing = new FakePolicy();
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.withPolicy(
            null, Collections.<String>emptyList(), refusing);

    verifier.reconfigure(Collections.singletonList(bytes(TestPki.MID)),
            Arrays.asList("localhost:5349"));
    assertTrue(verifier.verify(bytes(TestPki.LEAF)));

    verifier.reconfigure(null, Arrays.asList("localhost:5349"));
    assertFalse("the removed issuer must stop being trusted", verifier.verify(bytes(TestPki.LEAF)));
  }

  /**
   * THE case this design exists to prevent. A certificate covering two configured hosts, one of
   * whose policies refuses it: the verifier must refuse too, rather than carrying on to the host
   * whose policy is milder. Consulting hosts until one accepts would be choosing a security
   * policy by trial.
   */
  @Test
  public void oneHostPolicyCannotBorrowAnother() {
    FakePolicy policy = new FakePolicy("b.example.test");
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.withPolicy(
            null,
            Arrays.asList("a.example.test:5349", "b.example.test:5349"),
            policy);

    assertFalse("a refusal by any covered host is final", verifier.verify(bytes(TestPki.MULTI)));
    assertEquals("and nothing is asked after it", Collections.singletonList("a.example.test"),
            policy.asked);
  }

  /** With every covered host accepting, the certificate is accepted - and all of them are asked. */
  @Test
  public void everyCoveredHostMustAccept() {
    FakePolicy policy = new FakePolicy("a.example.test", "b.example.test");
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.withPolicy(
            null,
            Arrays.asList("a.example.test:5349", "b.example.test:443"),
            policy);

    assertTrue(verifier.verify(bytes(TestPki.MULTI)));
    assertEquals(Arrays.asList("a.example.test", "b.example.test"), policy.asked);
  }

  /** A host the certificate does not cover is never handed to a policy at all. */
  @Test
  public void anUncoveredHostIsNeverConsulted() {
    FakePolicy policy = new FakePolicy("localhost");
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.withPolicy(
            null,
            Arrays.asList("elsewhere.example.test:5349", "localhost:5349"),
            policy);

    assertTrue(verifier.verify(bytes(TestPki.LEAF)));
    assertEquals(Collections.singletonList("localhost"), policy.asked);
  }

  /**
   * The whole verification is bounded, however many endpoints there are to learn from.
   *
   * <p>The measured defect: twelve stalled endpoints in front of a healthy one made one
   * verification take 4359 ms against a budget of 2500. Each lookup spent its own full socket
   * allowance because running it on the verifying thread ignored what was left of the shared
   * deadline. Every blocking step is now clamped to the remainder, so the cost of the lot is
   * the budget and not a multiple of it.
   *
   * <p>libwebrtc calls this synchronously while allocating a relay candidate, so an overrun is
   * not a slow verification - it is a call that does not connect.
   */
  @Test
  public void aCrowdOfStalledEndpointsStaysInsideTheBudget() throws Exception {
    java.util.List<LocalTlsServer> stalls = new java.util.ArrayList<>();
    try {
      java.util.List<String> endpoints = new java.util.ArrayList<>();
      for (int i = 0; i < 12; i++) {
        LocalTlsServer stall = LocalTlsServer.stalling(8000);
        stalls.add(stall);
        endpoints.add(stall.endpoint());
      }
      try (LocalTlsServer healthy = LocalTlsServer.answering()) {
        endpoints.add(healthy.endpoint());

        FakePolicy policy = new FakePolicy("localhost");
        TrustedCertificateVerifier verifier =
                TrustedCertificateVerifier.withPolicy(null, endpoints, policy);

        long started = System.nanoTime();
        boolean accepted = verifier.verify(bytes(TestPki.LEAF));
        long elapsedMs = (System.nanoTime() - started) / 1000000L;

        assertTrue("the policy still decides", accepted);
        assertTrue("one verification, one budget: " + elapsedMs + " ms", elapsedMs < 3200);
      }
    } finally {
      for (LocalTlsServer stall : stalls) {
        stall.close();
      }
    }
  }

  /**
   * Fail closed. With no policy and no supplied anchor there is nothing to decide with, and the
   * answer must be no - not a silent fall-through to the library's own, different trust list.
   */
  @Test
  public void refusesWhenThereIsNothingToDecideWith() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.withPolicy(
            null, Arrays.asList("localhost:5349"), null);

    assertFalse(verifier.verify(bytes(TestPki.LEAF)));
  }
}
