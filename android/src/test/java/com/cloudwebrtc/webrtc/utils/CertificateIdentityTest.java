package com.cloudwebrtc.webrtc.utils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Test;

/**
 * Which host a certificate answers for.
 *
 * <p>This decides which network security policy is consulted, so a mistake here is a security
 * mistake, not a convenience one: matching a host the certificate does not cover would judge one
 * server under another server's rules.
 */
public class CertificateIdentityTest {
  private static X509Certificate certificate(String pem) throws Exception {
    return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
            new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void matchesADnsName() throws Exception {
    assertTrue(CertificateIdentity.covers(certificate(TestPki.LEAF), "localhost"));
  }

  /** The device locale must not decide: a Turkish locale lowercases "I" to a dotless form. */
  @Test
  public void matchesRegardlessOfCase() throws Exception {
    assertTrue(CertificateIdentity.covers(certificate(TestPki.LEAF), "LOCALHOST"));
  }

  @Test
  public void matchesAnIpLiteralAgainstAnIpEntry() throws Exception {
    assertTrue(CertificateIdentity.covers(certificate(TestPki.LEAF), "127.0.0.1"));
  }

  /** A name entry must not answer for an address, nor the other way round. */
  @Test
  public void doesNotCrossNamesAndAddresses() throws Exception {
    assertFalse(CertificateIdentity.covers(certificate(TestPki.MULTI), "127.0.0.1"));
    assertFalse(CertificateIdentity.covers(certificate(TestPki.LEAF), "127.0.0.2"));
  }

  @Test
  public void coversBothNamesOfAMultiNameCertificate() throws Exception {
    X509Certificate multi = certificate(TestPki.MULTI);

    assertTrue(CertificateIdentity.covers(multi, "a.example.test"));
    assertTrue(CertificateIdentity.covers(multi, "b.example.test"));
    assertFalse(CertificateIdentity.covers(multi, "c.example.test"));
  }

  /** A wildcard covers exactly one label, and never the bare domain. */
  @Test
  public void matchesOneWildcardLabelOnly() throws Exception {
    X509Certificate wild = certificate(TestPki.WILD);

    assertTrue(CertificateIdentity.covers(wild, "turn.wild.test"));
    assertFalse(CertificateIdentity.covers(wild, "wild.test"));
    assertFalse(CertificateIdentity.covers(wild, "a.b.wild.test"));
  }

  /**
   * No subject alternative name means no identity, whatever the common name says. Documented
   * contract: CN-as-hostname is long deprecated and honouring it would put a second, weaker
   * identity rule beside the platform's own.
   */
  @Test
  public void ignoresTheCommonNameEntirely() throws Exception {
    assertFalse(CertificateIdentity.covers(certificate(TestPki.NO_SAN), "nosan"));
  }

  @Test
  public void refusesNothingToMatchAgainst() throws Exception {
    assertFalse(CertificateIdentity.covers(certificate(TestPki.LEAF), null));
    assertFalse(CertificateIdentity.covers(certificate(TestPki.LEAF), ""));
  }

  /**
   * The thing that must never happen here: a host that merely looks numeric going to a resolver.
   * `999.999.999.999` and `10.0.0.1.5` are not addresses, and `InetAddress.getByName` answers
   * both with a DNS lookup - measured at tens of milliseconds on a good network, seconds on a
   * bad one, and this runs on libwebrtc's verification callback.
   */
  @Test
  public void neverResolvesAHostThatOnlyLooksNumeric() throws Exception {
    X509Certificate leaf = certificate(TestPki.LEAF);

    long started = System.nanoTime();
    assertFalse(CertificateIdentity.covers(leaf, "999.999.999.999"));
    assertFalse(CertificateIdentity.covers(leaf, "10.0.0.1.5"));
    assertFalse(CertificateIdentity.covers(leaf, "1.2.3"));
    assertFalse(CertificateIdentity.covers(leaf, "256.0.0.1"));
    long elapsed = System.nanoTime() - started;

    assertTrue("identity matching must not touch the network",
        elapsed < java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(50));
  }

  /**
   * `1234` is a host name, not the address 0.0.4.210 - which is what the deprecated integer form
   * of IPv4 would have made of it.
   */
  @Test
  public void doesNotAcceptTheIntegerFormOfAnAddress() throws Exception {
    assertFalse(CertificateIdentity.covers(certificate(TestPki.LEAF), "1234"));
  }
}
