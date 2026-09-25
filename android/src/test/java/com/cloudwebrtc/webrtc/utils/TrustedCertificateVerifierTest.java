package com.cloudwebrtc.webrtc.utils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

/**
 * What the verifier decides, and - more importantly - what it declines to decide.
 *
 * <p>Installing a verifier REPLACES the media library's own verdict, so a verifier built from
 * nothing usable would refuse certificates the built-in root list accepts. Every case below that
 * expects `null` is guarding that: no anchor, no verifier, and the library keeps deciding.
 *
 * <p>The fixtures are a self-signed CA, a leaf it issued, and an unrelated self-signed
 * certificate. They carry a hundred-year validity because a unit test that starts failing on a
 * date tells nobody anything useful about this class.
 */
public class TrustedCertificateVerifierTest {
  private static final String CA =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDJTCCAg2gAwIBAgIUHcCDy5TTtdAzwN5REdXBz8kvDzgwDQYJKoZIhvcNAQEL\n"
          + "BQAwITEfMB0GA1UEAwwWZmx1dHRlci13ZWJydGMgdGVzdCBDQTAgFw0yNjA5MjUx\n"
          + "MDMwMTJaGA8yMTI2MDkwMTEwMzAxMlowITEfMB0GA1UEAwwWZmx1dHRlci13ZWJy\n"
          + "dGMgdGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIk7PvVn\n"
          + "7Yn6rPuLbVTG5E2y5xLLabvcqzs2hSs1MROuewdhFR0NfP5yJpJf/D/tbMFklwjZ\n"
          + "2e4FqIXsMGo4Vv8hctxFYa+efH8BCtil8pUjIIDd8I4ZZ1Sgfv+RPhhJI2m7IsCo\n"
          + "u9qkEP50VYZ4rpuNVHJIeNF1ABr9XaC5Nga0Tmx3HhotmzqBm2vV+PO8LhNCVbZ1\n"
          + "x4UOhXfFf6LlgbyqcCZ5/zySNnLEnV66H5mvhmNmsR1mFy0s4AaLWA9hAKp8M1Dc\n"
          + "E29XQ8FHGgi5g3KXZoxzgn/n6ioaCZLeHq6Mc7c94a9Z20DBbn1i6mvMc76wZSZ5\n"
          + "1JWD+PYReoO/6Y8CAwEAAaNTMFEwHQYDVR0OBBYEFP7TIH7dOsN8qvruER9EQry8\n"
          + "LwEmMB8GA1UdIwQYMBaAFP7TIH7dOsN8qvruER9EQry8LwEmMA8GA1UdEwEB/wQF\n"
          + "MAMBAf8wDQYJKoZIhvcNAQELBQADggEBABR+DuCdUNuVoprGicWhiselD9deprPN\n"
          + "aJA3grbCaEHba72xV5On/cv33srS+ZzUxCmLbQjZkQxNIXQFMavs40Qjd6HTi1ON\n"
          + "eiNIyR8xZqB9Me+5xBICrHs4IfpsHSosBi+l9wLDyiUnoKEETABys4oyQqeSgdtC\n"
          + "mbsUU2bw63oTwISpY3/KgG2i4mWerW1SxIwGeTa5YQXT9nwFCpQb8NQ0aR4JiJGa\n"
          + "+Z2Zz09iodERnkW0NnhADxopkFrMQDte1sx4hCdFvQBQTijgt/xWMNYwdGcCO8wv\n"
          + "+K3jp6JEMwgUx0UrIibeYIgzylycq5lnl6qJxy8ppNNWfFiADwpCyYg=\n"
          + "-----END CERTIFICATE-----\n";
  private static final String LEAF =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDBzCCAe+gAwIBAgIUBlV8IQv61X/UM/Q3/sAHBuLMovEwDQYJKoZIhvcNAQEL\n"
          + "BQAwITEfMB0GA1UEAwwWZmx1dHRlci13ZWJydGMgdGVzdCBDQTAgFw0yNjA5MjUx\n"
          + "MDMwMTJaGA8yMTI2MDkwMTEwMzAxMlowFDESMBAGA1UEAwwJdHVybi50ZXN0MIIB\n"
          + "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0g48ThKMcNlqMRaPr22zldTR\n"
          + "ZdA483CrYJ7pLr6i9H8o6/bGwd7FtaFWJ3HhtkobsBXB+5oVxb1buQ5V0XEOr2z7\n"
          + "hVO5IM/A3xP/x4rYSAuqd2sJ57FdW+PzI/B9oo/4Rq/w34IffmInZNtqgvdyOi0W\n"
          + "YWAT7d7w93cJ6B1LbH/fN6JWFLks+NXOaIssZ3bXF3bRkk7iT71598Rsu1o6eUZm\n"
          + "oAZlQL7mnVaNUsJO5tviPXD0vR+8dZWCh6iZEGRhEPRKalYQ30fiCq5R24+EB/vg\n"
          + "yrRiL4IEpyIM521UZideOds4Yp47pi2CDC3heX01N88GmhWyKq0iCQrAnviAIwID\n"
          + "AQABo0IwQDAdBgNVHQ4EFgQUDN/QBO4akJo/4xbJMBz0dwHHI6YwHwYDVR0jBBgw\n"
          + "FoAU/tMgft06w3yq+u4RH0RCvLwvASYwDQYJKoZIhvcNAQELBQADggEBACJx/4c5\n"
          + "3a4P3u+eRTZXYzmWcxoTbfkNommvIluBZwLVbsGVYiM8BoeCH9c+ZdgSBARFllfk\n"
          + "QKXeXl7VCTdrxfPOXRVZGaufVKxqfFnW0zpwKCZYEQixUw8r8dypDlNeiXv6Yzeg\n"
          + "24n5BnCMgNWtqQQeK5s2ustE3ONbfbYQ7U2js3tw3E7VF+mJDXXZI55tmTjAFWrA\n"
          + "Fs0YNJ3lhBJ+4lqZ5HJAOnIDDExck466GdXRqnUNPrz0bPu+4lpV0ugLTNHkhuoh\n"
          + "FFF2yUdbcDZqG4A5HRhlTiTxSTtSUsjfEwE6phHRBk5HrmSeSO0QZHvr5JROV8DA\n"
          + "adEc/07DUk79agQ=\n"
          + "-----END CERTIFICATE-----\n";
  private static final String STRANGER =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDCTCCAfGgAwIBAgIUC5PghRLW8RPUHeBlefVf90joj2wwDQYJKoZIhvcNAQEL\n"
          + "BQAwEzERMA8GA1UEAwwIc3RyYW5nZXIwIBcNMjYwOTI1MTAzMDEyWhgPMjEyNjA5\n"
          + "MDExMDMwMTJaMBMxETAPBgNVBAMMCHN0cmFuZ2VyMIIBIjANBgkqhkiG9w0BAQEF\n"
          + "AAOCAQ8AMIIBCgKCAQEAybEmPIGot4JGcyt7gsws8Z3u+BztegUMr9KXJZgdq+w1\n"
          + "SFVHlplyZyCudJRRpH2MXgX19T5jZc8o5wemLeWn2moVjuW3agZUQ+VVLV+dYEFl\n"
          + "pdBFqq1y+EKp/KQJdL2CQmS49Gea1N9XqfyFgyrbOj1IsTQFMXmnsIc8cXPzPNcd\n"
          + "4isRJeZCRnKkzLxHFOdjFQOPuxLRgHIr7XqbMSX+wCO16DVNaWyh6+5jc2teF/eq\n"
          + "bxwPeKLm4h60PXtWFvj6mMnJ1QMjODdwiOJdAOiPH47MZfx4r3OFN2aPNZq2IfhQ\n"
          + "f1A0o+lVE25PUgmcGN+XnVDvS1ZySR6tq2PUgopnEQIDAQABo1MwUTAdBgNVHQ4E\n"
          + "FgQU0ivwmjxvJ/X9D+Fn4JTUjr/+CnQwHwYDVR0jBBgwFoAU0ivwmjxvJ/X9D+Fn\n"
          + "4JTUjr/+CnQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAwcU8\n"
          + "esAuXrmsXJLfTZS/nmQfawX+p0hwAMihXaOTRu/6J7n+iV7jkT7mNJvdNFz1XM1g\n"
          + "kzqYGTtA+g/l0kZP5p5u9Y8OofA+IUZv0RSlbG5irN9Cv6xLTQ8ZtG4oX1DAXbke\n"
          + "mPbDVheibECOMtEZpQy7a8XwbiUnxXEyvFuqxa1jol2qLXpwu2eDvEXy8V+6zuxg\n"
          + "hFLezFWHqSUnAFzqtHW82brcEX8hfDbe9jdGg4+9ZB9+vc8O3FdTidqk03pbA2F2\n"
          + "UNSRE07Y8VvXeVgez9f/PptkRcOqVJQw55WE5ZNDsMDq7twM7hziac4kziA84jdU\n"
          + "jaj+eGlE1z38z8hU2A==\n"
          + "-----END CERTIFICATE-----\n";

  private static byte[] bytes(String pem) {
    return pem.getBytes(StandardCharsets.UTF_8);
  }

  @Test
  public void leavesTheDecisionAloneWhenNothingWasSupplied() {
    assertNull(TrustedCertificateVerifier.create(null));
    assertNull(TrustedCertificateVerifier.create(Collections.<byte[]>emptyList()));
  }

  @Test
  public void leavesTheDecisionAloneWhenNothingSuppliedCouldBeRead() {
    assertNull(TrustedCertificateVerifier.create(
            Collections.singletonList("not a certificate".getBytes(StandardCharsets.UTF_8))));
  }

  @Test
  public void keepsTheAnchorsItCouldReadWhenOneEntryIsRubbish() {
    TrustedCertificateVerifier verifier = TrustedCertificateVerifier.create(
            Arrays.asList("not a certificate".getBytes(StandardCharsets.UTF_8), bytes(CA)));

    assertNotNull(verifier);
    assertTrue(verifier.verify(bytes(LEAF)));
  }

  @Test
  public void acceptsWhatTheSuppliedAnchorIssued() {
    TrustedCertificateVerifier verifier =
            TrustedCertificateVerifier.create(Collections.singletonList(bytes(CA)));

    assertNotNull(verifier);
    assertTrue(verifier.verify(bytes(LEAF)));
  }

  @Test
  public void refusesACertificateNoAnchorIssued() {
    TrustedCertificateVerifier verifier =
            TrustedCertificateVerifier.create(Collections.singletonList(bytes(CA)));

    assertNotNull(verifier);
    assertFalse(verifier.verify(bytes(STRANGER)));
  }

  @Test
  public void refusesWhatItCannotRead() {
    TrustedCertificateVerifier verifier =
            TrustedCertificateVerifier.create(Collections.singletonList(bytes(CA)));

    assertNotNull(verifier);
    assertFalse(verifier.verify(null));
    assertFalse(verifier.verify(new byte[0]));
    assertFalse(verifier.verify("not a certificate".getBytes(StandardCharsets.UTF_8)));
  }
}
