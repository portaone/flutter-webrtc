package com.cloudwebrtc.webrtc.utils;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Whether a certificate is issued for a given host.
 *
 * <p>This is not a convenience: on the platform path the host chooses which section of the
 * application's network security configuration applies, so picking a host the certificate does
 * not cover would mean judging one server under another server's policy. Matching happens
 * BEFORE any trust evaluation, and a host the certificate does not name is never consulted.
 *
 * <p><b>Subject alternative names only.</b> A certificate carrying no SAN matches nothing here,
 * even if its common name says otherwise. CN-as-hostname has been deprecated for a decade and
 * neither the platform nor any current authority relies on it; accepting it would mean a second,
 * weaker identity rule living beside the platform's own.
 */
final class CertificateIdentity {
  /** dNSName, as numbered in RFC 5280's GeneralName. */
  private static final int DNS_NAME = 2;

  /** iPAddress, likewise. */
  private static final int IP_ADDRESS = 7;

  private CertificateIdentity() { }

  /**
   * Whether {@code certificate} is issued for {@code host}.
   *
   * @param host a host as it appears in a `turns:` URL, without port and without the brackets of
   *     an IPv6 literal - see {@link TurnServerChains#hostOf}.
   */
  static boolean covers(X509Certificate certificate, String host) {
    if (host == null || host.isEmpty()) {
      return false;
    }

    Collection<List<?>> alternatives;
    try {
      alternatives = certificate.getSubjectAlternativeNames();
    } catch (Exception e) {
      // A malformed extension is not an identity. Refusing here is the safe direction.
      return false;
    }
    if (alternatives == null) {
      return false;
    }

    InetAddress literal = ipLiteral(host);
    // Case is folded with ROOT, not the device locale: a Turkish locale lowercases "I" to a
    // dotless form and would stop "TURN.example.com" from matching "turn.example.com".
    String wanted = host.toLowerCase(Locale.ROOT);

    for (List<?> alternative : alternatives) {
      if (alternative.size() < 2) {
        continue;
      }
      Object type = alternative.get(0);
      Object value = alternative.get(1);
      if (!(type instanceof Integer) || !(value instanceof String)) {
        continue;
      }
      int kind = (Integer) type;

      // An address is only ever an address, and a name only ever a name. Comparing across the
      // two would let a certificate naming the literal text "10.0.0.1" answer for the host.
      if (literal != null) {
        if (kind == IP_ADDRESS && sameAddress(literal, (String) value)) {
          return true;
        }
        continue;
      }
      if (kind == DNS_NAME && matchesName(wanted, ((String) value).toLowerCase(Locale.ROOT))) {
        return true;
      }
    }
    return false;
  }

  /**
   * The address {@code host} is, or null when it is a name.
   *
   * <p>Parsed here rather than handed to {@link InetAddress#getByName}, which resolves anything
   * it cannot parse - measured, `999.999.999.999` and `10.0.0.1.5` each cost a DNS lookup, and
   * this runs on libwebrtc's verification callback where a hostile resolver is paid for in
   * seconds. That method also still accepts the deprecated integer form, so `1234` would come
   * back as 0.0.4.210 and a host by that name would be compared against address entries.
   */
  private static InetAddress ipLiteral(String host) {
    byte[] address = ipv4(host);
    if (address != null) {
      try {
        return InetAddress.getByAddress(address);
      } catch (Exception e) {
        return null;
      }
    }
    if (host.indexOf(':') < 0) {
      return null;
    }
    try {
      // Only a colon-bearing string reaches this, and no host name may contain a colon, so there
      // is nothing here for a resolver to look up.
      return InetAddress.getByName(host);
    } catch (Exception e) {
      return null;
    }
  }

  /** Four decimal octets and nothing else, or null. */
  private static byte[] ipv4(String host) {
    byte[] address = new byte[4];
    int octet = 0;
    int value = -1;
    int digits = 0;

    for (int i = 0; i < host.length(); i++) {
      char c = host.charAt(i);
      if (c >= '0' && c <= '9') {
        if (++digits > 3) {
          return null;
        }
        value = (value < 0 ? 0 : value) * 10 + (c - '0');
        if (value > 255) {
          return null;
        }
      } else if (c == '.') {
        if (value < 0 || octet == 3) {
          return null;
        }
        address[octet++] = (byte) value;
        value = -1;
        digits = 0;
      } else {
        return null;
      }
    }

    if (octet != 3 || value < 0) {
      return null;
    }
    address[3] = (byte) value;
    return address;
  }

  /** Compared as addresses, so that any spelling of the same IPv6 address still matches. */
  private static boolean sameAddress(InetAddress wanted, String presented) {
    InetAddress parsed = ipLiteral(presented.trim());
    return parsed != null && wanted.equals(parsed);
  }

  private static boolean matchesName(String wanted, String presented) {
    if (presented.isEmpty()) {
      return false;
    }
    if (presented.equals(wanted)) {
      return true;
    }
    // `*.example.com` covers exactly one label, and never the bare domain. Anything else - a
    // wildcard deeper in the name, or one covering a public suffix - is not honoured.
    if (!presented.startsWith("*.")) {
      return false;
    }
    String suffix = presented.substring(2);
    if (suffix.indexOf('.') < 0) {
      return false;
    }
    int dot = wanted.indexOf('.');
    return dot > 0 && wanted.substring(dot + 1).equals(suffix);
  }
}
