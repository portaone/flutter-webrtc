package com.cloudwebrtc.webrtc.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

/**
 * Which ICE server entries have a chain worth learning, and what endpoint it is read from.
 *
 * <p>The learning itself is a network handshake and is not unit-testable; what IS worth pinning
 * down is the reading of the URL, because getting it wrong means either connecting to the wrong
 * port - and silently learning nothing - or trying to open TLS to a server that has none.
 */
public class TurnServerChainsTest {
  @Test
  public void keepsTheExplicitPort() {
    assertEquals("turn.example.com:443", TurnServerChains.endpointOf("turns:turn.example.com:443"));
  }

  @Test
  public void assumesTheDefaultTlsPortWhenNoneIsGiven() {
    assertEquals("turn.example.com:5349", TurnServerChains.endpointOf("turns:turn.example.com"));
  }

  @Test
  public void dropsTheTransportQuery() {
    assertEquals(
        "turn.example.com:443",
        TurnServerChains.endpointOf("turns:turn.example.com:443?transport=tcp"));
  }

  /** A plain `turn:` server presents no certificate, so there is nothing to learn from it. */
  @Test
  public void ignoresEverythingButTurns() {
    assertNull(TurnServerChains.endpointOf("turn:turn.example.com:3478?transport=udp"));
    assertNull(TurnServerChains.endpointOf("stun:stun.example.com:3478"));
    assertNull(TurnServerChains.endpointOf(null));
    assertNull(TurnServerChains.endpointOf("turns:"));
  }

  /** No endpoints means no work and, in particular, no network call. */
  @Test
  public void learnsNothingFromAnEmptyList() {
    assertTrue(TurnServerChains.intermediatesFor(Collections.<String>emptyList()).isEmpty());
    assertTrue(TurnServerChains.intermediatesFor(null).isEmpty());
  }

  /**
   * An endpoint that cannot be reached is not an error: the verifier still has whatever anchors
   * it was given, and an empty result simply means it learned nothing.
   */
  @Test
  public void survivesAnUnreachableEndpoint() {
    assertTrue(
        TurnServerChains.intermediatesFor(Arrays.asList("127.0.0.1:1")).isEmpty());
  }

  /** A bracketed IPv6 literal is all colons; none of them before the bracket is a port. */
  @Test
  public void readsIpv6Literals() {
    assertEquals("[2001:db8::1]:5349", TurnServerChains.endpointOf("turns:[2001:db8::1]"));
    assertEquals("[2001:db8::1]:443", TurnServerChains.endpointOf("turns:[2001:db8::1]:443"));
    assertEquals(
        "[::1]:443", TurnServerChains.endpointOf("turns:[::1]:443?transport=tcp"));
  }
}
