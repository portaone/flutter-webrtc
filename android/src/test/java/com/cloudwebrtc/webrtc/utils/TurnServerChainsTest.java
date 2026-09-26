package com.cloudwebrtc.webrtc.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Which ICE entries have a chain worth learning, where it is read from, and what the waiting
 * costs when a server misbehaves.
 *
 * <p>The scheduling cases run against real loopback TLS servers rather than a mock: the defect
 * they guard against - one stalled server starving an unrelated healthy one - only exists in the
 * interaction between the pool, the read timeout and the caller's deadline.
 */
public class TurnServerChainsTest {
  private static javax.net.ssl.SSLContext previousDefault;

  /**
   * The learner goes through the application's DEFAULT socket factory on purpose, so on a JVM it
   * refuses the generated test authority exactly as it would refuse any untrusted server - which
   * is correct, and which would leave nothing to measure. Trusting that authority for the length
   * of this class is what lets the scheduling and chain-reading behaviour be exercised at all.
   */
  @BeforeClass
  public static void trustTheTestAuthority() throws Exception {
    previousDefault = javax.net.ssl.SSLContext.getDefault();
    javax.net.ssl.SSLContext.setDefault(LocalTlsServer.trustingTheAuthority());
  }

  /** Put back, because this is process-wide state and other tests run in the same JVM. */
  @AfterClass
  public static void restoreTheDefault() throws Exception {
    if (previousDefault != null) {
      javax.net.ssl.SSLContext.setDefault(previousDefault);
    }
  }

  private static long ms(long value) {
    return TimeUnit.MILLISECONDS.toNanos(value);
  }

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
    assertEquals("turn.example.com:443",
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

  /** A bracketed IPv6 literal is all colons; none of them before the bracket is a port. */
  @Test
  public void readsIpv6Literals() {
    assertEquals("[2001:db8::1]:5349", TurnServerChains.endpointOf("turns:[2001:db8::1]"));
    assertEquals("[2001:db8::1]:443", TurnServerChains.endpointOf("turns:[2001:db8::1]:443"));
    assertEquals("[::1]:443", TurnServerChains.endpointOf("turns:[::1]:443?transport=tcp"));
  }

  /** The host a certificate would name: no port, and no brackets around an IPv6 literal. */
  @Test
  public void hostOfDropsThePortAndTheBrackets() {
    assertEquals("turn.example.com", TurnServerChains.hostOf("turn.example.com:5349"));
    assertEquals("2001:db8::1", TurnServerChains.hostOf("[2001:db8::1]:443"));
  }

  @Test
  public void learnsNothingFromNothing() {
    assertTrue(TurnServerChains.intermediatesFor(null, ms(1000)).isEmpty());
  }

  /**
   * The wait is the caller's budget, not a fixed cost: zero means "only what is known now".
   *
   * <p>Against a STALLING server, because that is what caught the defect. An endpoint that
   * refuses the connection returns fast whether the budget is honoured or not, so it proved
   * nothing; a server that accepts and then says nothing blocked for the whole socket allowance
   * - measured at 917 ms for a nominal wait of zero.
   */
  @Test
  public void aZeroWaitDoesNotBlock() throws Exception {
    try (LocalTlsServer stall = LocalTlsServer.stalling(8000)) {
      long started = System.nanoTime();
      TurnServerChains.intermediatesFor(stall.endpoint(), 0);

      assertTrue("nothing left to spend means nothing is spent",
              System.nanoTime() - started < ms(300));
      Thread.sleep(50);
      assertEquals("a cache-only read cannot create speculative work", 0, stall.connections());
    }
  }

  /** A real handshake, and only the intermediates of it are kept - never the leaf. */
  @Test
  public void learnsTheIntermediateFromARealServer() throws Exception {
    try (LocalTlsServer server = LocalTlsServer.answering()) {
      List<X509Certificate> learned =
              TurnServerChains.intermediatesFor(server.endpoint(), ms(8000));

      assertEquals(1, learned.size());
      assertEquals("CN=flutter-webrtc test authority",
              learned.get(0).getSubjectDN().getName());
    }
  }

  /**
   * The defect this guards, in the shape that survived the first attempt at it: AS MANY stalled
   * endpoints as there are workers, and a healthy one behind them. Waiting for a worker meant the
   * healthy server was never even connected to - measured, `healthyConnections=0` after 2509 ms -
   * so a verification now runs the lookup it needs on its own thread instead of queueing.
   */
  @Test
  public void stalledEndpointsDoNotStarveAHealthyOneEvenWhenTheyFillThePool() throws Exception {
    try (LocalTlsServer firstStall = LocalTlsServer.stalling(8000);
         LocalTlsServer secondStall = LocalTlsServer.stalling(8000);
         LocalTlsServer thirdStall = LocalTlsServer.stalling(8000);
         LocalTlsServer healthy = LocalTlsServer.answering()) {
      // Warm-up first, so the pool is occupied and the queue behind it is filling.
      TurnServerChains.warm(Arrays.asList(
              firstStall.endpoint(), secondStall.endpoint(), thirdStall.endpoint()));

      long started = System.nanoTime();
      List<X509Certificate> learned =
              TurnServerChains.intermediatesFor(healthy.endpoint(), ms(2500));
      long elapsed = System.nanoTime() - started;

      assertEquals("the healthy endpoint must be learned regardless of the pool", 1, learned.size());
      assertTrue("and within the verifier's own budget", elapsed < ms(2500));
    }
  }

  /**
   * A caller out of time is a fact about the caller, never a verdict about the endpoint.
   *
   * <p>The defect this guards: giving up on the deadline completed the shared lookup with an
   * empty result, which was then cached as a failure for a minute. Measured on a device, a
   * zero-budget ask followed by a full-budget one reached the healthy server zero times, and the
   * same certificate on a fresh port was accepted - so the endpoint was fine and the cache was
   * not. The pool is filled first, because a free worker would learn the chain by itself and
   * hide the whole question.
   */
  @Test
  public void anAskWithNoTimeLeftDoesNotPoisonTheEndpoint() throws Exception {
    try (LocalTlsServer firstStall = LocalTlsServer.stalling(8000);
         LocalTlsServer secondStall = LocalTlsServer.stalling(8000);
         LocalTlsServer healthy = LocalTlsServer.answering()) {
      TurnServerChains.warm(Arrays.asList(firstStall.endpoint(), secondStall.endpoint()));

      assertTrue("nothing can be learned with nothing to spend",
              TurnServerChains.intermediatesFor(healthy.endpoint(), 0).isEmpty());
      assertEquals("and the server is not contacted", 0, healthy.connections());

      List<X509Certificate> learned =
              TurnServerChains.intermediatesFor(healthy.endpoint(), ms(8000));

      assertEquals("the endpoint must still be reachable", 1, healthy.connections());
      assertEquals("and its chain still learnable", 1, learned.size());
    }
  }

  /**
   * A lookup that spent its allowance waiting for a worker starts over, it does not start spent.
   *
   * <p>The warm-up allowance used to run from the moment the task was queued, so a task that
   * waited longer than the allowance connected to nothing and cached that as a failure - before
   * any verification was involved. Eight stalled endpoints ahead of a healthy one hold the two
   * workers for longer than the allowance; the assertion is that the healthy server is contacted
   * once the queue reaches it, which is what the cached failure prevented.
   */
  @Test
  public void aLookupThatWaitedForAWorkerStillGetsItsAllowance() throws Exception {
    List<LocalTlsServer> stalls = new ArrayList<>();
    try {
      List<String> endpoints = new ArrayList<>();
      for (int i = 0; i < 8; i++) {
        LocalTlsServer stall = LocalTlsServer.stalling(8000);
        stalls.add(stall);
        endpoints.add(stall.endpoint());
      }
      try (LocalTlsServer healthy = LocalTlsServer.answering()) {
        endpoints.add(healthy.endpoint());
        TurnServerChains.warm(endpoints);

        long giveUpAt = System.nanoTime() + ms(15000);
        while (healthy.connections() == 0 && System.nanoTime() < giveUpAt) {
          Thread.sleep(50);
        }

        assertEquals("the queue must reach the healthy endpoint with time to spend",
                1, healthy.connections());
        assertEquals("and what it learned must be cached, not an empty failure", 1,
                TurnServerChains.intermediatesFor(healthy.endpoint(), ms(8000)).size());
      }
    } finally {
      for (LocalTlsServer stall : stalls) {
        stall.close();
      }
    }
  }

  /**
   * A refusal to learn is not a verdict. An unreachable endpoint returns nothing, and the caller
   * is expected to go on and ask its trust policies with whatever it has.
   */
  @Test
  public void survivesAnUnreachableEndpoint() {
    assertTrue(TurnServerChains.intermediatesFor("127.0.0.1:1", ms(1500)).isEmpty());
  }

  @Test
  public void aShortCallerBudgetDoesNotPreventAFullBudgetRetry() throws Exception {
    try (LocalTlsServer server = LocalTlsServer.answering(300)) {
      assertTrue(TurnServerChains.intermediatesFor(server.endpoint(), ms(80)).isEmpty());
      assertEquals(1, TurnServerChains.intermediatesFor(server.endpoint(), ms(2500)).size());
      assertEquals("both attempts reached the server", 2, server.connections());
    }
  }

  @Test
  public void partialTlsRecordsCannotExtendTheAbsoluteDeadline() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
      Thread drip = new Thread(() -> {
        try (Socket client = server.accept()) {
          // Announce a 4096-byte handshake record, then keep each individual read alive.
          client.getOutputStream().write(new byte[]{22, 3, 3, 16, 0});
          for (int i = 0; i < 100; i++) {
            client.getOutputStream().write(0);
            client.getOutputStream().flush();
            Thread.sleep(20);
          }
        } catch (Exception closed) {
          // The client's absolute deadline closes the connection during the record.
        }
      });
      drip.setDaemon(true);
      drip.start();
      long began = System.nanoTime();
      assertTrue(TurnServerChains.intermediatesFor("localhost:" + server.getLocalPort(), ms(200)).isEmpty());
      assertTrue("partial reads must not renew the budget", System.nanoTime() - began < ms(1000));
      drip.join(1000);
    }
  }
}
