package org.webrtc;

/**
 * Creates a peer connection with BOTH media constraints and a certificate verifier.
 *
 * <p>{@link PeerConnectionFactory} has exactly that method - it is what the two public overloads
 * both funnel into - but it is package-private, so the public API forces a choice: constraints
 * through {@code createPeerConnection(config, constraints, observer)}, or a verifier through
 * {@code createPeerConnection(config, dependencies)}, never both. Installing a verifier would
 * then silently drop legacy constraints, which still reach real settings (CPU overuse detection,
 * jitter buffer size, ICE renomination).
 *
 * <p>This class lives in {@code org.webrtc} for the sole purpose of reaching that method, the
 * same way the camera and encoder helpers beside it do.
 */
public final class PeerConnectionFactoryCertificateVerifier {
  private PeerConnectionFactoryCertificateVerifier() { }

  /** @param verifier may be null, in which case libwebrtc keeps deciding on its own. */
  public static PeerConnection createPeerConnection(
          PeerConnectionFactory factory,
          PeerConnection.RTCConfiguration configuration,
          MediaConstraints constraints,
          PeerConnection.Observer observer,
          SSLCertificateVerifier verifier) {
    return factory.createPeerConnectionInternal(configuration, constraints, observer, verifier);
  }
}
