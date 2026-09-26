import 'dart:async';

import 'package:webrtc_interface/webrtc_interface.dart';

import '../desktop_capturer.dart';
import 'data_packet_cryptor_impl.dart';
import 'desktop_capturer_impl.dart';
import 'frame_cryptor_impl.dart';
import 'media_recorder_impl.dart';
import 'media_stream_impl.dart';
import 'mediadevices_impl.dart';
import 'navigator_impl.dart';
import 'rtc_peerconnection_impl.dart';
import 'rtc_video_renderer_impl.dart';
import 'utils.dart';

class RTCFactoryNative extends RTCFactory {
  RTCFactoryNative._internal();

  static final RTCFactory instance = RTCFactoryNative._internal();

  @override
  Future<MediaStream> createLocalMediaStream(String label) async {
    final response = await WebRTC.invokeMethod('createLocalMediaStream');
    if (response == null) {
      throw Exception('createLocalMediaStream return null, something wrong');
    }
    return MediaStreamNative(response['streamId'], label);
  }

  @override
  Future<RTCPeerConnection> createPeerConnection(
      Map<String, dynamic> configuration,
      [Map<String, dynamic> constraints = const {}]) async {
    var defaultConstraints = <String, dynamic>{
      'mandatory': {},
      'optional': [
        {'DtlsSrtpKeyAgreement': true},
      ],
    };

    final response = await WebRTC.invokeMethod(
      'createPeerConnection',
      <String, dynamic>{
        'configuration': configuration,
        'constraints': constraints.isEmpty ? defaultConstraints : constraints
      },
    );

    String peerConnectionId = response['peerConnectionId'];
    return RTCPeerConnectionNative(peerConnectionId, configuration);
  }

  @override
  MediaRecorder mediaRecorder() {
    return MediaRecorderNative();
  }

  @override
  VideoRenderer videoRenderer() {
    return RTCVideoRenderer();
  }

  @override
  Navigator get navigator => NavigatorNative.instance;

  @override
  FrameCryptorFactory get frameCryptorFactory =>
      FrameCryptorFactoryImpl.instance;

  @override
  Future<RTCRtpCapabilities> getRtpReceiverCapabilities(String kind) async {
    final response = await WebRTC.invokeMethod(
      'getRtpReceiverCapabilities',
      <String, dynamic>{
        'kind': kind,
      },
    );
    return RTCRtpCapabilities.fromMap(response);
  }

  @override
  Future<RTCRtpCapabilities> getRtpSenderCapabilities(String kind) async {
    final response = await WebRTC.invokeMethod(
      'getRtpSenderCapabilities',
      <String, dynamic>{
        'kind': kind,
      },
    );
    return RTCRtpCapabilities.fromMap(response);
  }
}

/// Creates a peer connection from a W3C-shaped [configuration] map.
///
/// Two members beyond the W3C dictionary are read on the native side.
///
/// `tlsCertPolicy` on an entry of `iceServers` - `'secure'` (the default) or
/// `'insecure_no_check'`. The latter gives up verification for that `turns:`
/// server entirely, hostname included; it is the blunt option for a deployment
/// whose TURN certificate cannot otherwise be trusted, not a CA-only exemption.
/// Such an entry is also excluded from everything described below: nothing about
/// it is verified, so it contributes no trust policy to the servers that are.
///
/// `trustedCertificates` at the top level, Android only - a list of `Uint8List`,
/// each holding one or more DER or PEM certificates. Read the contract before
/// using it, because it is narrower than it looks:
///
/// * **Supply the certificate that DIRECTLY ISSUED the server's.** libwebrtc
///   hands the verifier the server's certificate alone, never the chain the
///   server sent, so there is nothing to walk upwards from. A root that signs
///   the leaf itself qualifies. A private root whose intermediate is missing
///   does NOT: obtaining that intermediate would require trusting the server
///   first, which is the very thing this anchor was meant to establish.
/// * **These are an alternative to the platform's decision, not an addition to
///   it.** A supplied issuer accepts on its own, so it does not enforce the pins
///   or anchors declared in `network_security_config.xml`. That independence is
///   the point - it is what makes a private authority, an authority the platform
///   has dropped, or an Android too old to carry the issuing root work at all.
/// * Absent, the platform decides, under the application's own network security
///   configuration.
///
/// On the platform path two restrictions follow from what libwebrtc does not
/// pass to a verifier, and both can refuse a certificate an ordinary Android TLS
/// connection would accept:
///
/// * The host is not given, so it is taken from the `turns:` URLs in
///   `iceServers`. Trust is then the INTERSECTION of the policies of every
///   configured host the certificate covers: all of them must accept. A
///   certificate covering one host pinned to another key and one meant to be
///   accepted normally is therefore refused, even when the connection was to the
///   second. Configure hosts needing different policies on separate peer
///   connections.
/// * Identity comes from subject alternative names only - DNS names against DNS
///   entries, IP literals against IP entries, wildcards over exactly one label.
///   A certificate with no SAN matches nothing, whatever its common name says,
///   and one covering none of the configured `turns:` hosts is refused outright.
///
Future<RTCPeerConnection> createPeerConnection(
    Map<String, dynamic> configuration,
    [Map<String, dynamic> constraints = const {}]) async {
  return RTCFactoryNative.instance
      .createPeerConnection(configuration, constraints);
}

Future<MediaStream> createLocalMediaStream(String label) async {
  return RTCFactoryNative.instance.createLocalMediaStream(label);
}

Future<RTCRtpCapabilities> getRtpReceiverCapabilities(String kind) async {
  return RTCFactoryNative.instance.getRtpReceiverCapabilities(kind);
}

Future<RTCRtpCapabilities> getRtpSenderCapabilities(String kind) async {
  return RTCFactoryNative.instance.getRtpSenderCapabilities(kind);
}

MediaRecorder mediaRecorder() {
  return RTCFactoryNative.instance.mediaRecorder();
}

Navigator get navigator => RTCFactoryNative.instance.navigator;

DesktopCapturer get desktopCapturer => DesktopCapturerNative.instance;

MediaDevices get mediaDevices => MediaDeviceNative.instance;

FrameCryptorFactory get frameCryptorFactory => FrameCryptorFactoryImpl.instance;

DataPacketCryptorFactory get dataPacketCryptorFactory =>
    DataPacketCryptorFactoryImpl.instance;
