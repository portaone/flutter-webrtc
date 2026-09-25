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
/// Two members beyond the W3C dictionary are read on the native side:
///
/// * `tlsCertPolicy` on an entry of `iceServers` - `'secure'` (the default)
///   or `'insecure_no_check'`. The latter gives up certificate verification
///   for that `turns:` server entirely, hostname included; it is the blunt
///   option for a deployment whose TURN certificate cannot otherwise be
///   trusted, not a CA-only exemption.
/// * `trustedCertificates` at the top level, Android only - a list of
///   `Uint8List`, each one or more DER or PEM certificates the application
///   trusts for `turns:` servers, asked before the platform trust store. Use
///   it for a private authority, or for an Android too old to carry the
///   authority that issued the server's certificate. Absent, the platform
///   store decides, under the application's network security configuration.
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
