import '../utils.dart';

enum AppleAudioMode {
  default_,
  gameChat,
  measurement,
  moviePlayback,
  spokenAudio,
  videoChat,
  videoRecording,
  voiceChat,
  voicePrompt,
}

extension AppleAudioModeEnumEx on String {
  AppleAudioMode toAppleAudioMode() =>
      AppleAudioMode.values.firstWhere((d) => d.name == toLowerCase());
}

enum AppleAudioCategory {
  soloAmbient,
  playback,
  record,
  playAndRecord,
  multiRoute,
}

extension AppleAudioCategoryEnumEx on String {
  AppleAudioCategory toAppleAudioCategory() =>
      AppleAudioCategory.values.firstWhere((d) => d.name == toLowerCase());
}

enum AppleAudioCategoryOption {
  mixWithOthers,
  duckOthers,
  interruptSpokenAudioAndMixWithOthers,
  allowBluetooth,
  allowBluetoothA2DP,
  allowAirPlay,
  defaultToSpeaker,
}

extension AppleAudioCategoryOptionEnumEx on String {
  AppleAudioCategoryOption toAppleAudioCategoryOption() =>
      AppleAudioCategoryOption.values
          .firstWhere((d) => d.name == toLowerCase());
}

class AppleAudioConfiguration {
  AppleAudioConfiguration({
    this.appleAudioCategory,
    this.appleAudioCategoryOptions,
    this.appleAudioMode,
  });
  final AppleAudioCategory? appleAudioCategory;
  final Set<AppleAudioCategoryOption>? appleAudioCategoryOptions;
  final AppleAudioMode? appleAudioMode;

  Map<String, dynamic> toMap() => <String, dynamic>{
        if (appleAudioCategory != null)
          'appleAudioCategory': appleAudioCategory!.name,
        if (appleAudioCategoryOptions != null)
          'appleAudioCategoryOptions':
              appleAudioCategoryOptions!.map((e) => e.name).toList(),
        if (appleAudioMode != null) 'appleAudioMode': appleAudioMode!.name,
      };
}

enum AppleAudioIOMode {
  none,
  remoteOnly,
  localOnly,
  localAndRemote,
}

class AppleNativeAudioManagement {
  static AppleAudioIOMode currentMode = AppleAudioIOMode.none;

  static AppleAudioConfiguration getAppleAudioConfigurationForMode(
      AppleAudioIOMode mode,
      {bool preferSpeakerOutput = false}) {
    currentMode = mode;
    if (mode == AppleAudioIOMode.remoteOnly) {
      return AppleAudioConfiguration(
        appleAudioCategory: AppleAudioCategory.playback,
        appleAudioCategoryOptions: {
          AppleAudioCategoryOption.mixWithOthers,
        },
        appleAudioMode: AppleAudioMode.spokenAudio,
      );
    } else if ([
      AppleAudioIOMode.localOnly,
      AppleAudioIOMode.localAndRemote,
    ].contains(mode)) {
      return AppleAudioConfiguration(
        appleAudioCategory: AppleAudioCategory.playAndRecord,
        appleAudioCategoryOptions: {
          AppleAudioCategoryOption.allowBluetooth,
          AppleAudioCategoryOption.mixWithOthers,
        },
        appleAudioMode: preferSpeakerOutput
            ? AppleAudioMode.videoChat
            : AppleAudioMode.voiceChat,
      );
    }

    return AppleAudioConfiguration(
      appleAudioCategory: AppleAudioCategory.soloAmbient,
      appleAudioCategoryOptions: {},
      appleAudioMode: AppleAudioMode.default_,
    );
  }

  static Future<void> setAppleAudioConfiguration(
      AppleAudioConfiguration config) async {
    if (WebRTC.platformIsIOS) {
      await WebRTC.invokeMethod(
        'setAppleAudioConfiguration',
        <String, dynamic>{'configuration': config.toMap()},
      );
    }
  }

  /// Hands control of the audio session to the application.
  ///
  /// With manual audio on, WebRTC stops activating and deactivating
  /// `AVAudioSession` by itself. The application then has to forward the
  /// CallKit `CXProviderDelegate` callbacks through [audioSessionDidActivate]
  /// and [audioSessionDidDeactivate], and gate audio with [setIsAudioEnabled].
  /// iOS only, a no-op elsewhere.
  static Future<void> setUseManualAudio(bool value) async {
    if (WebRTC.platformIsIOS) {
      await WebRTC.invokeMethod(
        'setUseManualAudio',
        <String, dynamic>{'value': value},
      );
    }
  }

  /// Whether WebRTC may run audio while manual audio is on.
  ///
  /// Enable it once the session is active, disable it before the session is
  /// torn down. iOS only, a no-op elsewhere.
  static Future<void> setIsAudioEnabled(bool value) async {
    if (WebRTC.platformIsIOS) {
      await WebRTC.invokeMethod(
        'setIsAudioEnabled',
        <String, dynamic>{'value': value},
      );
    }
  }

  /// Tells WebRTC the audio session has been activated.
  ///
  /// Call it from `provider:didActivateAudioSession:`. iOS only, a no-op
  /// elsewhere.
  static Future<void> audioSessionDidActivate() async {
    if (WebRTC.platformIsIOS) {
      await WebRTC.invokeMethod('audioSessionDidActivate');
    }
  }

  /// Tells WebRTC the audio session is about to be deactivated.
  ///
  /// Call it from `provider:didDeactivateAudioSession:`. iOS only, a no-op
  /// elsewhere.
  static Future<void> audioSessionDidDeactivate() async {
    if (WebRTC.platformIsIOS) {
      await WebRTC.invokeMethod('audioSessionDidDeactivate');
    }
  }

  /// Restarts the audio device module's playout and recording.
  ///
  /// The `AVAudioEngine` module keeps state of its own, and
  /// [audioSessionDidActivate] does not bring it back once CallKit has
  /// deactivated the session for a hold or an interruption: the engine has
  /// stopped while the module still reports itself as running. Call this after
  /// [audioSessionDidActivate]. iOS only, a no-op elsewhere.
  static Future<void> restartAudio() async {
    if (WebRTC.platformIsIOS) {
      await WebRTC.invokeMethod('restartAudio', <String, dynamic>{});
    }
  }
}
