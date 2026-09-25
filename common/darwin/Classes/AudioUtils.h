#if TARGET_OS_IPHONE

#import <WebRTC/WebRTC.h>

@interface AudioUtils : NSObject
+ (void)ensureAudioSessionWithRecording:(BOOL)recording;
// needed for wired headphones to use headphone mic
+ (BOOL)selectAudioInput:(AVAudioSessionPort)type;
+ (void)setSpeakerphoneOn:(BOOL)enable;
+ (void)setSpeakerphoneOnButPreferBluetooth;
+ (void)deactiveRtcAudioSession;
+ (void)setUseManualAudio:(BOOL)value;
+ (void)setIsAudioEnabled:(BOOL)value;
+ (void)audioSessionDidActivate;
+ (void)audioSessionDidDeactivate;
+ (void) setAppleAudioConfiguration:(NSDictionary*)configuration;
@end

#endif
