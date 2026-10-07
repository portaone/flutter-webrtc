#if TARGET_OS_IPHONE

#import <WebRTC/WebRTC.h>

@interface AudioUtils : NSObject
// Serial queue every change of the audio session goes through, so the changes take effect in
// the order they were asked for. AVAudioSession answers a category, mode or port change only
// after the system has moved the route, which takes hundreds of milliseconds - too long for the
// main thread, where the method channel delivers them - so those are dispatched asynchronously.
// A caller that needs the session settled before it goes on enters with dispatch_sync; nothing
// that runs on this queue may do that, or call into such a caller - it would wait for itself.
+ (dispatch_queue_t)sessionQueue;
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
