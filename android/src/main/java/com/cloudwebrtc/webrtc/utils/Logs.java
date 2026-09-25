package com.cloudwebrtc.webrtc.utils;

import android.util.Log;

/**
 * {@link Log} that a local JVM test can call.
 *
 * <p>The Android stubs on a unit-test classpath throw on every method, which would otherwise
 * force {@code unitTests.returnDefaultValues} onto the whole module - and that flag silences
 * every stub for every test, hiding real failures. This narrows the concession to logging:
 * the first call that throws switches the class to standard error for the rest of the process.
 */
final class Logs {
  private static volatile boolean useAndroidLog = true;

  private Logs() { }

  static void i(String tag, String message) {
    if (useAndroidLog) {
      try {
        Log.i(tag, message);
        return;
      } catch (RuntimeException e) {
        useAndroidLog = false;
      }
    }
    System.err.println("I/" + tag + ": " + message);
  }

  static void w(String tag, String message) {
    if (useAndroidLog) {
      try {
        Log.w(tag, message);
        return;
      } catch (RuntimeException e) {
        useAndroidLog = false;
      }
    }
    System.err.println("W/" + tag + ": " + message);
  }

  static void w(String tag, String message, Throwable cause) {
    if (useAndroidLog) {
      try {
        Log.w(tag, message, cause);
        return;
      } catch (RuntimeException e) {
        useAndroidLog = false;
      }
    }
    System.err.println("W/" + tag + ": " + message + " (" + cause + ")");
  }
}
