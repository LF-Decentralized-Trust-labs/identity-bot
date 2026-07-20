import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint;
import 'package:flutter/services.dart';

/// Dart-side bridge to the native ADR-027 Layer 1 hardware key wrapper.
///
/// Backed by a P-256 key generated inside the real Secure Enclave (iOS,
/// macOS today via `native_shared/HardwareKeyWrapper.swift`). The wrapping
/// key never leaves the enclave — only wrap/unwrap results cross into this
/// process. Platforms without a native implementation report unavailable;
/// callers must fall back to storing the plaintext, matching ADR-014's
/// existing behavior (see ADR-027 Consequences).
class HardwareKeyWrapper {
  static const _channel = MethodChannel('com.identityagent/hwwrap');

  static bool get _supportedPlatform =>
      !kIsWeb && (Platform.isIOS || Platform.isMacOS);

  static Future<bool> isAvailable() async {
    if (!_supportedPlatform) return false;
    try {
      return await _channel.invokeMethod<bool>('isAvailable') ?? false;
    } catch (e) {
      debugPrint('[HardwareKeyWrapper] isAvailable check failed: $e');
      return false;
    }
  }

  /// Returns the wrapped payload, or null if hardware wrapping isn't
  /// available/failed — callers should fall back to storing [plaintext] as-is.
  static Future<String?> wrap(String plaintext) async {
    if (!_supportedPlatform) return null;
    try {
      return await _channel
          .invokeMethod<String>('wrap', {'plaintext': plaintext});
    } catch (e) {
      debugPrint('[HardwareKeyWrapper] wrap failed: $e');
      return null;
    }
  }

  /// Returns the unwrapped plaintext, or null if unwrapping isn't
  /// available/failed.
  static Future<String?> unwrap(String payload) async {
    if (!_supportedPlatform) return null;
    try {
      return await _channel
          .invokeMethod<String>('unwrap', {'payload': payload});
    } catch (e) {
      debugPrint('[HardwareKeyWrapper] unwrap failed: $e');
      return null;
    }
  }
}
