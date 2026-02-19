import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;
import '../src/rust/frb_generated.dart';
import '../src/rust/api/keri_bridge.dart' as rust_api;

class BridgeInceptionResult {
  final String aid;
  final String publicKey;
  final String kel;

  BridgeInceptionResult({
    required this.aid,
    required this.publicKey,
    required this.kel,
  });
}

class BridgeRotationResult {
  final String aid;
  final String newPublicKey;
  final String kel;

  BridgeRotationResult({
    required this.aid,
    required this.newPublicKey,
    required this.kel,
  });
}

class BridgeSignatureResult {
  final String signature;
  final String publicKey;

  BridgeSignatureResult({
    required this.signature,
    required this.publicKey,
  });
}

bool get _isMobilePlatform {
  if (kIsWeb) return false;
  return Platform.isAndroid || Platform.isIOS;
}

class KeriBridge {
  static bool _rustInitialized = false;

  static Future<void> ensureInitialized() async {
    if (_rustInitialized) return;
    if (!_isMobilePlatform) return;
    await RustLib.init();
    _rustInitialized = true;
  }

  Future<BridgeInceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    if (!_isMobilePlatform) {
      throw UnsupportedError(
        'KeriBridge.inceptAid is only available on mobile (iOS/Android). '
        'Desktop uses the Python KERI driver via the Go backend.',
      );
    }
    await ensureInitialized();
    final result = rust_api.inceptAid(name: name, code: code);
    return BridgeInceptionResult(
      aid: result.aid,
      publicKey: result.publicKey,
      kel: result.kel,
    );
  }

  Future<BridgeRotationResult> rotateAid({
    required String name,
  }) async {
    if (!_isMobilePlatform) {
      throw UnsupportedError(
        'KeriBridge.rotateAid is only available on mobile (iOS/Android).',
      );
    }
    await ensureInitialized();
    final result = rust_api.rotateAid(name: name);
    return BridgeRotationResult(
      aid: result.aid,
      newPublicKey: result.newPublicKey,
      kel: result.kel,
    );
  }

  Future<BridgeSignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    if (!_isMobilePlatform) {
      throw UnsupportedError(
        'KeriBridge.signPayload is only available on mobile (iOS/Android).',
      );
    }
    await ensureInitialized();
    final result = rust_api.signPayload(name: name, data: data);
    return BridgeSignatureResult(
      signature: result.signature,
      publicKey: result.publicKey,
    );
  }

  Future<String> getCurrentKel({
    required String name,
  }) async {
    if (!_isMobilePlatform) {
      throw UnsupportedError(
        'KeriBridge.getCurrentKel is only available on mobile (iOS/Android).',
      );
    }
    await ensureInitialized();
    return rust_api.getCurrentKel(name: name);
  }

  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    if (!_isMobilePlatform) {
      throw UnsupportedError(
        'KeriBridge.verifySignature is only available on mobile (iOS/Android).',
      );
    }
    await ensureInitialized();
    return rust_api.verifySignature(
      data: data,
      signature: signature,
      publicKey: publicKey,
    );
  }
}
