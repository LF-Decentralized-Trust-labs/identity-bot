/// Web stub for KeriBridge.
///
/// On web, flutter_rust_bridge is not available (no WASM compiled).
/// This stub provides the same public API so that main.dart compiles
/// on all platforms. All operations throw UnsupportedError.
///
/// The real implementation is in keri_bridge.dart and is loaded on
/// native platforms via conditional import in main.dart.

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

class KeriBridge {
  static bool get isAvailable => false;
  static String? get loadError => 'Not available on web';

  static Future<void> ensureInitialized() async {}

  Future<BridgeInceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    throw UnsupportedError('KeriBridge is not available on web');
  }

  Future<BridgeRotationResult> rotateAid({
    required String name,
  }) async {
    throw UnsupportedError('KeriBridge is not available on web');
  }

  Future<BridgeSignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    throw UnsupportedError('KeriBridge is not available on web');
  }

  Future<String> getCurrentKel({
    required String name,
  }) async {
    throw UnsupportedError('KeriBridge is not available on web');
  }

  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    throw UnsupportedError('KeriBridge is not available on web');
  }
}
