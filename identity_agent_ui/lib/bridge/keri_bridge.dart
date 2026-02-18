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
  Future<BridgeInceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    // This method is backed by flutter_rust_bridge calling into
    // the Rust keri-core crate. The generated Dart bindings from
    // flutter_rust_bridge_codegen will replace this implementation.
    //
    // On mobile (iOS/Android), the Rust native library (.so/.dylib)
    // is compiled and linked via flutter_rust_bridge. The generated
    // code calls into rust/src/api/keri_bridge.rs::incept_aid().
    //
    // To compile:
    //   1. cd identity_agent_ui
    //   2. flutter_rust_bridge_codegen generate
    //   3. flutter build apk (or ios)
    throw UnimplementedError(
      'KeriBridge.inceptAid requires native Rust compilation. '
      'Run flutter_rust_bridge_codegen generate to create bindings. '
      'This cannot run on web or without the compiled Rust library.',
    );
  }

  Future<BridgeRotationResult> rotateAid({
    required String name,
  }) async {
    throw UnimplementedError(
      'KeriBridge.rotateAid requires native Rust compilation. '
      'Run flutter_rust_bridge_codegen generate to create bindings.',
    );
  }

  Future<BridgeSignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    throw UnimplementedError(
      'KeriBridge.signPayload requires native Rust compilation. '
      'Run flutter_rust_bridge_codegen generate to create bindings.',
    );
  }

  Future<String> getCurrentKel({
    required String name,
  }) async {
    throw UnimplementedError(
      'KeriBridge.getCurrentKel requires native Rust compilation. '
      'Run flutter_rust_bridge_codegen generate to create bindings.',
    );
  }

  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    throw UnimplementedError(
      'KeriBridge.verifySignature requires native Rust compilation. '
      'Run flutter_rust_bridge_codegen generate to create bindings.',
    );
  }
}
