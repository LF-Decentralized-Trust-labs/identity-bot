import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'bip39.dart';

class AgentKeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;

  AgentKeyPair({required this.publicKey, required this.privateKey});

  String get publicKeyEncoded {
    return 'B${base64Url.encode(publicKey).replaceAll('=', '')}';
  }

  String get publicKeyBase64 {
    return base64Url.encode(publicKey).replaceAll('=', '');
  }
}

class KeyManager {
  /// The 32 bytes Ed25519 actually takes, for the identity's signing key.
  ///
  /// Exposed because anything that SIGNS as this identity later has to arrive
  /// at the same bytes, and the only safe way to guarantee that is to call the
  /// one function rather than repeat the steps. Repeating them is not a
  /// hypothetical risk: seedFromMnemonic did, stopped one step short, and
  /// produced a seed that signs as a key this identity has never used.
  ///
  /// A BIP39 seed is 64 bytes and Ed25519 wants 32, so something has to give.
  /// What gives is a SHA-256 of the first half — not a truncation of it. The
  /// difference is invisible until a signature is checked by somebody else.
  static Uint8List signingSeed(Uint8List seed) {
    return Uint8List.fromList(sha256.convert(seed.sublist(0, 32)).bytes);
  }

  static AgentKeyPair generateFromSeed(Uint8List seed) {
    final privateSeed = signingSeed(seed);

    final privateKey = ed.newKeyFromSeed(privateSeed);
    final publicKey = ed.public(privateKey);

    return AgentKeyPair(
      publicKey: Uint8List.fromList(publicKey.bytes),
      privateKey: Uint8List.fromList(privateKey.bytes),
    );
  }

  static AgentKeyPair generateNextKeyFromSeed(Uint8List seed) {
    final nextSeedInput = Uint8List.fromList([...seed.sublist(0, 32), 0x01]);
    final seedHash = sha256.convert(nextSeedInput);
    final privateSeed = Uint8List.fromList(seedHash.bytes);

    final privateKey = ed.newKeyFromSeed(privateSeed);
    final publicKey = ed.public(privateKey);

    return AgentKeyPair(
      publicKey: Uint8List.fromList(publicKey.bytes),
      privateKey: Uint8List.fromList(privateKey.bytes),
    );
  }

  static ({AgentKeyPair signing, AgentKeyPair next}) generateKeysFromMnemonic(
    List<String> mnemonic,
  ) {
    final seed = Bip39.mnemonicToSeed(mnemonic);
    final signingKey = generateFromSeed(seed);
    final nextKey = generateNextKeyFromSeed(seed);
    return (signing: signingKey, next: nextKey);
  }
}
