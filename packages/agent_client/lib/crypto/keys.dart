import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'bip39.dart';

class AgentKeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;

  AgentKeyPair({required this.publicKey, required this.privateKey});

  /// The key pair a 32-byte Ed25519 signing seed makes.
  factory AgentKeyPair.fromSigningSeed(Uint8List signingSeed) {
    final privateKey = ed.newKeyFromSeed(signingSeed);
    return AgentKeyPair(
      publicKey: Uint8List.fromList(ed.public(privateKey).bytes),
      privateKey: Uint8List.fromList(privateKey.bytes),
    );
  }

  String get publicKeyEncoded {
    // CESR qb64 for a 32-byte Ed25519 verkey under the 1-char code "D", the
    // transferable code: an identity whose keys rotate names each key with D.
    // One pad byte is prepended so the key material lands on a base64
    // boundary, and the code replaces the leading output char — the same shape
    // OwnerSignature.blake3QB64 (code "E") and sigQB64 (code "0B") use.
    //
    // This was "B", the code for a key that can never rotate, which KERI's
    // code table does not allow in a transferable identity's key list. It also
    // kept the core from recognising a key it derives itself: the core writes
    // its own key with D, so the same key under B compared as a different one.
    //
    // An earlier form, 'B' + base64(key), omitted the pad byte as well, so the
    // string named in the inception's k[0] decoded to the WRONG 32 bytes and the
    // attach-signature step correctly refused the (valid) signature.
    final padded = Uint8List.fromList([0, ...publicKey]);
    final b64 = base64Url.encode(padded).replaceAll('=', '');
    return 'D${b64.substring(1)}';
  }

  String get publicKeyBase64 {
    return base64Url.encode(publicKey).replaceAll('=', '');
  }
}

class KeyManager {
  /// The branch an identity's own keys are on: m/44'/0'/0'/0'/n'. The core
  /// derives an identity's keys from the same phrase on the same path
  /// (DerivePairwiseSeed in identity-agent-core/backup), so an identity founded
  /// here is one the core can find again from the phrase.
  static const identityBranch = 0;

  /// The 32 bytes Ed25519 takes for key [index] of the identity: SLIP-0010
  /// Ed25519 from the 64-byte BIP39 [seed], at m/44'/0'/0'/0'/[index]'.
  ///
  /// [index] is which key in the identity's chain of keys: 0 is the key it was
  /// founded with, 1 the next key that founding committed to, 2 the key the
  /// first rotation commits to, and so on.
  ///
  /// Exposed because anything that SIGNS as this identity later has to arrive
  /// at the same bytes, and the only safe way to guarantee that is to call the
  /// one function rather than repeat the steps. Every key, at every index,
  /// comes from here, and identity-agent-core/backup/identity-key-vectors.json
  /// holds this function and the core's to the same answers.
  ///
  /// This replaced a SHA-256 of the seed's first half and the byte n, which
  /// only this app computed: an identity founded on it could not be recovered
  /// anywhere else from its phrase.
  static Uint8List signingSeed(Uint8List seed, {int index = 0}) {
    if (index < 0 || index >= 0x80000000) {
      throw ArgumentError.value(index, 'index', 'a key index is below 2^31');
    }
    return slip10Ed25519(seed, [
      44 | _hardened,
      0 | _hardened,
      0 | _hardened,
      identityBranch | _hardened,
      index | _hardened,
    ]);
  }

  static const _hardened = 0x80000000;

  /// SLIP-0010 for Ed25519: the master key is HMAC-SHA512 keyed "ed25519
  /// seed" over [seed], and each step of [path] — every one hardened, the only
  /// kind Ed25519 has — is HMAC-SHA512 under the chain code over 0x00, the
  /// parent key and the index, big-endian. Returns the 32-byte private key.
  static Uint8List slip10Ed25519(Uint8List seed, List<int> path) {
    var i = Hmac(sha512, utf8.encode('ed25519 seed')).convert(seed).bytes;
    var key = i.sublist(0, 32);
    var chain = i.sublist(32);
    for (final step in path) {
      if (step < _hardened || step > 0xFFFFFFFF) {
        throw ArgumentError.value(step, 'path', 'every Ed25519 step is hardened');
      }
      final data = Uint8List(37)
        ..[0] = 0
        ..setRange(1, 33, key)
        ..buffer.asByteData().setUint32(33, step);
      i = Hmac(sha512, chain).convert(data).bytes;
      key = i.sublist(0, 32);
      chain = i.sublist(32);
    }
    return Uint8List.fromList(key);
  }

  /// The key pair at [index] in the identity's chain (see [signingSeed]).
  static AgentKeyPair keyAt(Uint8List seed, int index) {
    final privateKey = ed.newKeyFromSeed(signingSeed(seed, index: index));
    return AgentKeyPair(
      publicKey: Uint8List.fromList(ed.public(privateKey).bytes),
      privateKey: Uint8List.fromList(privateKey.bytes),
    );
  }

  static AgentKeyPair generateFromSeed(Uint8List seed) => keyAt(seed, 0);

  static AgentKeyPair generateNextKeyFromSeed(Uint8List seed) => keyAt(seed, 1);

  static ({AgentKeyPair signing, AgentKeyPair next}) generateKeysFromMnemonic(
    List<String> mnemonic,
  ) {
    final seed = Bip39.mnemonicToSeed(mnemonic);
    final signingKey = generateFromSeed(seed);
    final nextKey = generateNextKeyFromSeed(seed);
    return (signing: signingKey, next: nextKey);
  }
}
