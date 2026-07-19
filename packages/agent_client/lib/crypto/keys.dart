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
  static AgentKeyPair generateFromSeed(Uint8List seed) {
    final seedHash = sha256.convert(seed.sublist(0, 32));
    final privateSeed = Uint8List.fromList(seedHash.bytes);

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
