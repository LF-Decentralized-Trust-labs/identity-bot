import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:test/test.dart';

String hexOf(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List bytesOf(String hex) =>
    Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);

List<int> pathOf(String p) => [
      for (final seg in p.substring(2).split('/')) int.parse(seg.substring(0, seg.length - 1)) | 0x80000000,
    ];

/// The vectors the core checks its own derivation against
/// (identity-agent-core/backup/identity-key-vectors.json). This package and the
/// core derive an identity's keys from its phrase the same way, or an identity
/// founded on one cannot be recovered on the other; both read this one file.
void main() {
  final file = File('../../identity-agent-core/backup/identity-key-vectors.json');
  final vectors = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;

  test('SLIP-0010\'s own Ed25519 vector reproduces', () {
    final p = vectors['slip10_published'] as Map<String, dynamic>;
    final key = KeyManager.slip10Ed25519(bytesOf(p['seed_hex'] as String), pathOf(p['path'] as String));
    expect(hexOf(key), p['private_key_hex']);
    expect(hexOf(ed.public(ed.newKeyFromSeed(key)).bytes), p['public_key_hex']);
  });

  test('every key of every phrase is the key the core derives', () {
    final phrases = vectors['phrases'] as List;
    expect(phrases, isNotEmpty);
    for (final ph in phrases.cast<Map<String, dynamic>>()) {
      final words = (ph['mnemonic'] as String).split(' ');
      final seed = Bip39.mnemonicToSeed(words);
      expect(hexOf(seed), ph['bip39_seed_hex'], reason: 'the BIP39 seed of ${words.first}…');
      for (final k in (ph['keys'] as List).cast<Map<String, dynamic>>()) {
        final n = k['index'] as int;
        expect(hexOf(KeyManager.signingSeed(seed, index: n)), k['seed_hex'], reason: 'key $n');
        expect(KeyManager.slip10Ed25519(seed, pathOf(k['path'] as String)), KeyManager.signingSeed(seed, index: n));
        final pair = KeyManager.keyAt(seed, n);
        expect(hexOf(pair.publicKey), k['public_key_hex'], reason: 'public key $n');
        // The string the app founds and rotates with is the string the core
        // writes for the same key, so a core holding this phrase recognises it.
        expect(pair.publicKeyEncoded, k['public_key_qb64'], reason: 'key $n in qb64');
      }
    }
  });

  test('a founded identity\'s keys are keys 0 and 1', () {
    final ph = (vectors['phrases'] as List).first as Map<String, dynamic>;
    final keys = KeyManager.generateKeysFromMnemonic((ph['mnemonic'] as String).split(' '));
    final want = (ph['keys'] as List).cast<Map<String, dynamic>>();
    expect(hexOf(keys.signing.publicKey), want[0]['public_key_hex']);
    expect(hexOf(keys.next.publicKey), want[1]['public_key_hex']);
  });
}
