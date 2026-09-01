import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:test/test.dart';

/// Signing as the owner has to mean signing as the key the identity was
/// founded with. Nothing else is the owner.
///
/// This is not a theoretical alignment. seedFromMnemonic truncated the BIP39
/// seed to 32 bytes while KeyManager hashes those same bytes, so the seed it
/// handed to the signer produced a key the identity had never used. Nothing
/// called it, so nothing had ever failed — and the first thing to call it would
/// have been an app talking to a hosted agent, where the only symptom is
/// "signature does not match the owner key" with no cause on screen.
void main() {
  test('the seed handed to the signer signs as the founded identity', () async {
    final words = Bip39.generateMnemonic();

    // The key the identity is founded with, and which an agent stores as owner.
    final founded = KeyManager.generateKeysFromMnemonic(words).signing.publicKey;

    // What the transport will actually sign with.
    final reader = seedFromMnemonic(
      () async => words,
      (m) => Bip39.mnemonicToSeed(m.split(' ')),
    );
    final seed = await reader();
    expect(seed, isNotNull);

    final signsAs =
        Uint8List.fromList(ed.public(ed.newKeyFromSeed(seed!)).bytes);

    expect(signsAs, equals(founded),
        reason: 'the owner client would sign with a key the identity has never '
            'used, so every owner-signed request to a hosted agent is refused');
  });

  test('no mnemonic means no seed, rather than a wrong one', () async {
    final reader = seedFromMnemonic(
      () async => null,
      (m) => Bip39.mnemonicToSeed(m.split(' ')),
    );
    expect(await reader(), isNull);
  });

  test('signingSeed is what generateFromSeed uses, so the two cannot drift',
      () {
    final seed = Bip39.mnemonicToSeed(Bip39.generateMnemonic());
    final viaHelper =
        Uint8List.fromList(ed.public(ed.newKeyFromSeed(KeyManager.signingSeed(seed))).bytes);
    final viaGenerate = KeyManager.generateFromSeed(seed).publicKey;
    expect(viaHelper, equals(viaGenerate));
  });
}
