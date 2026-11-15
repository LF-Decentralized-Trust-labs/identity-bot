import 'dart:typed_data';

import 'package:agent_client/services/signing_a_ceremony_rotation.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// A [CeremonySigner] for a key whose seed the test holds. The app has none:
/// a device's key is held by its core, which signs through CeremonyDevice.
CeremonySigner signingWithSeed(Uint8List seed) => (raw) async {
      final key = ed.newKeyFromSeed(seed);
      try {
        return ed.sign(key, raw);
      } finally {
        key.bytes.fillRange(0, key.bytes.length, 0);
      }
    };
