import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

import 'key_math.dart';
import 'the_event_this_device_expects.dart';

/// What an invited owner's device did with the rotation an ownership ceremony
/// asked it to sign.
class CeremonySigned {
  const CeremonySigned(this.status, {this.nextStage, this.applied = false});

  /// "waiting_for_signatures" while other owners have still to sign, else
  /// "recorded".
  final String status;

  /// "rot2" when a hand-over goes on to its second rotation, which this device
  /// is then to fetch and sign in turn.
  final String? nextStage;

  /// The ceremony is over and the log holds the change.
  final bool applied;
}

/// The core offered an event that is not the one this device agreed to.
class CeremonyEventRefused implements Exception {
  CeremonyEventRefused(this.reason);
  final String reason;
  @override
  String toString() => 'this rotation was not signed: $reason';
}

/// Makes the signature a device's key owes over the exact bytes of a rotation.
typedef CeremonySigner = Future<List<int>> Function(Uint8List raw);

/// A [CeremonySigner] for a key whose seed this app holds.
CeremonySigner signingWithSeed(Uint8List seed) => (raw) async {
      final key = ed.newKeyFromSeed(seed);
      try {
        return ed.sign(key, raw);
      } finally {
        key.bytes.fillRange(0, key.bytes.length, 0);
      }
    };

/// Fetches the rotation an ownership ceremony is waiting on from the core at
/// [baseUrl] (the one the invite named), checks it against [expected], signs it
/// with [sign] and returns the signature (identity-agent-core
/// `owner_ceremony_rotation.go`). [token] is the invite code this device
/// redeemed with.
///
/// [expected] is built from this device's own record of the ceremony
/// ([ExpectedEvent.asAnOwnerInACeremony]); the bytes are parsed with the
/// core's parser through [km] and must be exactly it before the seed is used.
/// The stage is checked too, so a signature made for the first rotation is not
/// offered for the second. Nothing is signed on a refusal.
Future<CeremonySigned> signTheCeremonyRotation(
  http.Client client,
  String baseUrl, {
  required String token,
  required CeremonyStage stage,
  required CeremonySigner sign,
  required KeyMath km,
  required ExpectedEvent expected,
}) async {
  final place = expected.place;
  if (place == null) {
    throw ArgumentError('this is not an event of an ownership ceremony');
  }
  final offered = await client
      .get(Uri.parse('$baseUrl/api/signer/invites/$token/ceremony-event'));
  if (offered.statusCode != 200) {
    throw CeremonyEventRefused(
        'the core has no rotation waiting for this device (${offered.statusCode})');
  }
  final body = jsonDecode(offered.body) as Map<String, dynamic>;
  if (body['stage'] != stage.wire) {
    throw CeremonyEventRefused(
        'the core offered the ${body['stage']} rotation, not the ${stage.wire} one');
  }
  final raw = base64Decode(body['raw_b64'] as String);
  final ParsedEvent ev;
  try {
    ev = await expected.requireIn(km, raw);
  } on NotTheEventExpected catch (e) {
    throw CeremonyEventRefused(e.difference);
  }
  if (ev.d != body['d']) {
    throw CeremonyEventRefused(
        'the core named the event ${body['d']}, which is not the one it sent (${ev.d})');
  }
  final sig = await sign(raw);
  final cesr = await km.indexEd25519Signature(sig,
      index: place.index, ondex: place.ondex, currentOnly: place.currentOnly);
  final res = await client.post(
    Uri.parse('$baseUrl/api/signer/invites/$token/ceremony-signature'),
    headers: const {'Content-Type': 'application/json'},
    body: jsonEncode({
      'd': ev.d,
      'sigs': [cesr]
    }),
  );
  if (res.statusCode != 201 && res.statusCode != 202) {
    throw EventSignatureRefusedByCeremony(res.statusCode, res.body);
  }
  final out = jsonDecode(res.body) as Map<String, dynamic>;
  return CeremonySigned(res.statusCode == 202 ? 'waiting_for_signatures' : 'recorded',
      nextStage: out['next_stage'] as String?, applied: out['applied'] == true);
}

/// The core refused a signature over a ceremony's rotation.
class EventSignatureRefusedByCeremony implements Exception {
  EventSignatureRefusedByCeremony(this.statusCode, this.body);
  final int statusCode;
  final String body;
  @override
  String toString() => 'the signature over the ceremony\'s rotation was refused ($statusCode): $body';
}
