import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

import 'key_math.dart';
import 'the_event_this_device_expects.dart';

/// Signs an event of an identity's key log and records the signature against
/// it in the core: its founding, a rotation, an interaction.
///
/// [rawBytesB64] is the event exactly as the core serialised it, and
/// [signingSeed] the 32-byte seed of the key that event is checked against.
/// [what] names the event for a person reading the error ("this rotation").
/// Returns the signature in CESR.
///
/// The one way this package does it, for every event and every service. It
/// throws rather than returning quietly: an event nobody signed is refused by
/// every counterparty that checks, so finishing quietly would hand somebody an
/// identity that looks fine and cannot be used with anybody, and the failure
/// would surface weeks later as a stranger refusing them for no reason they
/// can see.
///
/// [expected] is the event this phrase would have produced at that place. The
/// bytes are parsed with the core's parser through [km] and checked against it
/// ([ExpectedEvent.requireStoredIn]) before anything is signed or sent; an
/// event that is not it throws [AStoredEventIsNotTheOneExpected], carrying
/// what was stored and what was expected, and the signing seed is not used.
///
/// Recording the same signature twice is harmless: the core checks it against
/// the event again and stores it again.
Future<String> signAndRecordEvent(
  http.Client client,
  String baseUrl, {
  required String aid,
  required Object? sequenceNumber,
  required String rawBytesB64,
  required Uint8List signingSeed,
  required String what,
  required KeyMath km,
  required ExpectedEvent expected,
}) async {
  if (aid.isEmpty || rawBytesB64.isEmpty || sequenceNumber is! int) {
    throw Exception(
        'the core did not say which event $what is, so it cannot be '
        'signed and nobody would be able to verify it');
  }
  final raw = base64Decode(rawBytesB64);
  final ev = await expected.requireStoredIn(km, raw);
  if (ev.i != aid || ev.s != sequenceNumber) {
    throw AStoredEventIsNotTheOneExpected(
        'it is event ${ev.s.toRadixString(16)} of ${ev.i}, not event '
        '${sequenceNumber.toRadixString(16)} of $aid',
        utf8.decode(raw, allowMalformed: true),
        expected.describe());
  }
  final privateKey = ed.newKeyFromSeed(signingSeed);
  final List<int> signature;
  try {
    signature = ed.sign(privateKey, raw);
  } finally {
    // The seed is the caller's to zero; the key made from it is this
    // function's.
    privateKey.bytes.fillRange(0, privateKey.bytes.length, 0);
  }
  final String cesr;
  try {
    // The core is not asked to write it (ADR-061): keymath writes it here.
    cesr = await km.signatureByTheOnlyKey(signature);
  } catch (e) {
    throw Exception('$what could not be signed: $e');
  }
  final res = await client.post(
    Uri.parse('$baseUrl/api/events/signature'),
    headers: const {'Content-Type': 'application/json'},
    body: jsonEncode({
      'aid': aid,
      'sequence_number': sequenceNumber,
      'cesr_signature': cesr,
    }),
  );
  if (res.statusCode != 200) {
    throw EventSignatureRefused(what, res.statusCode, res.body);
  }
  return cesr;
}

/// The core refused to record a signature over an event.
class EventSignatureRefused implements Exception {
  EventSignatureRefused(this.what, this.statusCode, this.body);

  /// The event, as named to [signAndRecordEvent].
  final String what;
  final int statusCode;
  final String body;

  @override
  String toString() =>
      'the signature over $what was refused ($statusCode): $body';
}
