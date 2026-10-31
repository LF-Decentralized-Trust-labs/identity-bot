import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

/// Has the core write a raw Ed25519 signature in CESR.
///
/// Done by the core rather than here because the encoding is part of the
/// protocol, and there is one implementation of it. Throws if no encoded
/// signature comes back.
Future<String> cesrEncodeSignature(
    http.Client client, String baseUrl, List<int> rawSignature) async {
  final res = await client.post(
    Uri.parse('$baseUrl/api/cesr/encode'),
    headers: const {'Content-Type': 'application/json'},
    body: jsonEncode({'raw_sig_b64': base64Encode(rawSignature)}),
  );
  if (res.statusCode != 200) {
    throw Exception('the signature could not be encoded '
        '(${res.statusCode}): ${res.body}');
  }
  final decoded = jsonDecode(res.body);
  final cesr = decoded is Map ? (decoded['cesr_sig'] ?? '').toString() : '';
  if (cesr.isEmpty) {
    throw Exception(
        'the signature was sent to be encoded and nothing came back');
  }
  return cesr;
}

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
}) async {
  if (aid.isEmpty || rawBytesB64.isEmpty || sequenceNumber is! int) {
    throw Exception(
        'the core did not say which event $what is, so it cannot be '
        'signed and nobody would be able to verify it');
  }
  final signature =
      ed.sign(ed.newKeyFromSeed(signingSeed), base64Decode(rawBytesB64));
  final String cesr;
  try {
    cesr = await cesrEncodeSignature(client, baseUrl, signature);
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
    throw Exception('the signature over $what was refused '
        '(${res.statusCode}): ${res.body}');
  }
  return cesr;
}
