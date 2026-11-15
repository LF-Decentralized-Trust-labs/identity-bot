import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;

import '../crypto/owner_signature.dart';
import '../crypto/person_statement.dart';

/// What the Identity Agent answered to a close, reopen or limit.
class ConversationControlled {
  const ConversationControlled({required this.state, required this.unchanged});
  final String state;
  final bool unchanged;
}

/// The Identity Agent refused, or could not be asked.
class ConversationControlRefused implements Exception {
  const ConversationControlRefused(this.status, this.message);
  final int status;
  final String message;
  @override
  String toString() => message;
}

/// The holder of a self-owned Identity Agent saying a conversation is done,
/// taking that back, or giving it more turns (ADR-077 amendment of 2026-11-15).
///
/// A person whose Identity Agent has no other owner is that owner: they sign
/// the statement with the identity's own key, and send it on a request the
/// owner-signing [client] also signs, which is how the core knows it is the
/// holder asking. [signingSeed] gives the seed of the key in force now and is
/// read once. [identityAid] is the identity and also the Identity Agent that
/// holds the conversation, which on a self-owned Identity Agent are the same.
///
/// [limit] is the new turn limit, for [PersonStatement.kindLimit] only.
Future<ConversationControlled> holderControlsAConversation(
  http.Client client,
  String baseUrl, {
  required String identityAid,
  required Future<Uint8List> Function() signingSeed,
  required String kind,
  required String conversation,
  int? limit,
  DateTime? now,
  Uint8List? salt,
}) async {
  const kinds = [
    PersonStatement.kindClose,
    PersonStatement.kindReopen,
    PersonStatement.kindLimit,
  ];
  if (!kinds.contains(kind)) {
    throw ArgumentError('a holder signs a close, a reopen or a limit here');
  }
  if ((kind == PersonStatement.kindLimit) != (limit != null)) {
    throw ArgumentError('only a limit carries a number, and it must');
  }
  final words = kind == PersonStatement.kindLimit ? '$limit' : '';
  final seed = await signingSeed();
  final s = salt ?? PersonStatement.newSalt();
  final nonce = _id();
  final statement = PersonStatement(
    agent: identityAid,
    conversation: conversation,
    messageId: nonce,
    kind: kind,
    from: identityAid,
    signer: PersonStatement.signerOf(_publicKey(seed)),
    nonce: 'nonce-${_id()}',
    time: OwnerSignature.rfc3339Seconds((now ?? DateTime.now()).toUtc()),
    fingerprint: PersonStatement.fingerprintOf(s, utf8.encode(words)),
  );
  final proof = statement.signedWith(seed);
  final res = await client.post(
    Uri.parse('$baseUrl/api/mcp/conversations/$conversation/$kind'),
    headers: {
      'Content-Type': 'application/json',
      'X-IA-Speaking-For': identityAid,
      'X-IA-Person-Statement':
          base64Url.encode(utf8.encode(jsonEncode(proof))).replaceAll('=', ''),
      'X-IA-Person-Salt': base64Url.encode(s).replaceAll('=', ''),
    },
    body: jsonEncode(
        {'conversation': conversation, 'body': words, 'nonce': nonce}),
  );
  Map<String, dynamic> out = {};
  try {
    final j = jsonDecode(res.body);
    if (j is Map<String, dynamic>) out = j;
  } catch (_) {}
  if (res.statusCode != 200 && res.statusCode != 201) {
    throw ConversationControlRefused(
        res.statusCode, '${out['error'] ?? out['message'] ?? 'refused'}');
  }
  return ConversationControlled(
      state: '${out['state'] ?? ''}', unchanged: out['unchanged'] == true);
}

Uint8List _publicKey(Uint8List seed) {
  final priv = ed.newKeyFromSeed(seed);
  try {
    return Uint8List.fromList(ed.public(priv).bytes);
  } finally {
    priv.bytes.fillRange(0, priv.bytes.length, 0);
  }
}

String _id() {
  final b = PersonStatement.newSalt();
  return base64Url.encode(b).replaceAll('=', '');
}
