import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import 'owner_signature.dart';

/// What a person signs to say something to, or about, a conversation (ADR-067):
/// a statement over a salted fingerprint of their words. The record keeps the
/// statement and never the words.
///
/// The bytes signed here must match `PersonStatement.Bytes` in the core
/// (`identity-agent-core/agentmessage/signedfingerprint.go`) exactly, and the
/// published `signed-fingerprint-vectors.json` pins them together.
class PersonStatement {
  const PersonStatement({
    required this.agent,
    required this.conversation,
    required this.messageId,
    required this.kind,
    required this.from,
    required this.signer,
    required this.nonce,
    required this.time,
    required this.fingerprint,
    this.to = '',
    this.inReplyTo = '',
    this.rangeFirst = '',
    this.rangeLast = '',
    this.fingerprintVersion = 1,
  });

  final String agent,
      conversation,
      messageId,
      kind,
      from,
      signer,
      nonce,
      time,
      fingerprint;
  final String to, inReplyTo, rangeFirst, rangeLast;
  final int fingerprintVersion;

  /// The kinds the holder of a self-owned Identity Agent signs to end, take
  /// back or lengthen a conversation (ADR-077).
  static const kindClose = 'close';
  static const kindReopen = 'reopen';
  static const kindLimit = 'limit';

  static const _tag = 'IA-PERSON-MSG-V1';

  /// The string a person signs: the tag and then one field per line in a fixed
  /// order, with no trailing newline. Only a split names a range.
  Uint8List bytes() => Uint8List.fromList(utf8.encode([
        _tag, agent, conversation, messageId, kind, from, signer, to, inReplyTo,
        rangeFirst, rangeLast, nonce, time, '$fingerprintVersion',
        fingerprint, //
      ].join('\n')));

  Map<String, dynamic> toJson() => {
        'agent': agent,
        'conversation': conversation,
        'message_id': messageId,
        'kind': kind,
        'from': from,
        'signer': signer,
        if (to.isNotEmpty) 'to': to,
        if (inReplyTo.isNotEmpty) 'in_reply_to': inReplyTo,
        if (rangeFirst.isNotEmpty) 'range_first': rangeFirst,
        if (rangeLast.isNotEmpty) 'range_last': rangeLast,
        'nonce': nonce,
        'time': time,
        'fingerprint_version': fingerprintVersion,
        'fingerprint': fingerprint,
      };

  /// The version 1 fingerprint of [words] under [salt].
  static String fingerprintOf(List<int> salt, List<int> words) {
    if (salt.length < 16 || salt.length > 1024) {
      throw ArgumentError('a salt is between 16 and 1024 bytes');
    }
    return OwnerSignature.blake3QB64([
      ...utf8.encode('IA-FINGERPRINT-V1'),
      salt.length >> 8,
      salt.length & 0xff,
      ...salt,
      ...words,
    ]);
  }

  /// The identifier of the key that signs: the non-transferable form of the
  /// Ed25519 public key (code `B`), which is the key and nothing else.
  static String signerOf(Uint8List publicKey) {
    final padded = Uint8List.fromList([0, ...publicKey]);
    return 'B${base64Url.encode(padded).replaceAll('=', '').substring(1)}';
  }

  /// The public key in verkey form (code `D`).
  static String verkeyOf(Uint8List publicKey) {
    final padded = Uint8List.fromList([0, ...publicKey]);
    return 'D${base64Url.encode(padded).replaceAll('=', '').substring(1)}';
  }

  /// A fresh salt.
  static Uint8List newSalt() {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(16, (_) => r.nextInt(256)));
  }

  /// This statement signed with the Ed25519 key of [seed]: the proof the core
  /// reads (`statement`, `verkey`, `signature`).
  Map<String, dynamic> signedWith(Uint8List seed) {
    final priv = ed.newKeyFromSeed(seed);
    try {
      final pub = Uint8List.fromList(ed.public(priv).bytes);
      if (signer != signerOf(pub)) {
        throw ArgumentError(
            'the statement names a signer that is not this key');
      }
      final sig = ed.sign(priv, bytes());
      return {
        'statement': toJson(),
        'verkey': verkeyOf(pub),
        'signature': OwnerSignature.sigQB64(Uint8List.fromList(sig)),
      };
    } finally {
      priv.bytes.fillRange(0, priv.bytes.length, 0);
    }
  }
}
