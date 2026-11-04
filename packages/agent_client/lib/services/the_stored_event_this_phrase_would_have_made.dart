import 'dart:convert';
import 'dart:typed_data';

import '../crypto/keys.dart';
import 'key_math.dart';
import 'the_event_this_device_expects.dart';

/// The event an earlier version stored unsigned, as this phrase would have
/// made it: the [ExpectedEvent] a stored, marked event must be before it is
/// signed late (ADR-061 section 3, "the signer").
///
/// Earlier versions made a founding or rotation that commits to the next
/// classical key alone, with one key at a threshold of one, no post-quantum
/// commitment and no anchor; a rotation changes no witness. The keys and
/// commitments come from [seed]; where the event sits and what it follows from
/// the log's other events, parsed here ([stored], [before], [lastEstablishment]),
/// never from fields the core reports beside the bytes. What the phrase cannot
/// say, the founding's witnesses and their threshold and an interaction's
/// anchors, is read from the stored event: an interaction is signed late only
/// as an event this device asked for or the person approved, and a founding's
/// witnesses are the core's choice.
///
/// [ixnAnchors] are the seals an interaction must carry: what this device asked
/// for, or, for an interaction the person approved after being shown it, what
/// it stores. Left null, the interaction must be the anchor of a credential the
/// core issued: one seal, `{"i": x, "s": "0", "d": x}`, and nothing else.
///
/// [t], [aid], [sn] and [digest] are what this device recorded when it asked
/// for the event (or, for one the person approved, what they were shown), never
/// what the stored bytes say: the bytes must be that event. [digest] is null
/// only where the core's answer never arrived.
///
/// [generation] is the key this event reveals (0 for the founding).
/// [foundingAnchors] are the seals a founding was asked to carry (the owner
/// seal when it was made for one).
Future<ExpectedEvent> theStoredEventThisPhraseWouldHaveMade(
  KeyMath km,
  Uint8List seed, {
  required String t,
  required String aid,
  required int sn,
  String? digest,
  required ParsedEvent stored,
  required ParsedEvent? before,
  required ParsedEvent? lastEstablishment,
  required int generation,
  List<Object?> foundingAnchors = const [],
  List<Object?>? ixnAnchors,
}) async {
  Future<List<String>> next() async =>
      [await km.nextKeyDigest(KeyManager.publicKeyAt(seed, generation + 1))];
  int toadOf(ParsedEvent e) => int.tryParse('${e['bt']}', radix: 16) ?? -1;
  ExpectedEvent known(ExpectedEvent e) => digest == null ? e : e.withDigest(digest);
  switch (t) {
    case 'icp':
      return known(await theStoredFoundingThisKeyWouldHaveMade(km, stored,
          key: KeyManager.publicKeyAt(seed, 0),
          next: KeyManager.publicKeyAt(seed, 1),
          anchors: foundingAnchors));
    case 'rot':
      return known(ExpectedEvent.rotation(
          aid: aid,
          sn: sn,
          prior: before?.d ?? '',
          keys: [KeyManager.publicKeyAt(seed, generation)],
          next: await next(),
          toad: lastEstablishment == null ? -1 : toadOf(lastEstablishment)));
    case 'ixn':
      final a = stored['a'];
      final seal = a is List && a.length == 1 && a.first is Map ? (a.first as Map)['i'] : null;
      return known(ExpectedEvent.interaction(
          aid: aid,
          sn: sn,
          prior: before?.d ?? '',
          anchors: ixnAnchors ??
              (seal is String
                  ? [
                      {'i': seal, 's': '0', 'd': seal}
                    ]
                  : const [])));
    default:
      throw NotTheEventExpected('it is a $t, which this device does '
          'not sign late');
  }
}

/// The founding an earlier version stored, as the key [key] committing to
/// [next] alone would have made it: one key, one commitment, [anchors] and the
/// witnesses the core chose, read from [stored].
Future<ExpectedEvent> theStoredFoundingThisKeyWouldHaveMade(
    KeyMath km, ParsedEvent stored,
    {required String key,
    required String next,
    List<Object?> anchors = const []}) async {
  final b = stored['b'];
  return ExpectedEvent.founding(
      keys: [key],
      next: [await km.nextKeyDigest(next)],
      witnesses: b is List ? [for (final w in b) '$w'] : const [],
      toad: int.tryParse('${stored['bt']}', radix: 16) ?? -1,
      anchors: anchors);
}

/// Parses the stored bytes [rawB64] of an event with the core's parser. Bytes
/// that are not a well-formed event are a [NotTheEventExpected]: they are not
/// signed, and the person is shown them.
Future<ParsedEvent> parseTheStoredEvent(KeyMath km, String rawB64) async {
  try {
    return await km.parseEvent(base64Decode(rawB64));
  } on KeyMathRefused catch (e) {
    throw NotTheEventExpected(
        'the stored bytes are not a well-formed event: ${e.reason}');
  } on FormatException {
    throw NotTheEventExpected('the stored bytes are not base64');
  }
}
