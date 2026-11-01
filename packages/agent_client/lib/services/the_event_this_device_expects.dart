import 'dart:convert';

import 'key_math.dart';

/// The event a signer expects to sign, worked out from its own phrase and
/// record and never from what the core says (ADR-061 section 5).
///
/// The core prepares an event's bytes; the signer parses those bytes with the
/// core's own parser (through [KeyMath]), which checks the event is well formed,
/// carries only its type's fields and that `d` is the digest of the bytes. Then
/// every other field must equal what the signer expected, exactly, and none may
/// be missing or extra. A hint the core sends alongside is never read: what is
/// signed is the bytes, so the bytes are what is checked.
class ExpectedEvent {
  ExpectedEvent._(this.t, this.aid, this.sn, this.prior, this.fields);

  /// A founding: the signing keys, their next-key commitments (classical
  /// first, then post-quantum), the witnesses and their threshold, and its
  /// seals in order (the messaging keyset anchor).
  factory ExpectedEvent.founding({
    required List<String> keys,
    required List<String> next,
    String kt = '1',
    String nt = '1',
    List<String> witnesses = const [],
    int toad = 0,
    List<Object?> anchors = const [],
  }) =>
      ExpectedEvent._('icp', null, 0, null, {
        'kt': kt,
        'k': keys,
        'nt': nt,
        'n': next,
        'bt': toad.toRadixString(16),
        'b': witnesses,
        'c': const <String>[],
        'a': anchors,
      });

  /// A rotation of [aid] at [sn] following [prior]: a routine one at the tip,
  /// or a recovery rotation whose [prior] is the last establishment event or a
  /// kept interaction. The keys it reveals, its new commitments, its witness
  /// changes and seals.
  factory ExpectedEvent.rotation({
    required String aid,
    required int sn,
    required String prior,
    required List<String> keys,
    required List<String> next,
    String kt = '1',
    String nt = '1',
    int toad = 0,
    List<String> cuts = const [],
    List<String> adds = const [],
    List<Object?> anchors = const [],
  }) =>
      ExpectedEvent._('rot', aid, sn, prior, {
        'kt': kt,
        'k': keys,
        'nt': nt,
        'n': next,
        'bt': toad.toRadixString(16),
        'br': cuts,
        'ba': adds,
        'a': anchors,
      });

  /// An interaction of [aid] at [sn] following [prior], with its seals.
  factory ExpectedEvent.interaction({
    required String aid,
    required int sn,
    required String prior,
    required List<Object?> anchors,
  }) =>
      ExpectedEvent._('ixn', aid, sn, prior, {'a': anchors});

  final String t;

  /// The identifier, or null for a founding, whose identifier is its digest.
  final String? aid;
  final int sn;

  /// The prior event's digest, or null for a founding.
  final String? prior;

  /// Every field the event must carry besides `v`, `t`, `d`, `i`, `s` and `p`,
  /// with its exact value.
  final Map<String, Object?> fields;

  /// Parses [raw] with the core's parser and returns it when it is exactly
  /// this event; throws [NotTheEventExpected] saying the first difference.
  Future<ParsedEvent> requireIn(KeyMath km, List<int> raw) async {
    final ParsedEvent ev;
    try {
      ev = await km.parseEvent(raw);
    } on KeyMathRefused catch (e) {
      throw NotTheEventExpected(
          'the bytes are not a well-formed event: ${e.reason}');
    }
    final problem = differenceFrom(ev);
    if (problem != null) throw NotTheEventExpected(problem);
    return ev;
  }

  /// The first way [ev] differs from this event, or null when it is it.
  String? differenceFrom(ParsedEvent ev) {
    if (ev.t != t) return 'it is a ${ev.t}, not a $t';
    if (ev.s != sn) return 'it is at sequence number ${ev.s}, not $sn';
    if (aid == null) {
      if (ev.i != ev.d)
        return 'a founding is identified by its own digest, and this one is not';
    } else {
      if (ev.i != aid) return 'it is an event of ${ev.i}, not of $aid';
      if (ev.p != prior) return 'it follows ${ev.p}, not $prior';
    }
    const framing = {'v', 't', 'd', 'i', 's', 'p'};
    final seen = <String>{};
    for (final f in ev.fields) {
      if (framing.contains(f.name)) continue;
      if (!fields.containsKey(f.name))
        return 'it carries a field "${f.name}" that was not asked for';
      if (!seen.add(f.name)) return 'it carries "${f.name}" twice';
      if (jsonEncode(f.value) != jsonEncode(fields[f.name])) {
        return 'its "${f.name}" is ${jsonEncode(f.value)}, not ${jsonEncode(fields[f.name])}';
      }
    }
    for (final name in fields.keys) {
      if (!seen.contains(name)) return 'it has no "$name"';
    }
    return null;
  }
}

/// The bytes the core prepared are not the event this device expected, so
/// they are not signed.
class NotTheEventExpected implements Exception {
  NotTheEventExpected(this.difference);
  final String difference;
  @override
  String toString() =>
      'this is not the event this device expected to sign: $difference';
}
