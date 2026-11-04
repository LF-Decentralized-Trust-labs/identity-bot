import 'dart:convert';

import 'package:flutter/foundation.dart';

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
  ExpectedEvent._(this.t, this.aid, this.sn, this.prior, this.fields,
      {this.layout, this.digest});

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

  /// A rotation revealing the post-quantum reserve alone: `k` is the
  /// post-quantum key of generation j−1, opening the prior `n[1]` (ADR-061
  /// sections 5 and 6). Refused while CESR has assigned no code for an
  /// ML-DSA-65 key ([PostQuantumCodes.assigned]): such a key has no agreed
  /// form, so no event may publish one.
  factory ExpectedEvent.postQuantumReserveReveal({
    required String aid,
    required int sn,
    required String prior,
    required String postQuantumKey,
    required List<String> next,
    int toad = 0,
    List<String> cuts = const [],
    List<String> adds = const [],
    List<Object?> anchors = const [],
  }) {
    PostQuantumCodes.require('a rotation revealing the post-quantum reserve');
    return ExpectedEvent.rotation(
        aid: aid,
        sn: sn,
        prior: prior,
        keys: [postQuantumKey],
        next: next,
        toad: toad,
        cuts: cuts,
        adds: adds,
        anchors: anchors);
  }

  /// A stage-two rotation: both keys revealed, `kt = nt = "2"` (ADR-061
  /// section 6). Refused while no code is assigned, and until the classical
  /// re-commit rotation the first release that knows the codes makes has been
  /// witnessed ([reCommitWitnessed]), since that rotation is what commits to a
  /// post-quantum key in the assigned form.
  factory ExpectedEvent.stageTwoRotation({
    required String aid,
    required int sn,
    required String prior,
    required String classicalKey,
    required String postQuantumKey,
    required List<String> next,
    required bool reCommitWitnessed,
    int toad = 0,
    List<String> cuts = const [],
    List<String> adds = const [],
    List<Object?> anchors = const [],
  }) {
    PostQuantumCodes.require('a stage-two rotation');
    if (!reCommitWitnessed) {
      throw PostQuantumNotYet('a stage-two rotation',
          'the re-commit rotation under the assigned codes is not yet witnessed');
    }
    return ExpectedEvent.rotation(
        aid: aid,
        sn: sn,
        prior: prior,
        keys: [classicalKey, postQuantumKey],
        next: next,
        kt: '2',
        nt: '2',
        toad: toad,
        cuts: cuts,
        adds: adds,
        anchors: anchors);
  }

  /// A founding or rotation with several owners, as one of them checks it
  /// (ADR-061 section 5, "for an event with several signers"), in stage one.
  ///
  /// [agreed] is every owner's current key and next digests, as each gave them
  /// in the ceremony and this signer recorded them, keyed by identifier; [me]
  /// is this signer, and [mine] what its own phrase derives, which must be what
  /// it agreed. `k` and `n` must be exactly the agreed keys and digests at the
  /// places the layout gives them: checking only its own places would let a
  /// core replace an owner who is not signing. The thresholds and every other
  /// field must be as agreed.
  factory ExpectedEvent.asOneOfSeveralOwners({
    required String t,
    String? aid,
    int sn = 0,
    String? prior,
    required Map<String, OwnerKeys> agreed,
    required String me,
    required OwnerKeys mine,
    required Object kt,
    required Object nt,
    List<String> witnesses = const [],
    int toad = 0,
    List<String> cuts = const [],
    List<String> adds = const [],
    List<Object?> anchors = const [],
  }) {
    if (t != 'icp' && t != 'rot') {
      throw ArgumentError.value(
          t, 't', 'only a founding or a rotation has several owners\' keys');
    }
    if (t == 'rot' && (aid == null || prior == null || sn < 1)) {
      throw ArgumentError(
          'a rotation names the identity, its place and the event it follows');
    }
    final layout = OwnerLayout(agreed.keys.toList(), me);
    if (agreed[me] != mine) {
      throw ArgumentError.value(me, 'me',
          'agreed keys other than the ones this signer\'s phrase derives');
    }
    final k = [for (final o in layout.owners) agreed[o]!.key];
    final n = [
      for (final o in layout.owners) ...[
        agreed[o]!.nextClassical,
        agreed[o]!.nextPostQuantum
      ]
    ];
    if ({...k, ...n}.length != k.length + n.length) {
      throw ArgumentError.value(
          agreed, 'agreed', 'names one key or digest more than once');
    }
    final fields = <String, Object?>{
      'kt': kt,
      'k': k,
      'nt': nt,
      'n': n,
      'bt': toad.toRadixString(16),
      if (t == 'icp') ...{'b': witnesses, 'c': const <String>[]},
      if (t == 'rot') ...{'br': cuts, 'ba': adds},
      'a': anchors,
    };
    return ExpectedEvent._(
        t, t == 'icp' ? null : aid, t == 'icp' ? 0 : sn, prior, fields,
        layout: layout);
  }

  final String t;

  /// The identifier, or null for a founding, whose identifier is its digest.
  final String? aid;
  final int sn;

  /// The prior event's digest, or null for a founding.
  final String? prior;

  /// Every field the event must carry besides `v`, `t`, `d`, `i`, `s` and `p`,
  /// with its exact value.
  final Map<String, Object?> fields;

  /// For an event with several owners, this signer's places in it, which
  /// give the index and ondex it signs with.
  final OwnerLayout? layout;

  /// The digest of the event, where this device recorded it when the core said
  /// it had added the event ([withDigest]); null where it is not yet known.
  final String? digest;

  /// This event, which must also have the digest [d] this device recorded for
  /// it, taken from that record and never from the bytes.
  ExpectedEvent withDigest(String d) => ExpectedEvent._(t, aid, sn, prior, fields,
      layout: layout, digest: d);

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

  /// [requireIn] for bytes the core stored earlier, which a person may be
  /// shown: a refusal is an [AStoredEventIsNotTheOneExpected] carrying the
  /// stored bytes as text and this event's fields, so an app can put both in
  /// front of the person. Same checks, same code; nothing is signed on a throw.
  Future<ParsedEvent> requireStoredIn(KeyMath km, List<int> raw) async {
    try {
      return await requireIn(km, raw);
    } on NotTheEventExpected catch (e) {
      throw AStoredEventIsNotTheOneExpected(
          e.difference, utf8.decode(raw, allowMalformed: true), describe());
    }
  }

  /// What this event must be, for showing a person: its type, place, the event
  /// it follows and every other field.
  Map<String, Object?> describe() => {
        't': t,
        if (aid != null) 'i': aid,
        's': sn.toRadixString(16),
        if (prior != null) 'p': prior,
        if (digest != null) 'd': digest,
        ...fields,
      };

  /// The first way [ev] differs from this event, or null when it is it.
  String? differenceFrom(ParsedEvent ev) {
    if (ev.t != t) return 'it is a ${ev.t}, not a $t';
    if (ev.s != sn) return 'it is at sequence number ${ev.s}, not $sn';
    if (digest != null && ev.d != digest) {
      return 'its digest is ${ev.d}, not the $digest this device recorded for it';
    }
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
      if (f.name == 'k' && !PostQuantumCodes.assigned) {
        final v = f.value;
        if (v is List && v.any((e) => e is! String || !_isEd25519Key(e))) {
          return 'its "k" holds a key that is not Ed25519, and no other kind may be revealed yet';
        }
      }
      if (!_sameValue(f.value, fields[f.name])) {
        return 'its "${f.name}" is ${jsonEncode(f.value)}, not ${jsonEncode(fields[f.name])}';
      }
    }
    for (final name in fields.keys) {
      if (!seen.contains(name)) return 'it has no "$name"';
    }
    return null;
  }
}

/// Whether two values hold the same content, the keys of an object in any
/// order (a list keeps its order): a seal read from a listing and the same seal
/// in the stored bytes name their fields in different orders.
bool _sameValue(Object? a, Object? b) => jsonEncode(_sorted(a)) == jsonEncode(_sorted(b));

Object? _sorted(Object? v) => v is Map
    ? {for (final k in (v.keys.map((k) => '$k').toList()..sort())) k: _sorted(v[k])}
    : v is List
        ? [for (final e in v) _sorted(e)]
        : v;

/// The places one owner holds in an event with several (ADR-061 section 6),
/// in stage one; stage two's layout (`k[2i]`, `k[2i+1]`) comes with stage two.
///
/// The owners are sorted by identifier, as ASCII strings, ascending; owner i
/// has `k[i]` and `n[2i]`, `n[2i+1]` (classical, then post-quantum), and signs
/// at index i with ondex 2i. Every signer computes this from the owner list in
/// its own record, never from the core.
class OwnerLayout {
  OwnerLayout._(this.owners, this.keyIndex);

  /// [owners] is the ceremony's owner list as this signer recorded it, in any
  /// order; [me] is this signer's identifier, which must be in it once.
  factory OwnerLayout(List<String> owners, String me) {
    final sorted = [...owners]..sort();
    for (var i = 1; i < sorted.length; i++) {
      if (sorted[i] == sorted[i - 1]) {
        throw ArgumentError.value(owners, 'owners', 'names ${sorted[i]} twice');
      }
    }
    final i = sorted.indexOf(me);
    if (i < 0) {
      throw ArgumentError.value(me, 'me', 'is not one of the owners');
    }
    return OwnerLayout._(List.unmodifiable(sorted), i);
  }

  /// The owners in the layout's order.
  final List<String> owners;

  /// This signer's place in `k`, which is also the index it signs at.
  final int keyIndex;

  int get count => owners.length;

  /// The places of this signer's next digests in `n`; the classical one is
  /// the ondex its signature names.
  int get nextClassicalIndex => 2 * keyIndex;
  int get nextPostQuantumIndex => 2 * keyIndex + 1;
}

/// One owner's keys as the ceremony agreed them: its current key and its next
/// classical and post-quantum digests.
class OwnerKeys {
  const OwnerKeys(this.key, this.nextClassical, this.nextPostQuantum);
  final String key;
  final String nextClassical;
  final String nextPostQuantum;

  @override
  bool operator ==(Object other) =>
      other is OwnerKeys &&
      other.key == key &&
      other.nextClassical == nextClassical &&
      other.nextPostQuantum == nextPostQuantum;

  @override
  int get hashCode => Object.hash(key, nextClassical, nextPostQuantum);
}

/// A transferable Ed25519 public key in qb64: code `D` and 43 more characters.
bool _isEd25519Key(String k) =>
    k.length == 44 &&
    k.startsWith('D') &&
    RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(k);

/// Whether CESR has assigned codes for an ML-DSA-65 public key and its indexed
/// signatures. Until it has, no event that reveals a post-quantum key is
/// signed, so none is ever published in a form nobody agreed (ADR-061
/// section 6). Off. Changed only by the release that adopts the assigned codes;
/// until then only a test turns it on ([useAssignedCodesInATest]), against a
/// core built with the `kerigo_pqtest` tag, and nothing under `lib` calls that.
class PostQuantumCodes {
  static bool _assigned = false;

  static bool get assigned => _assigned;

  /// Turns the setting on or off, for a test. Always put it back off. Any code
  /// that imports this package could call it, so it refuses to turn the
  /// setting on in a release build, where no test runs and the codes are not
  /// assigned.
  ///
  /// [inARelease] is whether this is a release build; a test gives it to show
  /// the refusal, since a test never runs in one.
  @visibleForTesting
  static void useAssignedCodesInATest(bool on,
      {bool inARelease = kReleaseMode}) {
    if (on && inARelease) {
      throw StateError('the post-quantum codes cannot be switched on in a '
          'release build: CESR has assigned none');
    }
    _assigned = on;
  }

  static void require(String what) {
    if (!assigned) {
      throw PostQuantumNotYet(what,
          'CESR has assigned no code for an ML-DSA-65 key, so no event may reveal one');
    }
  }
}

/// An event that would reveal a post-quantum key, refused because it may not
/// be made yet.
class PostQuantumNotYet implements Exception {
  PostQuantumNotYet(this.what, this.why);
  final String what;
  final String why;
  @override
  String toString() => '$what is not signed yet: $why';
}

/// An event the core stored is not the one this phrase would have produced,
/// so it is not signed late: [stored] is the stored bytes as text and
/// [expected] the event they should have been, both for the person to see.
class AStoredEventIsNotTheOneExpected extends NotTheEventExpected {
  AStoredEventIsNotTheOneExpected(super.difference, this.stored, this.expected);
  final String stored;
  final Map<String, Object?> expected;
  @override
  String toString() => 'a stored event is not the one this recovery phrase '
      'would have produced, so it is not signed: $difference. '
      'Stored: $stored. Expected: ${jsonEncode(expected)}';
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
