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
  ExpectedEvent._(this.t, this.aid, this.sn, this.prior, this.fields,
      {Map<String, _OwnPlaces> own = const {}})
      : _own = own;

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
  /// (ADR-061 section 5, "for an event with several signers"): this signer's
  /// own key and next digests at the places [layout] gives it, the lengths and
  /// thresholds the ceremony agreed, and every other field as agreed. The
  /// other owners' keys and digests are theirs to check.
  factory ExpectedEvent.asOneOfSeveralOwners({
    required String t,
    String? aid,
    int sn = 0,
    String? prior,
    required OwnerLayout layout,
    required String myKey,
    required String myNextClassical,
    required String myNextPostQuantum,
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
    if (t == 'rot' && (aid == null || prior == null)) {
      throw ArgumentError(
          'a rotation names the identity and the event it follows');
    }
    final own = {
      'k': _OwnPlaces(layout.count, {layout.keyIndex: myKey}),
      'n': _OwnPlaces(2 * layout.count, {
        layout.nextClassicalIndex: myNextClassical,
        layout.nextPostQuantumIndex: myNextPostQuantum,
      }),
    };
    final fields = <String, Object?>{
      'kt': kt,
      'k': null,
      'nt': nt,
      'n': null,
      'bt': toad.toRadixString(16),
      if (t == 'icp') ...{'b': witnesses, 'c': const <String>[]},
      if (t == 'rot') ...{'br': cuts, 'ba': adds},
      'a': anchors,
    };
    return ExpectedEvent._(
        t, t == 'icp' ? null : aid, t == 'icp' ? 0 : sn, prior, fields,
        own: own);
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

  /// For an event with several owners, the fields of which this signer checks
  /// only its own places.
  final Map<String, _OwnPlaces> _own;

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
      final own = _own[f.name];
      if (own != null) {
        final problem = own.differenceFrom(f.name, f.value);
        if (problem != null) return problem;
        continue;
      }
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

/// The places one owner holds in an event with several (ADR-061 section 6).
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

/// A list field of which one signer checks its length and its own entries.
class _OwnPlaces {
  const _OwnPlaces(this.length, this.mine);
  final int length;
  final Map<int, String> mine;

  String? differenceFrom(String name, Object? value) {
    if (value is! List) return 'its "$name" is not a list';
    if (value.length != length) {
      return 'its "$name" has ${value.length} entries, not the $length agreed';
    }
    for (final e in value) {
      if (e is! String || e.isEmpty) {
        return 'its "$name" holds ${jsonEncode(e)}, which is not a key or digest';
      }
    }
    for (final p in mine.entries) {
      if (value[p.key] != p.value) {
        return 'its "$name" holds ${value[p.key]} at place ${p.key}, not this signer\'s ${p.value}';
      }
    }
    // This signer's key or digest anywhere else would count it twice.
    for (var i = 0; i < value.length; i++) {
      if (!mine.containsKey(i) && mine.containsValue(value[i])) {
        return 'its "$name" holds this signer\'s ${value[i]} again at place $i';
      }
    }
    return null;
  }
}

/// Whether CESR has assigned codes for an ML-DSA-65 public key and its indexed
/// signatures. Until it has, no event that reveals a post-quantum key is
/// signed, so none is ever published in a form nobody agreed (ADR-061
/// section 6). Changed only by the release that adopts the assigned codes.
class PostQuantumCodes {
  static bool get assigned => false;

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

/// The bytes the core prepared are not the event this device expected, so
/// they are not signed.
class NotTheEventExpected implements Exception {
  NotTheEventExpected(this.difference);
  final String difference;
  @override
  String toString() =>
      'this is not the event this device expected to sign: $difference';
}
