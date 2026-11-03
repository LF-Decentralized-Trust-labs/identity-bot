import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import 'key_math.dart';
import 'the_identity_this_device_holds.dart';
import 'the_key_events_this_device_makes.dart';
import 'the_witnesses_of_this_devices_events.dart';

/// An identity's key state as this device read it.
class VerifiedKeyState {
  VerifiedKeyState(
      {required this.aid,
      required this.establishment,
      required this.keyInForce,
      required this.generation,
      required this.tip,
      required this.witnesses,
      required this.fromItsOwnRecord,
      required this.corroborated,
      this.movingToThisPhrase = false});

  final String aid;

  /// The newest establishment event, and the key it revealed.
  final Place establishment;
  final String keyInForce;

  /// Which generation of this phrase's keys is in force: the key the next
  /// interaction is signed with is key [generation], and the next rotation
  /// reveals key [generation] + 1.
  final int generation;

  /// Where the log ends: what the next event follows.
  final Place tip;

  /// The witnesses in force, and their threshold.
  final WitnessSet witnesses;

  /// Whether this was read from this device's own record (source 1) rather
  /// than from copies of the log.
  final bool fromItsOwnRecord;

  /// Whether enough of the identity's witnesses hold its newest establishment
  /// event to meet their threshold; true where it names no witnesses.
  final bool corroborated;

  /// Whether the key in force is another phrase's, and commits to this
  /// phrase's first key: step 1 of a move to this phrase is in the log and
  /// step 2 is not (ADR-061 section 10). Nothing but step 2 is signed with
  /// this phrase until it is.
  final bool movingToThisPhrase;

  /// The form [TheKeyEventsThisDeviceMakes] retries a `tip_moved` with.
  KeyStateNow get now => (
        tip: (sn: tip.sn, digest: tip.digest),
        generation: generation,
        witnesses: witnesses
      );
}

/// One verified copy of an identity's log, and where it came from: a witness
/// named [witness], or the Identity Agent's discovery record.
class LogCopy {
  LogCopy(this.source, this.events, {this.witness});
  final String source;
  final String? witness;
  final List<LoggedEvent> events;
}

/// Two verified copies of the log, or a copy and this device's own record,
/// hold different establishment events at one place. Only a holder of the
/// phrase can sign one, so the phrase has been used elsewhere. Signing stops
/// and the person is shown both.
class TheLogHasTwoHistories implements Exception {
  TheLogHasTwoHistories(this.aid, this.sn, this.held);
  final String aid;
  final int sn;

  /// The digest each source holds at that place.
  final Map<String, String> held;
  @override
  String toString() => 'the log of $aid has two different establishment events '
      'at sequence number $sn ($held); this phrase has been used elsewhere';
}

/// Too few of the identity's witnesses could be read, or agree, to say which
/// establishment event is in force.
class TheWitnessesDoNotSay implements Exception {
  TheWitnessesDoNotSay(this.aid, this.why);
  final String aid;
  final String why;
  @override
  String toString() => 'the key state of $aid could not be read from its '
      'witnesses: $why';
}

/// This device made an establishment event the copies of the log do not
/// hold: the key it put in force is not in any copy enough witnesses agree on.
/// Signing with an older key would fork the log, so nothing is signed.
class TheCopiesAreBehindThisDevice implements Exception {
  TheCopiesAreBehindThisDevice(this.aid, this.made, this.read);
  final String aid;
  final Place made;
  final Place read;
  @override
  String toString() => 'this device made the establishment event at sequence '
      'number ${made.sn} of $aid, and the copies of its log go no further than '
      '${read.sn}; nothing is signed with an older key';
}

/// The key in force is not one of this phrase's, and is not the key that
/// moves the identity to it: another phrase, or someone else, controls it.
class TheKeyInForceIsNotThisPhrases implements Exception {
  TheKeyInForceIsNotThisPhrases(this.aid, this.sn, this.key);
  final String aid;
  final int sn;
  final String key;
  @override
  String toString() => 'the establishment event at sequence number $sn of $aid '
      'reveals $key, which is not a key of this recovery phrase; nothing is '
      'signed until the person has looked at it';
}

/// How this device learns the key in force of the identity whose keys it
/// holds, without asking an owner route (ADR-061 section 9).
///
/// First from its own record ([TheIdentityThisDeviceHolds]): the newest events
/// this device made. When that cannot answer, from copies of the log: each of
/// the identity's witnesses' copies, and the Identity Agent's public discovery
/// record, every one verified by the engine on this device from the founding.
/// They are combined as section 9 says: different establishment events at one
/// place stop signing; a copy that stops early is one that has not caught up;
/// the newest establishment event enough witnesses hold to meet their
/// threshold is in force, followed by the interactions every copy that reaches
/// them agrees on.
class TheKeyStateThisDeviceReads {
  TheKeyStateThisDeviceReads(this._client, this._km, this._agentBase,
      {TheIdentityThisDeviceHolds? held})
      : _held = held ?? TheIdentityThisDeviceHolds();

  final http.Client _client;
  final KeyMath _km;

  /// The Identity Agent's address, whose public discovery record is one copy.
  final String _agentBase;
  final TheIdentityThisDeviceHolds _held;

  /// The key state for the phrase whose 64-byte BIP39 seed is [seed]: from
  /// this device's record where it can answer, otherwise from the copies.
  Future<VerifiedKeyState> read(Uint8List seed) async {
    final h = await _held.read();
    if (h == null) throw StateError('this device holds no identity');
    final est = h.establishment;
    final tip = h.tip;
    final g = h.generation;
    final key = h.keyInForce;
    if (est != null &&
        tip != null &&
        g != null &&
        key != null &&
        KeyManager.keyAt(seed, g).publicKeyEncoded == key) {
      return VerifiedKeyState(
          aid: h.aid,
          establishment: est,
          keyInForce: key,
          generation: g,
          tip: tip,
          witnesses: WitnessSet(h.witnesses, h.toad),
          fromItsOwnRecord: true,
          corroborated: true);
    }
    return readTheCopies(seed);
  }

  /// The key state read from copies of the log, never from this device's
  /// record alone, which is then brought up to it. [acceptTheCoreAlone] takes
  /// the discovery record's copy where no witness can be read: the state an
  /// identity founded before this device kept witness addresses is in, until
  /// it learns them. The result says it was not corroborated.
  Future<VerifiedKeyState> readTheCopies(Uint8List seed,
      {bool acceptTheCoreAlone = false}) async {
    final h = await _held.read();
    if (h == null) throw StateError('this device holds no identity');
    final aid = h.aid;
    final witnesses = TheWitnessesOfThisDevicesEvents(
        _client, _km, KnownWitnesses(h.witnessAddresses));
    final copies = <LogCopy>[];
    await Future.wait([
      for (final w in h.witnessAddresses.keys)
        witnesses.copyHeldBy(w, aid).then((st) {
          if (st != null)
            copies.add(LogCopy('witness $w', st.events, witness: w));
        }),
      _discoveryCopy(aid).then((c) {
        if (c != null) copies.add(c);
      }),
    ]);
    final made = h.establishment;
    final read = combine(aid, copies,
        made: made == null ? const [] : [made],
        acceptTheCoreAlone: acceptTheCoreAlone);
    final e = read.establishment;
    final key = e.keys.isEmpty ? '' : e.keys.first;

    // Once this phrase's keys are in force, every establishment event after
    // is this phrase's: anything else is another phrase, or someone else.
    var ours = false;
    for (final ev in read.events) {
      if (!ev.establishment) continue;
      final k = ev.keys.isEmpty ? '' : ev.keys.first;
      final mine = _generationOf(seed, k) != null || h.keysRevealed.contains(k);
      if (mine) ours = true;
      if (ours && !mine) throw TheKeyInForceIsNotThisPhrases(aid, ev.sn, k);
    }

    var g = _generationOf(seed, key);
    var moving = false;
    if (g == null) {
      // Step 1 of a move to this phrase reveals the old phrase's key and
      // commits to this phrase's key 1.
      final first =
          await _km.nextKeyDigest(KeyManager.keyAt(seed, 1).publicKeyEncoded);
      if (e.next.isEmpty || e.next.first != first) {
        throw TheKeyInForceIsNotThisPhrases(aid, e.sn, key);
      }
      g = 0;
      moving = true;
    }
    final tip = read.tip;
    final state = VerifiedKeyState(
        aid: aid,
        establishment: (sn: e.sn, digest: e.digest),
        keyInForce: key,
        generation: g,
        tip: (sn: tip.sn, digest: tip.digest),
        witnesses: WitnessSet(tip.witnesses, tip.toad),
        fromItsOwnRecord: false,
        corroborated: read.corroborated,
        movingToThisPhrase: moving);
    if (!moving) {
      await _held.readFromCopies(
          aid: aid,
          establishment: state.establishment,
          key: key,
          generation: g,
          tip: state.tip,
          witnesses: tip.witnesses,
          toad: tip.toad);
    }
    return state;
  }

  /// The generation of this phrase whose key is [key], or null.
  static int? _generationOf(Uint8List seed, String key) {
    for (var j = 0; j < 256; j++) {
      if (KeyManager.keyAt(seed, j).publicKeyEncoded == key) return j;
    }
    return null;
  }

  /// The copy of the log the Identity Agent's public discovery record serves,
  /// verified; null when it cannot be read or does not verify.
  Future<LogCopy?> _discoveryCopy(String aid) async {
    try {
      final res = await _client.get(Uri.parse('$_agentBase/public/oobi/$aid'));
      if (res.statusCode != 200) return null;
      final j = jsonDecode(res.body) as Map<String, dynamic>;
      final raws = j['raw_events_b64'] as List? ?? const [];
      final sigs = j['cesr_signatures'] as List? ?? const [];
      if (raws.isEmpty || raws.length != sigs.length) return null;
      final st = await _km.verifyLog(aid, [
        for (var i = 0; i < raws.length; i++)
          SignedCopy('${raws[i]}', ['${sigs[i]}'])
      ]);
      return LogCopy('the discovery record', st.events);
    } catch (_) {
      return null;
    }
  }

  /// Combines verified [copies] of [aid]'s log as ADR-061 section 9 says,
  /// with [made], the establishment events this device made, as one more
  /// source.
  static CombinedLog combine(String aid, List<LogCopy> copies,
      {List<Place> made = const [], bool acceptTheCoreAlone = false}) {
    // Different establishment events at one place, anywhere.
    final at = <int, Map<String, String>>{};
    for (final c in copies) {
      for (final e in c.events) {
        if (e.establishment) (at[e.sn] ??= {})[c.source] = e.digest;
      }
    }
    for (final m in made) {
      (at[m.sn] ??= {})['this device'] = m.digest;
    }
    for (final e in at.entries) {
      if (e.value.values.toSet().length > 1) {
        throw TheLogHasTwoHistories(aid, e.key, e.value);
      }
    }

    // The newest establishment event enough of its own witnesses hold.
    final candidates = <int, LoggedEvent>{};
    for (final c in copies) {
      for (final e in c.events) {
        if (e.establishment) candidates[e.sn] = e;
      }
    }
    LoggedEvent? chosen;
    var corroborated = false;
    for (final sn in candidates.keys.toList()..sort((a, b) => b - a)) {
      final e = candidates[sn]!;
      final set = WitnessSet(e.witnesses, e.toad);
      final holding = {
        for (final c in copies)
          if (c.witness != null &&
              set.witnesses.contains(c.witness) &&
              c.events.length > sn &&
              c.events[sn].digest == e.digest)
            c.witness!
      };
      if (holding.length >= set.toEstablish) {
        chosen = e;
        corroborated = true;
        break;
      }
    }
    if (chosen == null && acceptTheCoreAlone) {
      for (final c in copies.where((c) => c.witness == null)) {
        final est = c.events.lastWhere((e) => e.establishment);
        if (chosen == null || est.sn > chosen.sn) chosen = est;
      }
    }
    if (chosen == null) {
      throw TheWitnessesDoNotSay(
          aid,
          copies.isEmpty
              ? 'no copy of the log could be read'
              : 'no establishment event is held by enough of its witnesses');
    }
    for (final m in made) {
      if (m.sn > chosen.sn) {
        throw TheCopiesAreBehindThisDevice(
            aid, m, (sn: chosen.sn, digest: chosen.digest));
      }
    }

    // The interactions after it that every copy reaching them agrees on.
    final agreeing = [
      for (final c in copies)
        if (c.events.length > chosen.sn &&
            c.events[chosen.sn].digest == chosen.digest)
          c
    ];
    final events = List<LoggedEvent>.from(
        agreeing.firstWhere((c) => true).events.sublist(0, chosen.sn + 1));
    // What this device made must be in that history, whatever stands at its
    // place: an interaction there would mean its establishment event was
    // replaced, which nothing may do.
    for (final m in made) {
      if (events[m.sn].digest != m.digest) {
        throw TheLogHasTwoHistories(aid, m.sn,
            {'this device': m.digest, 'the copies': events[m.sn].digest});
      }
    }
    for (var sn = chosen.sn + 1;; sn++) {
      final here = [
        for (final c in agreeing)
          if (c.events.length > sn) c.events[sn]
      ];
      if (here.isEmpty ||
          here.any((e) => e.establishment) ||
          here.map((e) => e.digest).toSet().length > 1) {
        break;
      }
      events.add(here.first);
    }
    return CombinedLog(chosen, events.last, events, corroborated);
  }
}

/// The log as the copies combine into it.
class CombinedLog {
  CombinedLog(this.establishment, this.tip, this.events, this.corroborated);
  final LoggedEvent establishment;
  final LoggedEvent tip;
  final List<LoggedEvent> events;
  final bool corroborated;
}
