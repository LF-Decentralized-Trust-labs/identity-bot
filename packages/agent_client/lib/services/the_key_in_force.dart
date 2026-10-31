import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import '../crypto/owner_signature.dart';
import 'keri_service.dart';
import 'owner_signing_client.dart';
import 'signing_an_event.dart';
import 'the_events_this_device_asked_for.dart';
import 'the_key_is_not_held_by_the_core.dart';

/// Which of an identity's keys is in force, read from its key log at the core
/// that keeps it.
///
/// Key n is [KeyManager.keyAt] at index n. Founding puts key 0 in force and
/// every rotation moves one along, so the key in force is the number of
/// establishment events after the first. It is read from the log every time
/// rather than remembered: the log is what a counterparty checks a signature
/// against, it survives a restart because the core keeps it, and a count kept
/// beside it could disagree with it and nothing would notice.
///
/// Everything that signs as the identity asks this: the KERI service for its
/// events and payloads, and the owner-signing transport for requests.
class TheKeyInForce {
  /// [client] must be a plain client, never an [OwnerSigningClient]: the
  /// owner-signing transport asks this which key to sign with, so reading the
  /// key log through it would ask again, without end. Give it the transport's
  /// inner client.
  TheKeyInForce(this._client, this._baseUrl, {TheEventsThisDeviceAskedFor? asked})
      : _asked = asked ?? TheEventsThisDeviceAskedFor() {
    if (_client is OwnerSigningClient) {
      throw ArgumentError.value(_client, 'client',
          'the key in force is read through a plain client; the owner-signing '
          'transport asks this which key to sign with, so it would recurse');
    }
  }

  final http.Client _client;
  final String _baseUrl;
  final TheEventsThisDeviceAskedFor _asked;

  /// The digest a next-key commitment names for [keyQb64]: Blake3 over the
  /// key's qb64 text, as a validator recomputes it.
  static String commitmentTo(String keyQb64) => OwnerSignature.blake3QB64(utf8.encode(keyQb64));

  /// Refuses a rotation this device would sign unless it is exactly the one it
  /// asks for: it reveals key [j] of this phrase (checked by the caller), commits
  /// to exactly key j + 1 with one key and a threshold of one ("kt" and "nt"
  /// "1"), anchors nothing, changes no witness and keeps the witness threshold
  /// [priorBt] the identity had. A core choosing what a rotation commits to
  /// would otherwise choose who can rotate the identity next.
  static void requireTheRotationIsThisDevices(
      Map<String, dynamic> event, Uint8List seed, int j, {Object? priorBt}) {
    bool empty(Object? v) => v == null || (v is List && v.isEmpty);
    final next = commitmentTo(KeyManager.keyAt(seed, j + 1).publicKeyEncoded);
    final n = event['n'];
    String? why;
    if (n is! List || n.length != 1 || n.first != next) {
      why = 'it commits to $n, not to the next key of this recovery phrase ($next)';
    } else if (event['kt'] != '1' || event['nt'] != '1') {
      why = 'its signing thresholds are ${event['kt']} and ${event['nt']}, not 1 and 1';
    } else if (!empty(event['a'])) {
      why = 'it anchors ${event['a']}, which this device did not ask for';
    } else if (!empty(event['br']) || !empty(event['ba'])) {
      why = 'it changes the witnesses, which this device did not ask for';
    } else if (priorBt != null && event['bt'] != priorBt) {
      why = 'it changes the witness threshold from $priorBt to ${event['bt']}, which this device did not ask for';
    }
    if (why != null) {
      throw Exception('event ${event['s']} is not the rotation this device asked for, so it is not signed: $why');
    }
  }

  /// Refuses the founding event of an identity this device would sign unless
  /// it is the one it asks for:
  ///  - a founding ("t" icp, sequence 0) of the identifier [aid], when the
  ///    device knows it;
  ///  - naming one key, [key], with a threshold of one ("kt" "1");
  ///  - committing first to [next], with at most one more commitment, and a
  ///    threshold of one ("nt" "1");
  ///  - with no configuration traits ("c" empty);
  ///  - anchoring nothing, or exactly one anchor of the identity's messaging
  ///    keys (an IA-HYBRID-1 keyset: "ia", "ka" and "sa" and nothing else),
  ///    after an owner seal naming [ownerAid] when the device asked for one.
  /// The witnesses ("b", "bt") are the core's choice at founding.
  ///
  /// THE LIMIT. The one further commitment, to a post-quantum key, and the
  /// messaging keys are what the core adds of its own, derived from the root
  /// seed it holds, and the device cannot recompute either. Where that seed is
  /// this phrase's they are the identity's own keys. A core holding a
  /// different root seed can still put its own post-quantum digest and
  /// messaging-keyset anchor into a founding this device signs, and with a
  /// next threshold of one that post-quantum key alone could rotate the
  /// identity. Closing it needs the core to prove which seed it holds, which
  /// is a protocol step of its own. What is refused here is everything else:
  /// another first commitment, more commitments, other anchors, traits and
  /// thresholds.
  static void requireTheFoundingIsThisDevices(Map<String, dynamic> event,
      {required String key, required String next, String? aid, String? ownerAid}) {
    bool same(Object? a, Object? b) => jsonEncode(a) == jsonEncode(b);
    String? why;
    final n = event['n'];
    final want = commitmentTo(next);
    if (event['t'] != 'icp' || event['s'] != '0') {
      why = 'it is not a founding event';
    } else if (aid != null && event['i'] != aid) {
      why = 'it founds ${event['i']}, not $aid';
    } else if (!same(event['k'], [key])) {
      why = 'it names ${event['k']}, not this device\'s key $key';
    } else if (event['kt'] != '1' || event['nt'] != '1') {
      why = 'its signing thresholds are ${event['kt']} and ${event['nt']}, not 1 and 1';
    } else if (!same(event['c'] ?? const [], const [])) {
      why = 'it sets configuration traits ${event['c']} this device did not ask for';
    } else if (n is! List || n.isEmpty || n.length > 2 || n.first != want) {
      why = 'it commits to $n, not to this device\'s next key ($want) with at most one more';
    } else {
      why = _foundingAnchorProblem(event['a'], ownerAid: ownerAid);
    }
    if (why != null) {
      throw Exception('the founding event is not the one this device asked for, so it is not signed: $why');
    }
  }

  static String? _foundingAnchorProblem(Object? a, {String? ownerAid}) {
    final anchors = a is List ? List<Object?>.from(a) : <Object?>[];
    if (a != null && a is! List) return 'its anchors are not a list';
    if (ownerAid != null) {
      final seal = {'i': ownerAid, 's': '0', 'd': ownerAid};
      if (anchors.isEmpty || jsonEncode(anchors.first) != jsonEncode(seal)) {
        return 'it does not name the owner this device asked for ($ownerAid) first';
      }
      anchors.removeAt(0);
    }
    if (anchors.isEmpty) return null;
    final keyset = anchors.first;
    final isKeyset = keyset is Map &&
        keyset['ia'] == 'IA-HYBRID-1' &&
        keyset['ka'] is List &&
        keyset['sa'] is List &&
        keyset.keys.length == 3;
    if (anchors.length > 1 || !isKeyset) return 'it anchors $anchors, which this device did not ask for';
    return null;
  }

  /// The identifier of the identity the core holds, which is the name its key
  /// log is kept under. The recovery phrase in secure storage is that
  /// identity's, so it is the log every key derived from the phrase answers to.
  Future<String> ownIdentifier() async {
    final res = await _client.get(Uri.parse('$_baseUrl/api/identity'));
    if (res.statusCode != 200) {
      refusedByTheCore(res, 'Could not read which identity this core holds');
    }
    final aid = (jsonDecode(res.body) as Map<String, dynamic>)['aid'];
    if (aid is! String || aid.isEmpty) {
      throw Exception('this core holds no identity, so there is no key in force to sign with');
    }
    return aid;
  }

  /// The key event log of the identity held under [name].
  Future<KeyEventLog> keyLog(String name) async {
    final res = await _client.get(
      Uri.parse('$_baseUrl/api/kel?name=${Uri.encodeQueryComponent(name)}'),
    );
    if (res.statusCode != 200) {
      refusedByTheCore(res, 'Could not read the key log');
    }
    final json = jsonDecode(res.body);
    if (json is! Map<String, dynamic>) {
      throw Exception('the core answered with something that is not a key log');
    }
    return KeyEventLog.fromJson(json);
  }

  /// The identity's own key log, checked to be its own and to name, in each
  /// establishment event j, key j of the phrase whose BIP39 seed is [seed].
  /// Returns the log and, for each event, the index of the key in force at it.
  Future<_Checked> _checkedLog(Uint8List seed) async {
    final aid = await ownIdentifier();
    final log = await keyLog(aid);
    if (log.aid != aid) {
      throw Exception('the core answered with the key log of ${log.aid} when asked for $aid');
    }
    final keyAt = <int>[];
    var current = -1;
    for (final event in log.events) {
      if (_establishing.contains(event['t'])) {
        current++;
        final keys = event['k'];
        final named = keys is List && keys.isNotEmpty ? keys.first : null;
        if (named != KeyManager.keyAt(seed, current).publicKeyEncoded) {
          throw Exception('the key log of $aid names $named in its establishment event '
              '${event['s']}, which is not key $current of this recovery phrase, so nothing '
              'signed here would verify against it');
        }
      }
      keyAt.add(current);
    }
    if (current < 0) {
      throw Exception('the key log of $aid has no founding event, so there is no '
          'key in force to sign with');
    }
    return _Checked(aid, log, keyAt);
  }

  static const _establishing = {'icp', 'dip', 'rot', 'drt'};

  /// The index of the key in force, for the identity whose 64-byte BIP39 seed
  /// is [seed]. Throws rather than answering if the log names a key this phrase
  /// does not hold: a signature by any other key is one no counterparty can
  /// verify, and carrying on would only move the failure to them.
  ///
  /// It finishes nothing. The owner-signing transport calls this alone: a
  /// request it signs adds no event to the log, so there is nothing for it to
  /// finish, and finishing would mean signing and posting events from inside
  /// a transport that is only meant to sign the request in hand.
  Future<int> index(Uint8List seed) async {
    final checked = await _checkedLog(seed);
    return checked.keyAt.last;
  }

  /// Signs and records the events of the identity's log that the core says are
  /// unsigned and that this device asked for, then returns the key in force.
  /// A founding or rotation is signed with the key it names, an interaction
  /// with the key in force at it.
  ///
  /// An event is added first and signed second, so a device that lost its
  /// connection between the two leaves the log refused by everybody from that
  /// event on; this is the second step, done late. Call it before making a
  /// signature, instead of [index]: it reads the log once for both.
  ///
  /// Nothing is signed unless all of these hold, because the core supplies
  /// both the log and the bytes:
  ///  - this device asked for the event (TheEventsThisDeviceAskedFor). Any
  ///    other unsigned event is refused, never signed: a core appending one of
  ///    its own and marking it unsigned would otherwise have it signed here;
  ///  - the bytes are the event the log lists at that place: this identity's,
  ///    with the same type, sequence number, digest and keys;
  ///  - a founding or rotation commits to exactly the next key of this phrase,
  ///    and a rotation changes no witness
  ///    ([requireTheEstablishmentIsThisDevices]).
  ///
  /// A core that does not say which events are signed is left as it is.
  Future<KeyState> finishStrandedEvents(Uint8List seed) async {
    final checked = await _checkedLog(seed);
    final log = checked.log;
    final signed = log.signed;
    final scope = await _asked.scope();
    Map<String, dynamic>? establishment;
    Object? priorBt;
    var j = -1;
    for (var at = 0; at < log.events.length; at++) {
      final event = log.events[at];
      final establishing = _establishing.contains(event['t']);
      final bt = priorBt;
      if (establishing) {
        j++;
        establishment = event;
        priorBt = event['bt'];
      }
      if (signed == null || signed[at]) continue;
      final asked = await _asked.whichAskedFor(scope, checked.aid, event, commitmentTo);
      if (asked == null) {
        throw AnEventThisDeviceDidNotAskFor(checked.aid, '${event['s']}', '${event['t']}');
      }
      await _checkAndSign(seed, checked, at, j, priorBt: bt);
      await _asked.forgetId(scope, asked);
    }
    if (signed != null) await _asked.forgetSettled(scope, checked.aid, log.events, signed);
    return KeyState(checked.aid, checked.keyAt.last, establishment!, log.events.length);
  }

  /// The checks every event this device signs late must pass, then the
  /// signature: the bytes are the event listed, a founding or rotation is the
  /// one this device would ask for, and the key is the one in force at it.
  Future<void> _checkAndSign(Uint8List seed, _Checked checked, int at, int j, {Object? priorBt}) async {
    final log = checked.log;
    final event = log.events[at];
    final raw = at < log.rawEventsB64.length ? log.rawEventsB64[at] : '';
    _requireTheBytesAreTheEvent(checked.aid, event, raw);
    if (event['t'] == 'rot') requireTheRotationIsThisDevices(event, seed, j, priorBt: priorBt);
    if (event['t'] == 'icp') {
      requireTheFoundingIsThisDevices(event,
          key: KeyManager.keyAt(seed, 0).publicKeyEncoded,
          next: KeyManager.keyAt(seed, 1).publicKeyEncoded,
          aid: checked.aid);
    }
    if (event['t'] != 'rot' && event['t'] != 'icp' && event['t'] != 'ixn') {
      throw Exception('event ${event['s']} is a ${event['t']}, which this device does not sign late');
    }
    try {
      await signAndRecordEvent(_client, _baseUrl,
          aid: checked.aid,
          sequenceNumber: int.tryParse('${event['s']}', radix: 16),
          rawBytesB64: raw,
          signingSeed: KeyManager.signingSeed(seed, index: checked.keyAt[at]),
          what: 'event ${event['s']} of this identity, left unsigned,');
    } on EventSignatureRefused catch (e) {
      if (e.statusCode == 404 || e.statusCode == 409) {
        throw StrandedEventCannotBeFinished(checked.aid, '${event['s']}', e);
      }
      rethrow;
    }
  }

  /// The unsigned events of the identity's log this device did not ask for,
  /// for the app to show the person whose identity it is.
  ///
  /// While any is there the identity is locked: [finishStrandedEvents] refuses
  /// to sign anything, because signing past an event nobody here asked for
  /// would build on it. It stays locked until the person approves one with
  /// [signApprovedEvent], or it is otherwise explained and removed.
  Future<List<Map<String, dynamic>>> eventsAwaitingApproval(Uint8List seed) async {
    final checked = await _checkedLog(seed);
    final signed = checked.log.signed;
    if (signed == null) return const [];
    final scope = await _asked.scope();
    final out = <Map<String, dynamic>>[];
    for (var at = 0; at < checked.log.events.length; at++) {
      if (signed[at]) continue;
      final event = checked.log.events[at];
      if (await _asked.whichAskedFor(scope, checked.aid, event, commitmentTo) == null) out.add(event);
    }
    return out;
  }

  /// Signs the unsigned event at [sequenceNumber] with digest [digest], which
  /// this device did not ask for, because the person whose identity it is has
  /// looked at it and approved it. Call it only from that approval.
  ///
  /// The approval does not lift any other check: the bytes must be the event,
  /// and a founding or rotation must still be exactly the one this device
  /// would ask for, committing to its own next key. What it permits is an
  /// event this device has no record of asking for: one made on another of
  /// the person's devices, say, or an interaction they recognise.
  Future<void> signApprovedEvent(Uint8List seed, {required String sequenceNumber, required String digest}) async {
    final checked = await _checkedLog(seed);
    final log = checked.log;
    var j = -1;
    Object? priorBt;
    for (var at = 0; at < log.events.length; at++) {
      final event = log.events[at];
      final bt = priorBt;
      if (_establishing.contains(event['t'])) {
        j++;
        priorBt = event['bt'];
      }
      if (event['s'] != sequenceNumber || event['d'] != digest) continue;
      if (log.signed == null || log.signed![at]) {
        throw Exception('event $sequenceNumber of ${checked.aid} is not waiting for a signature');
      }
      await _checkAndSign(seed, checked, at, j, priorBt: bt);
      return;
    }
    throw Exception('the key log of ${checked.aid} has no event $sequenceNumber with digest $digest');
  }


  static void _requireTheBytesAreTheEvent(String aid, Map<String, dynamic> event, String rawB64) {
    Object? parsed;
    try {
      parsed = jsonDecode(utf8.decode(base64Decode(rawB64)));
    } catch (_) {
      parsed = null;
    }
    bool same(Object? a, Object? b) => jsonEncode(a) == jsonEncode(b);
    if (parsed is! Map ||
        parsed['i'] != aid ||
        parsed['t'] != event['t'] ||
        parsed['s'] != event['s'] ||
        parsed['d'] != event['d'] ||
        !same(parsed['k'], event['k'])) {
      throw Exception('the bytes the core gave for event ${event['s']} of $aid are not that '
          'event, so they are not signed');
    }
  }
}

/// An event of the identity's log is unsigned and this device never asked for
/// it. It is not signed: the core supplies the log, so an event it appended on
/// its own and marked unsigned would otherwise be signed by this device, and a
/// rotation committing to somebody else's key would hand them the identity.
/// Nothing more is signed until the event is explained.
class AnEventThisDeviceDidNotAskFor implements Exception {
  AnEventThisDeviceDidNotAskFor(this.aid, this.sequenceNumber, this.type);

  final String aid;
  final String sequenceNumber;
  final String type;

  @override
  String toString() => 'event $sequenceNumber ($type) of $aid is unsigned, and this device did not ask '
      'for it, so it will not sign it. Something other than this device added it to the '
      "identity's key log; until it is explained, nothing more is signed.";
}

/// An event of the identity's log is unsigned, and the core would not record
/// a signature over it: it does not hold the event (404) or will not take a
/// signature for it (409). Nothing signed after it would be accepted by a
/// counterparty, so signing stops here until the core's record of the event
/// is put right.
class StrandedEventCannotBeFinished implements Exception {
  StrandedEventCannotBeFinished(this.aid, this.sequenceNumber, this.refusal);

  final String aid;
  final String sequenceNumber;
  final EventSignatureRefused refusal;

  @override
  String toString() => 'event $sequenceNumber of $aid is unsigned and the core would not record a '
      'signature over it (${refusal.statusCode}: ${refusal.body}). Every counterparty refuses the '
      "identity's key log from that event on, so nothing more is signed until the core's record "
      'of the event is repaired.';
}

/// The identity's log as read and checked against this phrase.
class _Checked {
  _Checked(this.aid, this.log, this.keyAt);
  final String aid;
  final KeyEventLog log;

  /// For each event, the index of the key in force at it.
  final List<int> keyAt;
}

/// Where the identity's keys stand after any stranded event is finished.
class KeyState {
  KeyState(this.aid, this.index, this.establishment, this.nextSequenceNumber);

  final String aid;

  /// The index of the key in force.
  final int index;

  /// The last establishment event, which names the key in force.
  final Map<String, dynamic> establishment;

  /// The sequence number the next event will have: the tip plus one.
  final int nextSequenceNumber;
}
