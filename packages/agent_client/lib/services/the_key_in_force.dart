import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import '../crypto/owner_signature.dart';
import 'key_math.dart';
import 'keri_service.dart';
import 'owner_signing_client.dart';
import 'signing_an_event.dart';
import 'the_stored_event_this_phrase_would_have_made.dart';
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
  /// [keyMath] is the core's key arithmetic, which an event left unsigned is
  /// checked with before it is signed late. Left out, [index] works and
  /// signing an event late refuses.
  TheKeyInForce(this._client, this._baseUrl,
      {TheEventsThisDeviceAskedFor? asked, KeyMath? keyMath})
      : _asked = asked ?? TheEventsThisDeviceAskedFor(),
        _keyMath = keyMath {
    if (_client is OwnerSigningClient) {
      throw ArgumentError.value(_client, 'client',
          'the key in force is read through a plain client; the owner-signing '
          'transport asks this which key to sign with, so it would recurse');
    }
  }

  final http.Client _client;
  final String _baseUrl;
  final TheEventsThisDeviceAskedFor _asked;
  final KeyMath? _keyMath;

  /// The digest a next-key commitment names for [keyQb64]: Blake3 over the
  /// key's qb64 text, as a validator recomputes it.
  static String commitmentTo(String keyQb64) => OwnerSignature.blake3QB64(utf8.encode(keyQb64));

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
        if (named != KeyManager.publicKeyAt(seed, current)) {
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
  ///  - the stored bytes are exactly the event this phrase would have produced
  ///    at that place (ExpectedEvent, through [signAndRecordEvent]): a founding
  ///    or rotation commits to the next key of this phrase alone, a rotation
  ///    changes no witness, and nothing carries an extra key, digest or anchor.
  ///
  /// A core that does not say which events are signed is left as it is.
  Future<KeyState> finishStrandedEvents(Uint8List seed) async {
    final checked = await _checkedLog(seed);
    final log = checked.log;
    final signed = log.signed;
    final scope = await _asked.scope();
    Map<String, dynamic>? establishment;
    for (var at = 0; at < log.events.length; at++) {
      final event = log.events[at];
      if (_establishing.contains(event['t'])) establishment = event;
      if (signed == null || signed[at]) continue;
      final asked = await _asked.whichAskedFor(scope, checked.aid, event, commitmentTo);
      if (asked == null) {
        throw AnEventThisDeviceDidNotAskFor(checked.aid, '${event['s']}', '${event['t']}');
      }
      final request = await _asked.theRequest(scope, asked);
      final wanted = (request?['asked'] as Map?)?['anchors'];
      await _checkAndSign(seed, checked, at,
          t: '${request?['t']}',
          // The place and digest this device recorded, not the bytes'.
          sn: int.parse('${request?['s'] ?? request?['expected']}', radix: 16),
          digest: request?['d'] as String?,
          ixnAnchors: wanted is List ? List<Object?>.from(wanted) : null);
      await _asked.forgetId(scope, asked);
    }
    if (signed != null) await _asked.forgetSettled(scope, checked.aid, log.events, signed);
    return KeyState(checked.aid, checked.keyAt.last, establishment!, log.events.length,
        '${log.events.last['d'] ?? ''}');
  }

  /// The checks every event this device signs late must pass, then the
  /// signature. The stored bytes are parsed with the core's parser and must be
  /// exactly the event this phrase would have produced at that place, the same
  /// [ExpectedEvent] checks a new event gets (in [signAndRecordEvent], which
  /// nothing signs late without). An event that is not is not signed: it comes
  /// back as an [AStoredEventIsNotTheOneExpected] carrying what was stored and
  /// what was expected, for the person to see.
  Future<void> _checkAndSign(Uint8List seed, _Checked checked, int at,
      {required String t, required int sn, required String? digest, List<Object?>? ixnAnchors}) async {
    final km = _keyMath;
    if (km == null) {
      throw StateError('this app has not given the client the core\'s key '
          'arithmetic (KeyMath), so it cannot check an event before signing '
          'it, and signs nothing');
    }
    final log = checked.log;
    final event = log.events[at];
    Future<ParsedEvent?> parsed(int i) async => i >= 0 && i < log.rawEventsB64.length && log.rawEventsB64[i].isNotEmpty
        ? await parseTheStoredEvent(km, log.rawEventsB64[i])
        : null;
    final raw = at < log.rawEventsB64.length ? log.rawEventsB64[at] : '';
    final stored = await parsed(at);
    if (stored == null) {
      throw Exception('event ${event['s']} of ${checked.aid} was stored without the bytes it was '
          'made from, so it is not signed');
    }
    var lastEstablishment = at - 1;
    while (lastEstablishment >= 0 && !_establishing.contains(log.events[lastEstablishment]['t'])) {
      lastEstablishment--;
    }
    final expected = await theStoredEventThisPhraseWouldHaveMade(km, seed,
        t: t,
        aid: checked.aid,
        sn: sn,
        digest: digest,
        stored: stored,
        before: await parsed(at - 1),
        lastEstablishment: await parsed(lastEstablishment),
        generation: checked.keyAt[at],
        ixnAnchors: ixnAnchors);
    final signingSeed = KeyManager.signingSeed(seed, index: checked.keyAt[at]);
    try {
      await signAndRecordEvent(_client, _baseUrl,
          aid: checked.aid,
          sequenceNumber: sn,
          rawBytesB64: raw,
          signingSeed: signingSeed,
          what: 'event ${event['s']} of this identity, left unsigned,',
          km: km,
          expected: expected);
    } on EventSignatureRefused catch (e) {
      if (e.statusCode == 404 || e.statusCode == 409) {
        throw StrandedEventCannotBeFinished(checked.aid, '${event['s']}', e);
      }
      rethrow;
    } finally {
      signingSeed.fillRange(0, signingSeed.length, 0);
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
    for (var at = 0; at < log.events.length; at++) {
      final event = log.events[at];
      if (event['s'] != sequenceNumber || event['d'] != digest) continue;
      if (log.signed == null || log.signed![at]) {
        throw Exception('event $sequenceNumber of ${checked.aid} is not waiting for a signature');
      }
      // The person has been shown the event as stored, so its seals are what
      // they approved; everything else is checked as for any other.
      final seals = event['a'];
      await _checkAndSign(seed, checked, at,
          t: '${event['t']}',
          sn: int.parse(sequenceNumber, radix: 16),
          digest: digest,
          ixnAnchors: seals is List ? List<Object?>.from(seals) : const []);
      return;
    }
    throw Exception('the key log of ${checked.aid} has no event $sequenceNumber with digest $digest');
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
  KeyState(this.aid, this.index, this.establishment, this.nextSequenceNumber, this.tipDigest);

  final String aid;

  /// The index of the key in force.
  final int index;

  /// The last establishment event, which names the key in force.
  final Map<String, dynamic> establishment;

  /// The sequence number the next event will have: the tip plus one.
  final int nextSequenceNumber;

  /// The digest of the tip, which the next event follows.
  final String tipDigest;
}
