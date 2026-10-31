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

  /// Refuses an establishment event this device would sign unless it commits
  /// to exactly the next key of this phrase, and, for a rotation, changes no
  /// witness and keeps the threshold [priorBt] the identity had. [j] is the
  /// event's place among the establishment events: it reveals key j and must
  /// commit to key j + 1. A core choosing what an event commits to would
  /// otherwise choose who can rotate the identity next.
  static void requireTheEstablishmentIsThisDevices(
      Map<String, dynamic> event, Uint8List seed, int j, {Object? priorBt}) {
    String? why;
    final next = commitmentTo(KeyManager.keyAt(seed, j + 1).publicKeyEncoded);
    final n = event['n'];
    if (n is! List || n.length != 1 || n.first != next) {
      why = 'it commits to $n, not to the next key of this recovery phrase ($next)';
    } else if (event['t'] == 'rot') {
      bool empty(Object? v) => v == null || (v is List && v.isEmpty);
      if (!empty(event['br']) || !empty(event['ba'])) {
        why = 'it changes the witnesses, which this device did not ask for';
      } else if (priorBt != null && event['bt'] != priorBt) {
        why = 'it changes the witness threshold from $priorBt to ${event['bt']}, which this device did not ask for';
      }
    }
    if (why != null) {
      throw Exception('event ${event['s']} is not the ${event['t'] == 'rot' ? 'rotation' : 'founding'} '
          'this device asked for, so it is not signed: $why');
    }
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
  Future<({String aid, KeyEventLog log, List<int> keyAt})> _checkedLog(Uint8List seed) async {
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
    return (aid: aid, log: log, keyAt: keyAt);
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
  Future<({String aid, int index, Map<String, dynamic> establishment})> finishStrandedEvents(
      Uint8List seed) async {
    final checked = await _checkedLog(seed);
    final log = checked.log;
    final signed = log.signed;
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
      final asked = await _asked.whichAskedFor(checked.aid, event, commitmentTo);
      if (asked == null) {
        throw AnEventThisDeviceDidNotAskFor(checked.aid, '${event['s']}', '${event['t']}');
      }
      final raw = at < log.rawEventsB64.length ? log.rawEventsB64[at] : '';
      _requireTheBytesAreTheEvent(checked.aid, event, raw);
      if (establishing) requireTheEstablishmentIsThisDevices(event, seed, j, priorBt: bt);
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
      await _asked.forget(asked);
    }
    if (signed != null) {
      await _asked.forgetSigned(checked.aid, [
        for (var at = 0; at < log.events.length; at++)
          if (signed[at]) log.events[at],
      ]);
    }
    return (aid: checked.aid, index: checked.keyAt.last, establishment: establishment!);
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
