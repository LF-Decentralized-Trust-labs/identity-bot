import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import 'keri_service.dart';
import 'signing_an_event.dart';
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
  TheKeyInForce(this._client, this._baseUrl);

  final http.Client _client;
  final String _baseUrl;

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

  /// The index of the key in force, for the identity whose 64-byte BIP39 seed
  /// is [seed].
  ///
  /// Each establishment event must name key j of this phrase, the j-th from
  /// founding. If one does not, this throws rather than signing: a signature
  /// by any other key is one no counterparty can verify, and carrying on would
  /// only move the failure to them.
  ///
  /// It also finishes any establishment event the core says is unsigned,
  /// signing it with the key it names and recording the signature. An event is
  /// added first and signed second, so a device that lost its connection
  /// between the two leaves the identity's log refused by everybody from that
  /// event on; this is the second step, done late. A core that does not say
  /// which events are signed is left as it is.
  Future<int> index(Uint8List seed) async {
    final aid = await ownIdentifier();
    final log = await keyLog(aid);
    final establishing = <int>[
      for (var i = 0; i < log.events.length; i++)
        if (const {'icp', 'dip', 'rot', 'drt'}.contains(log.events[i]['t'])) i,
    ];
    if (establishing.isEmpty) {
      throw Exception('the key log of $aid has no founding event, so there is no '
          'key in force to sign with');
    }
    for (var j = 0; j < establishing.length; j++) {
      final event = log.events[establishing[j]];
      final keys = event['k'];
      final named = keys is List && keys.isNotEmpty ? keys.first : null;
      if (named != KeyManager.keyAt(seed, j).publicKeyEncoded) {
        throw Exception('the key log of $aid names $named in its establishment event '
            '${event['s']}, which is not key $j of this recovery phrase, so nothing '
            'signed here would verify against it');
      }
    }
    final signed = log.signed;
    if (signed != null) {
      for (var j = 0; j < establishing.length; j++) {
        final at = establishing[j];
        if (signed[at]) continue;
        final raw = at < log.rawEventsB64.length ? log.rawEventsB64[at] : '';
        await signAndRecordEvent(_client, _baseUrl,
            aid: aid,
            sequenceNumber: int.tryParse('${log.events[at]['s']}', radix: 16),
            rawBytesB64: raw,
            signingSeed: KeyManager.signingSeed(seed, index: j),
            what: 'establishment event ${log.events[at]['s']} of this identity, left unsigned,');
      }
    }
    return establishing.length - 1;
  }
}
