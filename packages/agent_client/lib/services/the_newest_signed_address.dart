import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import 'the_owner_at_this_computer.dart';

/// Where an organisation's signed endpoint records come from (ADR-062).
///
/// Whoever serves a record is not trusted: [FindingAnAgentThatMoved] checks
/// every record against the key the organisation's own verified key log names
/// now, so a source can withhold a record but cannot make one up.
abstract class EndpointRecordSource {
  /// Every record the source holds for [aid], as it was signed. May be empty.
  Future<List<Map<String, dynamic>>> recordsFor(String aid);
}

/// Asks the organisation's witnesses, the public route
/// `GET /api/witness/endpoint/{aid}` that ADR-062 opens to anybody.
///
/// Every witness is asked and a failing one is skipped, so one witness that is
/// down, stale or hostile cannot decide the answer.
class WitnessEndpointRecords implements EndpointRecordSource {
  WitnessEndpointRecords({
    required this.witnesses,
    http.Client? client,
    this.timeout = const Duration(seconds: 8),
  })  : _client = ProvingThisComputer.over(client),
        _ownsClient = client == null;

  /// The witnesses' base addresses, from wherever the app learned them.
  final Future<List<String>> Function() witnesses;
  final http.Client _client;
  final bool _ownsClient;
  final Duration timeout;

  @override
  Future<List<Map<String, dynamic>>> recordsFor(String aid) async {
    final found = <Map<String, dynamic>>[];
    for (final base in await witnesses()) {
      try {
        final res = await _client
            .get(Uri.parse(
                '${base.replaceAll(RegExp(r'/+$'), '')}/api/witness/endpoint/'
                '${Uri.encodeComponent(aid)}'))
            .timeout(timeout);
        if (res.statusCode != 200) continue;
        final body = jsonDecode(res.body);
        final record = body is Map ? body['record'] : null;
        if (record is Map) found.add(Map<String, dynamic>.from(record));
      } catch (_) {
        // Withheld, down or unreadable: the next witness may answer.
      }
    }
    return found;
  }

  void dispose() {
    if (_ownsClient) _client.close();
  }
}

/// The newest signed record this app has accepted for each organisation, kept
/// so an older one is never accepted later, whoever offers it (ADR-062 §3).
abstract class NewestRecordHeld {
  Future<Map<String, dynamic>?> heldFor(String aid);
  Future<void> keep(Map<String, dynamic> record);
}

/// Kept on this computer, with the app's other settings.
class NewestRecordInPreferences implements NewestRecordHeld {
  static String _key(String aid) => 'newest_signed_endpoint_record/$aid';

  @override
  Future<Map<String, dynamic>?> heldFor(String aid) async {
    final prefs = await SharedPreferences.getInstance();
    final text = prefs.getString(_key(aid));
    if (text == null) return null;
    try {
      final v = jsonDecode(text);
      return v is Map ? Map<String, dynamic>.from(v) : null;
    } catch (_) {
      return null;
    }
  }

  @override
  Future<void> keep(Map<String, dynamic> record) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_key(record['aid'] as String), jsonEncode(record));
  }
}

/// The witnesses this app has been told an organisation uses, kept per
/// identifier. The app that founded or joined the organisation records them
/// ([rememberWitnessesOf]); the find-it-again check reads them.
String _witnessKey(String aid) => 'witness_bases/$aid';

Future<void> rememberWitnessesOf(String aid, List<String> bases) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setStringList(_witnessKey(aid), bases);
}

/// Reads the record source for one organisation from what was remembered.
class WitnessesRememberedFor implements EndpointRecordSource {
  WitnessesRememberedFor({this.client});
  final http.Client? client;

  @override
  Future<List<Map<String, dynamic>>> recordsFor(String aid) async {
    final prefs = await SharedPreferences.getInstance();
    final bases = prefs.getStringList(_witnessKey(aid)) ?? const <String>[];
    if (bases.isEmpty) return const [];
    final source =
        WitnessEndpointRecords(witnesses: () async => bases, client: client);
    try {
      return await source.recordsFor(aid);
    } finally {
      source.dispose();
    }
  }
}
