import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../crypto/endpoint_record.dart';
import 'asking_to_act_for_an_identity.dart';
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

/// A source that can also be told where to ask: addresses learned from the
/// organisation's own verified key log through this computer's core.
abstract class EndpointRecordSourceWithLeads implements EndpointRecordSource {
  Future<List<Map<String, dynamic>>> recordsForWithLeads(
      String aid, List<String> leads);
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

/// Keeps the witnesses a verified key log named, at the addresses this
/// computer's core holds for them, alongside any already remembered for [aid].
/// Called when this computer joins an organisation, the one moment its key log
/// has just been verified and the addresses are in hand. Nothing is removed and
/// nothing without an address is kept.
Future<void> rememberWitnessesFoundIn(
    String aid, List<NamedWitness> found) async {
  final prefs = await SharedPreferences.getInstance();
  final kept = <String>[
    ...?prefs.getStringList(_witnessKey(aid)),
  ];
  for (final w in found) {
    final origin = canonicalOriginOf(w.url.trim());
    if (origin != null && !kept.contains(origin)) kept.add(origin);
  }
  await prefs.setStringList(_witnessKey(aid), kept);
}

/// Reads the record source for one organisation from every lead this computer
/// has for where its witnesses are. The safety is not in where an address came
/// from but in the verification of every record a witness returns, so every
/// lead is used and one that is down or answers with an invalid record is
/// skipped:
///
///  1. the witnesses named in the organisation's own key log, which this
///     computer's core verified, at the address the core holds for each
///     (`leads`, from [AskingToActForAnIdentity.confirmThisIsReallyAndLearnItsWitnesses]);
///  2. the same, read from the verified log the core already holds for the
///     organisation ([coreKnows], [AskingToActForAnIdentity.witnessesTheCoreKnowsFor]);
///  3. the addresses the organisation handed over when this computer founded
///     or joined it ([rememberWitnessesOf]).
class WitnessesRememberedFor implements EndpointRecordSourceWithLeads {
  WitnessesRememberedFor({this.client, this.coreKnows});
  final http.Client? client;

  /// Addresses this computer's own core holds for the witnesses of [aid].
  final Future<List<String>> Function(String aid)? coreKnows;

  @override
  Future<List<Map<String, dynamic>>> recordsFor(String aid) =>
      recordsForWithLeads(aid, const []);

  @override
  Future<List<Map<String, dynamic>>> recordsForWithLeads(
      String aid, List<String> leads) async {
    final prefs = await SharedPreferences.getInstance();
    var fromCore = const <String>[];
    try {
      fromCore = await coreKnows?.call(aid) ?? const <String>[];
    } catch (_) {
      // A core that cannot be asked is one lead fewer, not a failure.
    }
    final seen = <String>{};
    final bases = <String>[
      for (final b in [
        ...leads,
        ...fromCore,
        ...(prefs.getStringList(_witnessKey(aid)) ?? const <String>[]),
      ])
        if (canonicalOriginOf(b.trim()) case final o? when seen.add(o)) o,
    ];
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
