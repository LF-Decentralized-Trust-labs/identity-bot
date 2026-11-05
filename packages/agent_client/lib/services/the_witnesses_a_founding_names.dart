import 'dart:convert';

import 'package:http/http.dart' as http;

import 'key_math.dart';
import 'the_key_events_this_device_makes.dart' show KeyEventRefused;
import 'the_witnesses_of_this_devices_events.dart';

/// The witnesses a founding this device signs names, and where they are.
class WitnessesChosen {
  WitnessesChosen(this.witnesses, this.toad, this.addresses, this.unwitnessed);

  /// The witnesses that answered, in the order the core proposed them.
  final List<String> witnesses;

  /// How many of them must receipt the founding: the core's threshold, lowered
  /// to the witnesses that remain.
  final int toad;

  /// Where each is reached, to be kept in this device's record.
  final Map<String, Uri> addresses;

  /// Why the founding names no witness; null where it names some.
  final String? unwitnessed;
}

/// Who a founding names as its witnesses (ADR-061 sections 3 and 9).
///
/// The core proposes the witnesses it would have chosen, with where each is
/// reached. A witness is named only once this device has heard it answer in
/// its own name, by its signed answer to a fresh nonce: a witness that is not
/// there, or that answers with another witness's key, is left out. The
/// founding is permanent, so what it names is never taken on the core's word.
class TheWitnessesAFoundingNames {
  TheWitnessesAFoundingNames(this._client, this._baseUrl, this._km);

  final http.Client _client;
  final String _baseUrl;
  final KeyMath _km;

  /// Asks the core for its proposal and confirms each witness in it. A core
  /// that cannot be asked at all throws, rather than have the identity
  /// founded unwitnessed for good because a request failed once.
  Future<WitnessesChosen> choose() async {
    final res = await _client
        .get(Uri.parse('$_baseUrl/api/events/witnesses-for-a-founding'));
    if (res.statusCode == 404) {
      return _none('this core does not propose witnesses');
    }
    if (res.statusCode < 200 || res.statusCode > 299) {
      throw KeyEventRefused('the witnesses of the founding', res.statusCode,
          '', res.body);
    }
    final body = jsonDecode(res.body);
    final proposed = <String, Uri>{};
    final listed = body is Map && body['witnesses'] is List
        ? body['witnesses'] as List
        : const [];
    for (final w in listed) {
      if (w is! Map) continue;
      final address = Uri.tryParse('${w['address']}');
      if (address == null ||
          !(address.scheme == 'http' || address.scheme == 'https') ||
          address.host.isEmpty) {
        continue;
      }
      final key = '${w['aid']}';
      // Only the canonical spelling of a witness, each once.
      if (WitnessSet([key], 0).witnesses.isEmpty) continue;
      proposed.putIfAbsent(
          key,
          () => address.path.endsWith('/')
              ? address
              : address.replace(path: '${address.path}/'));
    }
    if (proposed.isEmpty) return _none('the core proposed no witnesses');

    final witnesses = TheWitnessesOfThisDevicesEvents(
        _client, _km, KnownWitnesses(proposed));
    final answered = <String>{};
    await Future.wait([
      for (final w in proposed.keys)
        witnesses.answersInItsOwnName(w).then((ok) {
          if (ok) answered.add(w);
        })
    ]);
    final chosen = [
      for (final w in proposed.keys)
        if (answered.contains(w)) w
    ];
    if (chosen.isEmpty) {
      return _none('none of the ${proposed.length} witnesses the core proposed '
          'answered in its own name');
    }
    final asked = body is Map ? body['toad'] : null;
    final toad = (asked is int ? asked : 1).clamp(1, chosen.length).toInt();
    return WitnessesChosen(chosen, toad,
        {for (final w in chosen) w: proposed[w]!}, null);
  }

  static WitnessesChosen _none(String why) =>
      WitnessesChosen(const [], 0, const {}, why);
}
