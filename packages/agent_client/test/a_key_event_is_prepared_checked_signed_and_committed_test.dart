import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/the_core.dart';

/// A client whose next commit reaches the core and whose answer is lost, as
/// when the connection drops after the core has the request.
class _LosesOneCommitAnswer extends http.BaseClient {
  _LosesOneCommitAnswer(this._inner);
  final http.Client _inner;
  bool lose = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    // The secret an app hands the core it starts, as the app's client sends it.
    request.headers['X-Local-Owner-Secret'] = ownerSecret;
    final res = await _inner.send(request);
    if (lose && request.url.path == '/api/events/commit') {
      lose = false;
      await res.stream.drain<void>();
      throw http.ClientException(
          'the connection dropped before the answer arrived', request.url);
    }
    return res;
  }
}

const ownerSecret = 'a-secret-only-this-test-and-its-core-know';

void main() {
  late Process core;
  late String base;
  late KeyMath km;
  final mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  final Uint8List seed = Bip39.mnemonicToSeed(mnemonic.split(' '));

  setUpAll(() async {
    // A development build: it founds an identity on a machine that cannot
    // attest, as a production build rightly refuses to.
    final bin = await buildTheCore('prepare-commit-core', dev: true);
    km = await keyMathOf(bin);
    final port = 20000 + Random().nextInt(20000);
    base = 'http://127.0.0.1:$port';
    final data = await Directory('${File(bin).parent.path}/data').create();
    core = await Process.start(bin, [], environment: {
      ...Platform.environment,
      'PORT': '$port',
      'HOST': '127.0.0.1',
      'AGENT_DATA_DIR': data.path,
      'IDENTITY_AGENT_LOCAL_OWNER_SECRET': ownerSecret,
    });
    core.stdout.drain<void>();
    core.stderr.drain<void>();
    for (var i = 0; i < 100; i++) {
      try {
        if ((await http.get(Uri.parse('$base/api/health'))).statusCode == 200)
          return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('the core did not start');
  });

  tearDownAll(() => core.kill());

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

  test(
      'an identity whose keys this device holds is founded, rotated and interacts through the core',
      () async {
    final client = _LosesOneCommitAnswer(http.Client());
    final makes = TheKeyEventsThisDeviceMakes(client, base, km);

    final founded = await makes.found(seed);
    expect(founded.sn, 0);
    expect(founded.status, 'recorded');
    final aid = founded.aid;

    final rotated = await makes.rotate(seed,
        aid: aid, generation: 0, afterSn: 0, afterDigest: founded.digest);
    expect(rotated.sn, 1);

    final ixn = await makes.interact(seed,
        aid: aid,
        generation: 1,
        afterSn: 1,
        afterDigest: rotated.digest,
        anchors: [
          {
            'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
            's': '0',
            'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
          }
        ]);
    expect(ixn.sn, 2);

    // An interaction prepared after a place that is no longer the tip.
    await expectLater(
        makes.interact(seed,
            aid: aid,
            generation: 1,
            afterSn: 1,
            afterDigest: rotated.digest,
            anchors: const [
              {
                'i': 'ESecondSecondSecondSecondSecondSecondSecon12',
                's': '0',
                'd': 'ESecondSecondSecondSecondSecondSecondSecon12'
              }
            ]),
        throwsA(
            isA<KeyEventRefused>().having((e) => e.code, 'code', 'tip_moved')));

    // The commit reaches the core, and its answer is lost. The reservation
    // keeps the signed event, and finishing commits the same digest again,
    // so the log holds exactly one event at that place.
    client.lose = true;
    await expectLater(
        makes.interact(seed,
            aid: aid,
            generation: 1,
            afterSn: 2,
            afterDigest: ixn.digest,
            anchors: const [
              {
                'i': 'ESecondSecondSecondSecondSecondSecondSecon12',
                's': '0',
                'd': 'ESecondSecondSecondSecondSecondSecondSecon12'
              }
            ]),
        throwsA(isA<http.ClientException>()));
    final left = await TheEventsThisDeviceSigned().unfinished(aid);
    expect(left, hasLength(1));
    expect(left.single.sn, 3);
    final finished = await makes.finishSigned(aid);
    expect(finished.single.digest, left.single.digest);
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty);

    final kel = jsonDecode((await http.get(Uri.parse('$base/api/kel?name=$aid'),
            headers: {'X-Local-Owner-Secret': ownerSecret}))
        .body) as Map<String, dynamic>;
    final events = kel['kel'] as List? ?? const [];
    expect([for (final e in events) e['s']], ['0', '1', '2', '3'],
        reason: 'one event at each of four places: $kel');
    expect(kel['signed'], [true, true, true, true],
        reason: 'every event the core holds is signed');
  });
}
