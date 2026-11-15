import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:login_dart/app_checks.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:login_dart/seal.dart';
import 'package:pointycastle/export.dart' show SHA256Digest;

/// A utility app's back end behind a relay, made from the shared vectors: the
/// relay identifier and sealing key of seal.json answer and open sealed calls,
/// and the app is the one of app-checks.json (its key is derived from a fixed
/// seed there). Real enough that the SDK's every check runs; the
/// routes are the back end's half of ADR-072 section 2.
final sealVectors =
    jsonDecode(File('../login-web/test-vectors/seal.json').readAsStringSync())
        as Map<String, dynamic>;
final appVectors = jsonDecode(
        File('../login-web/test-vectors/app-checks.json').readAsStringSync())
    as Map<String, dynamic>;

BigInt big(String hex) => BigInt.parse(hex, radix: 16);
Uint8List sha(String s) =>
    SHA256Digest().process(Uint8List.fromList(utf8.encode(s)));

class FakeApp {
  final String rid = sealVectors['rid'] as String;
  final String assetId;
  final DateTime clock;
  late final AppLink link;
  late final ed.PrivateKey relayKey = ed.newKeyFromSeed(Uint8List.fromList([
    for (var i = 0; i < 64; i += 2)
      int.parse((sealVectors['relay_seed_hex'] as String).substring(i, i + 2),
          radix: 16)
  ]));
  late final ed.PrivateKey appKey = ed.newKeyFromSeed(sha('app-checks:app'));
  final BigInt sealD =
      big((sealVectors['seal_key'] as Map)['private_hex'] as String);

  /// Every call that opened, as the back end read it.
  final calls = <({
    String method,
    String target,
    Map<String, dynamic> headers,
    String body
  })>[];

  /// What the back end says about the sign-in: pending this many asks, then [outcome].
  int pendingAsks = 1;
  String outcome = 'verified';
  String? asked; // the ask handed out
  Map<String, dynamic>? startedWith;
  String? thumbprintSeen;
  bool installedOnly = true;

  /// When set, the challenge the back end signs names this key, not the one asked for.
  String? challengeKey;
  int status401After = -1;
  int sealedCount = 0;

  FakeApp({this.assetId = 'Eapp0123456789', DateTime? clock})
      : clock = clock ?? DateTime.utc(2026, 11, 11, 12) {
    final hash = (appVectors['links'] as List).first['hash'] as String;
    final p = Uri.splitQueryString(hash.substring(1));
    final seal = sealVectors['seal_key'] as Map;
    link = AppLink(p['aid']!, p['kel']!, rid, 'https://tasks.example',
        seal['statement'] as String, seal['min'] as String);
  }

  late final http.Client client = MockClient((req) async {
    if (req.url.path != sealPath) return http.Response('not here', 404);
    final o = openRequest(rid, sealD, req.body);
    final call = jsonDecode(utf8.decode(o.content)) as Map<String, dynamic>;
    final method = call['method'] as String;
    final target = call['target'] as String;
    final headers = (call['headers'] as Map).cast<String, dynamic>();
    final body = call['body'] as String;
    sealedCount++;
    calls.add((method: method, target: target, headers: headers, body: body));
    final r = route(method, target, headers, body);
    final nonce = headers['x-browser-answer-nonce'] as String;
    final bytes = utf8.encode(jsonEncode(r.body));
    final sig = ed.sign(
        relayKey,
        Uint8List.fromList(utf8.encode(
            answerText(rid, nonce, r.status, 'application/json', bytes))));
    final answer = jsonEncode({
      'status': r.status,
      'content_type': 'application/json',
      'body': b64uEncode(bytes),
      'log': sealVectors['relay_log'],
      'sig': b64uEncode(sig),
    });
    return http.Response(o.reply.seal(utf8.encode(answer)), 200,
        headers: {'content-type': 'application/json'});
  });

  String serverTime() => '${clock.toUtc().toIso8601String().split('.').first}Z';

  ({int status, Map<String, dynamic> body}) route(
      String method, String target, Map<String, dynamic> headers, String body) {
    switch ('$method $target') {
      case 'POST /signin/installed-key/ask':
        asked = 'ask-${calls.length}';
        return (
          status: 200,
          body: {
            'ask': asked,
            'challenge': b64uEncode(List<int>.generate(32, (i) => 100 + i)),
            'expires': '2026-11-11T12:05:00Z'
          }
        );
      case 'POST /signin/session':
        final j = jsonDecode(body) as Map<String, dynamic>;
        startedWith = j;
        thumbprintSeen = j['browserKey'] as String;
        final kind = j['frontEnd'] as String;
        if (installedOnly && kind == 'installed_app' && (j['proof'] == null)) {
          return (
            status: 403,
            body: {
              'error':
                  'an installed-app sign-in needs the key proved in hardware'
            }
          );
        }
        final c = jsonEncode({
          'v': 'ASK1',
          't': 1,
          'site_aid': link.aid,
          'browser_key': challengeKey ?? j['browserKey'],
          'front_end': kind,
          'expiry':
              '${clock.add(const Duration(minutes: 10)).toUtc().toIso8601String().split('.').first}Z',
          'session_token': 'tok',
        });
        final sig = ed.sign(appKey, Uint8List.fromList(utf8.encode(c)));
        return (
          status: 200,
          body: {
            'session_token': 'tok',
            'relay_or_qr_url': 'https://ia.example/i/tok',
            'canonical_body': c,
            'sig': matterEncode('0B', sig),
            'server_time': serverTime(),
          }
        );
      case 'GET /signin/session/tok':
        if (pendingAsks-- > 0) return (status: 200, body: {'state': 'pending'});
        return (
          status: 200,
          body: outcome == 'verified'
              ? {
                  'state': 'verified',
                  'app_session_token': 'grant-1',
                  'pairwise_aid': 'EP',
                  'server_time': serverTime()
                }
              : {'state': outcome}
        );
      case 'GET /session/whoami':
        return (
          status: 200,
          body: {
            'pairwise_aid': 'EP',
            'browser_key': thumbprintSeen ?? '',
            'server_time': serverTime()
          }
        );
      case 'POST /session/signout':
        return (status: 200, body: {'ok': true});
    }
    if (target.startsWith('/session/')) {
      if (status401After >= 0 && sealedCount > status401After)
        return (status: 401, body: {'error': 'ended'});
      return (status: 200, body: {'ok': true, 'echo': body});
    }
    return (status: 404, body: {'error': 'no such route'});
  }
}

/// A [HardwareKeyPlatform] standing in for the device: a key held in memory that
/// records what it was asked to attest.
class FakeHardware implements HardwareKeyPlatform {
  SoftwareFrontEndKey key = SoftwareFrontEndKey.generate();
  Uint8List? lastChallenge, lastDigest;
  int made = 0;
  @override
  String get platform => InstalledPlatform.android;
  Uint8List get _point =>
      Uint8List.fromList([4, ...b64uDecode(key.x)!, ...b64uDecode(key.y)!]);
  @override
  Future<Uint8List> publicPoint(String label) async => _point;
  @override
  Future<Uint8List> signDer(String label, Uint8List message) async =>
      rawToDer(b64uDecode(await key.sign(utf8.decode(message)))!);
  @override
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge) async {
    // Android fixes the attestation challenge when the key is generated: a new key per ask.
    key = SoftwareFrontEndKey.generate();
    made++;
    lastChallenge = challenge;
    return (
      point: _point,
      evidence:
          Uint8List.fromList(utf8.encode('chain-for-${b64uEncode(challenge)}'))
    );
  }

  @override
  Future<Uint8List> signStatement(
      String label, Uint8List statementDigest) async {
    lastDigest = statementDigest;
    return rawToDer(b64uDecode(await key.sign(b64uEncode(statementDigest)))!);
  }
}

/// ASN.1 DER of a raw r||s signature, as hardware gives it.
Uint8List rawToDer(Uint8List raw) {
  Uint8List part(Uint8List v) {
    var i = 0;
    while (i < v.length - 1 && v[i] == 0) {
      i++;
    }
    var b = v.sublist(i);
    if (b[0] & 0x80 != 0) b = Uint8List.fromList([0, ...b]);
    return Uint8List.fromList([0x02, b.length, ...b]);
  }

  final r = part(raw.sublist(0, 32)), s = part(raw.sublist(32));
  return Uint8List.fromList([0x30, r.length + s.length, ...r, ...s]);
}
