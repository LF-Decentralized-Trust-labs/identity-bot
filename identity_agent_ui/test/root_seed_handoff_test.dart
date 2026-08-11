import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:agent_client/services/root_seed_handoff.dart';

void main() {
  test('handoff posts the standard BIP39 seed to the local keystore', () async {
    late Uri capturedUri;
    late Map<String, dynamic> capturedBody;
    final client = MockClient((req) async {
      capturedUri = req.url;
      capturedBody = jsonDecode(req.body) as Map<String, dynamic>;
      return http.Response('{"status":"stored"}', 201);
    });

    final ok = await RootSeedHandoff.register(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' '),
      baseUrl: 'http://127.0.0.1:5050',
      client: client,
    );

    expect(ok, isTrue);
    expect(capturedUri.path, '/api/keystore/root-seed');
    final seedHex = base64Decode(capturedBody['seed_b64'] as String)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    // The BIP39 reference vector for this phrase — proves the Dart derivation
    // matches the core's Go derivation byte-for-byte.
    expect(
      seedHex,
      '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1'
      '9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
    );
  });

  test('a refused handoff reports failure without throwing', () async {
    final client =
        MockClient((req) async => http.Response('{"error":"conflict"}', 409));
    final ok = await RootSeedHandoff.register(
      const ['abandon', 'ability'],
      baseUrl: 'http://127.0.0.1:5050',
      client: client,
    );
    expect(ok, isFalse);
  });
}
