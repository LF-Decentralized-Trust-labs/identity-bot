import 'dart:convert';
import 'dart:typed_data';

import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/root_seed_handoff.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

// The core's refusal, as its refuseIfRootSeedRefused writes it.
const _title = 'an identity cannot be created on this computer';
const _why = 'this phone\'s secure hardware is not available to this app yet';
http.Response _refusal() =>
    http.Response(jsonEncode({'error': _title, 'details': _why, 'code': 'root_seed_refused'}), 412);

Matcher _theRefusal() => throwsA(isA<RootSeedRefused>().having(
    (e) => e.message, 'message', allOf(contains(_title), contains(_why))));

// A client that signs as the owner, which is how a front end reaches its agent.
CoreService _coreAnswering(http.Response Function() answer) => CoreService(
      baseUrl: 'http://core.test',
      ownerSeed: () async => Uint8List.fromList(List.filled(32, 7)),
      ownerAid: 'EOwner',
      inner: MockClient((req) async => answer()),
    );

void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

  test('founding through the local core throws the refusal, not a bare Exception', () async {
    final keri = LocalCoreKeriService(
      baseUrl: 'http://core.test',
      client: MockClient((req) async => _refusal()),
    );
    await SecureKeyStore.saveMnemonic(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'.split(' '));
    await expectLater(
        keri.inceptAid(
            name: 'x',
            code:
                'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),
        _theRefusal());
  });

  test('founding through CoreService throws the refusal', () async {
    final core = _coreAnswering(_refusal);
    await expectLater(
        core.createInception(
            publicKey: 'Dk', nextPublicKey: 'Dn', signingSeed: Uint8List(32)),
        _theRefusal());
  });

  test('minting the identity that owns a machine throws the refusal', () async {
    final core = _coreAnswering(_refusal);
    await expectLater(core.mintMachineOwner(), _theRefusal());
  });

  test('a 412 that is not the root-seed refusal is not thrown as one', () async {
    final core = _coreAnswering(() => http.Response(
        jsonEncode({'error': 'Rotation required', 'details': 'x'}), 412));
    await expectLater(core.mintMachineOwner(),
        throwsA(isNot(isA<RootSeedRefused>())));
  });

  test('a fault that is not the refusal is still an ordinary failure', () async {
    final core = _coreAnswering(() => http.Response('{"error":"boom"}', 500));
    await expectLater(core.mintMachineOwner(),
        throwsA(isNot(isA<RootSeedRefused>())));
  });
}
