import 'dart:convert';
import 'dart:io';

import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

/// Founding an organisation on a machine, and what has to travel with it.
///
/// The machine is given the owner's recovery key WHILE IT IS BEING SET UP,
/// because there is no second chance: afterwards its encrypted volume opens
/// only with a key derived from the software's measurement, and that key moves
/// whenever the image or the firmware does. An organisation founded without it
/// loses everything on the next update, and nothing says so at the time.

/// A stand-in machine that records the founding request.
class _FakeMachine {
  _FakeMachine(this._server, this.received);
  final HttpServer _server;
  final List<Map<String, dynamic>> received;

  String get url => 'http://127.0.0.1:${_server.port}';
  Future<void> close() => _server.close(force: true);

  static Future<_FakeMachine> start({List<String>? configKeys}) async {
    final received = <Map<String, dynamic>>[];
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((req) async {
      final path = req.uri.path;
      if (path.endsWith('/api/backup/config')) {
        req.response
          ..headers.contentType = ContentType.json
          ..write(jsonEncode({'seal_to_public_keys_b64': configKeys ?? []}));
        await req.response.close();
        return;
      }
      final body = await utf8.decoder.bind(req).join();
      if (path.endsWith('/api/pairing/begin')) {
        req.response.write(jsonEncode({'public_key': 'DKEY'}));
      } else if (path.endsWith('/api/pairing/complete')) {
        received.add(
            body.isEmpty ? {} : jsonDecode(body) as Map<String, dynamic>);
        req.response.write(jsonEncode({'root_aid': 'EORGROOT'}));
      }
      await req.response.close();
    });
    return _FakeMachine(server, received);
  }
}

void main() {
  test('the machine is given the owner key it will seal its disk to', () async {
    final machine = await _FakeMachine.start();
    addTearDown(machine.close);

    final core = CoreService(baseUrl: machine.url);
    addTearDown(core.dispose);

    final aid = await core.adoptAsOrganisation(
      adoptionCode: 'CODE',
      ownerAid: 'EOWNER',
      ownerPublicKey: 'DOWNERKEY',
      backupSealPublicKeys: const ['SEALKEY1'],
    );

    expect(aid, 'EORGROOT');
    final sent = machine.received.single;

    // THE POINT. Without this the organisation can write no backup anybody
    // could restore, and has no way back into its own encrypted volume.
    expect(sent['backup_seal_public_keys_b64'], ['SEALKEY1'],
        reason: 'the machine was set up with no recovery key, so the next image '
            'or firmware update would strand its data permanently');

    // Founded, not delegated — a delegation cannot be handed to the next owner.
    expect(sent['found_as_root'], isTrue);
    expect(sent['owner_aid'], 'EOWNER');
  });

  // An organisation whose owner never supplied one is still founded, because an
  // organisation with no owner at all cannot be repaired later and this can.
  test('a founding with no recovery key still names its owner', () async {
    final machine = await _FakeMachine.start();
    addTearDown(machine.close);

    final core = CoreService(baseUrl: machine.url);
    addTearDown(core.dispose);

    await core.adoptAsOrganisation(
      adoptionCode: 'CODE',
      ownerAid: 'EOWNER',
      ownerPublicKey: 'DOWNERKEY',
    );

    final sent = machine.received.single;
    expect(sent.containsKey('backup_seal_public_keys_b64'), isFalse,
        reason: 'an empty list would look like a decision to seal to nobody');
    expect(sent['owner_aid'], 'EOWNER');
  });

  test('an organisation can read back the key it was given', () async {
    final machine = await _FakeMachine.start(configKeys: ['SEALKEY1']);
    addTearDown(machine.close);

    final core = CoreService(baseUrl: machine.url);
    addTearDown(core.dispose);

    // Read back rather than re-derived: the seed these come from is on the
    // owner's device and never on this one, so this is the only copy.
    expect(await core.recoveryKeysHeld(), ['SEALKEY1']);
  });

  test('an agent holding no recovery key says so plainly', () async {
    final machine = await _FakeMachine.start();
    addTearDown(machine.close);

    final core = CoreService(baseUrl: machine.url);
    addTearDown(core.dispose);

    expect(await core.recoveryKeysHeld(), isEmpty);
  });
}
