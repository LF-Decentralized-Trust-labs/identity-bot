import 'dart:convert';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart';
import 'package:agent_client/services/the_events_this_device_asked_for.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_in_force.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/the_core.dart';

/// An event an earlier version stored without a signature is signed late only
/// if it is exactly the event this phrase would have produced (ADR-061
/// section 3, the signer's fence; build plan B13). Run against the real core,
/// with the stored rows marked as the upgrade marks them.
void main() {
  final seed = Bip39.mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' '));
  String key(int i) => KeyManager.publicKeyAt(seed, i);
  late String bin;
  late KeyMath km;
  final cores = <ACore>[];

  setUpAll(() async {
    bin = await buildTheCore('late-signing-core', dev: true);
    km = await keyMathOf(bin);
  });

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

  tearDown(() async {
    for (final c in cores) {
      await c.close();
    }
    cores.clear();
  });

  Future<String> digest(int i) => km.nextKeyDigest(key(i));

  /// The events as an earlier version asked for them, committed signed to a
  /// real core, then left as it left them: [bodies] are prepared in order
  /// (each after the one before) and signed by the key the previous
  /// establishment event named, then the events at [unsigned] lose their
  /// signature and are marked, and the core is started again.
  /// The stored bytes of each event of the last [storedBy], as prepared.
  var rawsOfTheLast = <String>[];

  Future<(ACore, String, List<(int, String)>)> storedBy(
      List<Map<String, Object?>> bodies, List<int> unsigned) async {
    rawsOfTheLast = [];
    var core = await anotherCore(bin, km);
    cores.add(core);
    var aid = '';
    final placed = <(int, String)>[];
    var gen = 0;
    for (final (sn, body) in bodies.indexed) {
      final b = {...body};
      if (sn > 0) {
        b['aid'] = aid;
        b['after'] = {'s': (sn - 1).toRadixString(16), 'd': placed[sn - 1].$2};
      }
      // A rotation is signed by the key it reveals.
      if (body['t'] == 'rot') gen++;
      final signed =
          await preparedAndSigned(core.client, core.base, seed, gen, b);
      await commitTo(core.base, signed.rawB64, signed.sigs);
      final ev = await km.parseEvent(base64Decode(signed.rawB64));
      if (sn == 0) aid = ev.i;
      placed.add((sn, ev.d));
      rawsOfTheLast.add(signed.rawB64);
    }
    final data = core.dataDir!;
    final port = Uri.parse(core.base).port;
    await core.close();
    await Future<void>.delayed(const Duration(milliseconds: 500));
    await leaveUnsigned(data, aid, unsigned);
    core = await anotherCore(bin, km, dataDir: data, port0: port);
    cores.add(core);
    return (core, aid, placed);
  }

  Map<String, Object?> founding({List<String> n = const [], int next = 1}) => {
        't': 'icp',
        'k': [key(0)],
        'kt': '1',
        'n': ['placeholder', ...n],
        'nt': '1',
        'a': <Object?>[],
      };

  Future<Map<String, Object?>> legacyFounding(
          {List<String> more = const [], List<String> witnesses = const [], String toad = '0'}) async =>
      {
        ...founding(n: more),
        'n': [await digest(1), ...more],
        if (witnesses.isNotEmpty) ...{'b': witnesses, 'bt': toad},
      };

  Future<Map<String, Object?>> rotation(int to, {String? commitsTo, String toad = '0'}) async => {
        't': 'rot',
        'k': [key(to)],
        'kt': '1',
        'n': [commitsTo ?? await digest(to + 1)],
        'nt': '1',
        'a': <Object?>[],
        'br': <String>[],
        'ba': <String>[],
        'bt': toad,
      };

  Map<String, Object?> interaction(List<Object?> anchors) =>
      {'t': 'ixn', 'a': anchors};

  Future<List<bool>> signedInTheCore(ACore core, String aid) async {
    final res = await core.client.get(Uri.parse('${core.base}/api/kel?name=$aid'));
    return [for (final s in (jsonDecode(res.body) as Map)['signed'] as List) s as bool];
  }

  /// Late signing reads the key state it follows from this device's own record
  /// (a witness cannot hold an event nobody signed), so a test says what the
  /// record holds: the founding [at] it made, signed, with [witnesses].
  Future<void> recorded(String aid, Place at,
      {WitnessSet? witnesses}) async {
    final held = TheIdentityThisDeviceHolds();
    await held.holds(aid);
    await held.made(
        aid: aid,
        at: at,
        ilk: 'icp',
        key: key(0),
        keys: [key(0)],
        generation: 0,
        witnesses: witnesses?.witnesses ?? const [],
        toad: witnesses?.toad ?? 0);
  }

  TheKeyInForce keysOf(ACore core, {TheEventsThisDeviceAskedFor? asked}) =>
      TheKeyInForce(core.client, core.base,
          asked: asked ?? TheEventsThisDeviceAskedFor(),
          keyMath: km,
          readTheKeyState: (seed) =>
              TheKeyStateThisDeviceReads(core.client, km, core.base).read(seed));

  test('a stored founding with an extra next-key digest is not signed', () async {
    final extra = 'E${'M' * 43}';
    final (core, aid, _) =
        await storedBy([await legacyFounding(more: [extra])], [0]);
    expect(await signedInTheCore(core, aid), [false]);

    await expectLater(
        keysOf(core).signApprovedEvent(seed, sequenceNumber: '0', digest: aid),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.difference, 'difference', contains('"n"'))
            .having((e) => e.stored, 'what was stored', contains(extra))
            .having((e) => e.expected['n'], 'what was expected', [await digest(1)])));
    expect(await signedInTheCore(core, aid), [false],
        reason: 'nothing was recorded');
  });

  test('a stored rotation committing to another key is not signed', () async {
    final stranger = await km.nextKeyDigest(key(7));
    final (core, aid, placed) = await storedBy(
        [await legacyFounding(), await rotation(1, commitsTo: stranger)], [1]);
    await recorded(aid, (sn: 0, digest: placed[0].$2));
    expect(await signedInTheCore(core, aid), [true, false]);

    await expectLater(
        keysOf(core).signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.stored, 'what was stored', contains(stranger))
            .having((e) => e.expected['n'], 'what was expected', [await digest(2)])));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  test('a stored interaction anchoring something else is not signed', () async {
    final other = 'E${'O' * 43}';
    final theirs = 'E${'T' * 43}';
    final (core, aid, placed) = await storedBy([
      await legacyFounding(),
      interaction([
        {'i': other, 's': '0', 'd': other}
      ]),
    ], [1]);
    await recorded(aid, (sn: 0, digest: placed[0].$2));
    // This device asked for an anchor of its own, and was given this event.
    final asked = TheEventsThisDeviceAskedFor();
    final request = await asked.asking(t: 'ixn', aid: aid, expectedSn: 1, asked: {
      'anchors': [
        {'i': theirs, 's': '0', 'd': theirs}
      ]
    });
    await asked.added(request, aid: aid, sequenceNumber: 1, digest: placed[1].$2);

    await expectLater(
        keysOf(core).finishStrandedEvents(seed),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.stored, 'what was stored', contains(other))
            .having((e) => jsonEncode(e.expected['a']), 'what was expected', contains(theirs))));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  test('an interaction that anchors a credential and something more is not signed',
      () async {
    final said = 'E${'C' * 43}';
    final (core, aid, placed) = await storedBy([
      await legacyFounding(),
      interaction([
        {'i': said, 's': '0', 'd': said},
        {'i': said, 's': '1', 'd': said},
      ]),
    ], [1]);
    await recorded(aid, (sn: 0, digest: placed[0].$2));
    final asked = TheEventsThisDeviceAskedFor();
    final request = await asked.asking(t: 'ixn', aid: aid, expectedSn: 1, asked: {
      'anchors': [
        {'i': said, 's': '0', 'd': said}
      ]
    });
    await asked.added(request, aid: aid, sequenceNumber: 1, digest: placed[1].$2);

    await expectLater(keysOf(core).finishStrandedEvents(seed),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  test('an interaction asked for without saying what it anchors is refused, with what was stored, and signed only when the person approves it',
      () async {
    // {i: x, s: "0", d: x} is a credential's seal and also a delegator's
    // approval of the delegate x, so a core choosing x cannot be told apart.
    final x = 'E${'X' * 43}';
    final (core, aid, placed) = await storedBy([
      await legacyFounding(),
      interaction([
        {'i': x, 's': '0', 'd': x}
      ]),
    ], [1]);
    await recorded(aid, (sn: 0, digest: placed[0].$2));
    final asked = TheEventsThisDeviceAskedFor();
    final request = await asked.asking(t: 'ixn', aid: aid, expectedSn: 1);
    await asked.added(request, aid: aid, sequenceNumber: 1, digest: placed[1].$2);

    await expectLater(
        keysOf(core).finishStrandedEvents(seed),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.stored, 'what was stored', contains(x))
            .having((e) => e.difference, 'difference', contains('did not ask'))));
    expect(await signedInTheCore(core, aid), [true, false]);

    // Shown to the person, who approves exactly this event.
    await keysOf(core).signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2);
    expect(await signedInTheCore(core, aid), [true, true]);
  });

  test('bytes whose digest is not the one this device recorded are not signed',
      () async {
    final mine = 'E${'C' * 43}';
    final theirs = 'E${'D' * 43}';
    final (core, aid, placed) = await storedBy([
      await legacyFounding(),
      interaction([
        {'i': mine, 's': '0', 'd': mine}
      ]),
    ], [1]);
    await recorded(aid, (sn: 0, digest: placed[0].$2));
    // The same founding elsewhere, with an interaction of the core's choosing.
    await storedBy([
      await legacyFounding(),
      interaction([
        {'i': theirs, 's': '0', 'd': theirs}
      ]),
    ], []);
    final theirBytes = rawsOfTheLast[1];
    // This device asked for the seal the other bytes carry, and recorded the
    // digest of the event the core listed: the bytes served are another
    // event's, whose content is exactly what was asked.
    final asked = TheEventsThisDeviceAskedFor();
    final request = await asked.asking(t: 'ixn', aid: aid, expectedSn: 1, asked: {
      'anchors': [
        {'i': theirs, 's': '0', 'd': theirs}
      ]
    });
    await asked.added(request, aid: aid, sequenceNumber: 1, digest: placed[1].$2);
    core.client.serveOtherBytesAt[1] = theirBytes;

    await expectLater(
        keysOf(core, asked: asked).finishStrandedEvents(seed),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.difference, 'difference', contains('digest'))
            .having((e) => e.expected['d'], 'the digest recorded', placed[1].$2)));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  final witnesses = [for (final c in ['A', 'B', 'C']) 'B${c * 43}'];

  test('a stored rotation that lowers the witness threshold is not signed',
      () async {
    final (core, aid, placed) = await storedBy([
      await legacyFounding(witnesses: witnesses, toad: '2'),
      await rotation(1, toad: '1'),
    ], [1]);
    // The threshold in force is the one this device recorded: two.
    await recorded(aid, (sn: 0, digest: placed[0].$2),
        witnesses: WitnessSet(witnesses, 2));

    await expectLater(
        keysOf(core).signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.difference, 'difference', contains('"bt"'))
            .having((e) => e.expected['bt'], 'the threshold in force', '2')));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  test('a stored rotation that keeps the witness threshold in force is signed',
      () async {
    final (core, aid, placed) = await storedBy([
      await legacyFounding(witnesses: witnesses, toad: '2'),
      await rotation(1, toad: '2'),
    ], [1]);
    await recorded(aid, (sn: 0, digest: placed[0].$2),
        witnesses: WitnessSet(witnesses, 2));

    await keysOf(core).signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2);
    expect(await signedInTheCore(core, aid), [true, true]);
  });

  test('a stored rotation that follows another event than this device recorded is not signed',
      () async {
    final (core, aid, placed) = await storedBy(
        [await legacyFounding(), await rotation(1)], [1]);
    // This device's record has another founding at sequence number 0: the
    // history the core serves is not the one this device made.
    final other = 'E${'F' * 43}';
    await recorded(aid, (sn: 0, digest: other));

    await expectLater(
        keysOf(core).signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2),
        throwsA(isA<AStoredEventIsNotTheOneExpected>()
            .having((e) => e.difference, 'difference', contains('follows'))
            .having((e) => e.expected['p'], 'what it must follow', other)));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  test('nothing is signed late when the key state it follows cannot be read',
      () async {
    final (core, aid, placed) = await storedBy(
        [await legacyFounding(), await rotation(1)], [1]);
    // No record, no witnesses to ask: only the core's own word is left.
    await expectLater(
        keysOf(core).signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2),
        throwsA(isA<TheKeyStateCannotBeReadToSignLate>()));
    final bare = TheKeyInForce(core.client, core.base,
        asked: TheEventsThisDeviceAskedFor(), keyMath: km);
    await expectLater(
        bare.signApprovedEvent(seed, sequenceNumber: '1', digest: placed[1].$2),
        throwsA(isA<TheKeyStateCannotBeReadToSignLate>()));
    expect(await signedInTheCore(core, aid), [true, false]);
  });

  test('a stored founding, rotation and interaction that are exactly right are signed and accepted by the core',
      () async {
    final said = 'E${'C' * 43}';
    final (core, aid, placed) = await storedBy([
      await legacyFounding(),
      await rotation(1),
      interaction([
        {'i': said, 's': '0', 'd': said}
      ]),
    ], [0, 1, 2]);
    expect(await signedInTheCore(core, aid), [false, false, false]);

    final asked = TheEventsThisDeviceAskedFor();
    await asked.asking(t: 'icp', expectedSn: 0, asked: {'key': key(0), 'next': key(1)});
    await asked.asking(t: 'rot', aid: aid, expectedSn: 1, asked: {'key': key(1), 'next': key(2)});
    final request = await asked.asking(t: 'ixn', aid: aid, expectedSn: 2, asked: {
      'anchors': [
        {'i': said, 's': '0', 'd': said}
      ]
    });
    await asked.added(request, aid: aid, sequenceNumber: 2, digest: placed[2].$2);

    final state = await keysOf(core).finishStrandedEvents(seed);
    expect(state.index, 1);
    expect(await signedInTheCore(core, aid), [true, true, true]);
    expect(await keysOf(core).finishStrandedEvents(seed), isNotNull,
        reason: 'nothing is left to sign, and asking again is harmless');
  });
}
