/// Each test here runs a real core and signs with post-quantum keys, so it
/// takes longer than the default 30 seconds.
@Timeout(Duration(minutes: 3))
library;

import 'dart:typed_data';
import 'dart:convert';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/recovering_this_identity.dart';
import 'package:agent_client/services/root_seed_handoff.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_key_state_this_device_reads.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

void main() {
  late String bin;
  late KeyMath km;
  late AWitness w1, w2, w3;
  late ACore before, after;
  late TheWitnessesOfThisDevicesEvents witnesses;
  final seed = Bip39.mnemonicToSeed(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' '));
  const anchor = [
    {
      'i': 'EAnchoredAnchoredAnchoredAnchoredAnchored12',
      's': '0',
      'd': 'EAnchoredAnchoredAnchoredAnchoredAnchored12'
    }
  ];

  setUpAll(() async {
    bin = await buildTheCore('recovery-core', dev: true);
    km = await keyMathOf(bin);
    w1 = await AWitness.start(km);
    w2 = await AWitness.start(km);
    w3 = await AWitness.start(km);
    witnesses = TheWitnessesOfThisDevicesEvents(
        http.Client(),
        km,
        KnownWitnesses({
          for (final w in [w1, w2, w3]) w.aid: w.base
        }));
  });

  tearDownAll(() async {
    for (final w in [w1, w2, w3]) {
      await w.close();
    }
  });

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    SharedPreferences.setMockInitialValues({});
    for (final w in [w1, w2, w3]) {
      w.forgetAll();
    }
    before = await anotherCore(bin, km);
    after = await anotherCore(bin, km);
  });

  tearDown(() async {
    await before.close();
    await after.close();
  });

  Map<String, Uri> addresses() => {
        for (final w in [w1, w2, w3]) w.aid: w.base
      };

  /// An identity founded, rotated and used on the device before it was
  /// wiped.
  Future<({String aid, Committed ixn})> anIdentityInUse() async {
    final m = TheKeyEventsThisDeviceMakes(before.client, before.base, km,
        witnesses: witnesses, held: TheIdentityThisDeviceHolds());
    final founded =
        await m.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
    final set = WitnessSet([w1.aid, w2.aid, w3.aid], 2);
    final rot = await m.rotate(seed,
        aid: founded.aid,
        generation: 0,
        afterSn: 0,
        afterDigest: founded.digest,
        toad: 2,
        witnessedBy: set);
    final ixn = await m.interact(seed,
        aid: founded.aid,
        generation: 1,
        afterSn: rot.sn,
        afterDigest: rot.digest,
        anchors: anchor,
        witnessedBy: set);
    return (aid: founded.aid, ixn: ixn);
  }

  Future<String?> heldBy(ACore core) async {
    final res = await http.get(Uri.parse('${core.base}/api/identity'),
        headers: const {'X-Local-Owner-Secret': ownerSecret});
    if (res.statusCode != 200) return null;
    final aid = (jsonDecode(res.body) as Map)['aid'];
    return aid is String && aid.isNotEmpty ? aid : null;
  }

  test(
      'a wiped device recovers the identity from its phrase and its witnesses, '
      'installs it in a new core, and goes on to interact', () async {
    final used = await anIdentityInUse();
    // Wiped: nothing of the identity is left on the device.
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());

    final recovered = await RecoveringThisIdentity(after.client, after.base, km)
        .recover(seed,
            aid: used.aid,
            witnessAddresses: addresses(),
            agentBase: before.base);
    expect(recovered.state.generation, 1);
    expect(recovered.state.tip.digest, used.ixn.digest);
    expect(recovered.messagingGeneration, 0);
    expect(await heldBy(after), used.aid);
    final record = await TheIdentityThisDeviceHolds().read();
    expect((record!.tip?.digest, record.generation), (used.ixn.digest, 1),
        reason: 'the device\'s record starts from the log\'s tip');

    // The new core keeps the log, and the device signs the next event there.
    final state = await TheKeyStateThisDeviceReads(after.client, km, after.base)
        .read(seed);
    expect(state.fromItsOwnRecord, isTrue);
    final m = TheKeyEventsThisDeviceMakes(after.client, after.base, km,
        witnesses: witnesses, held: TheIdentityThisDeviceHolds());
    final next = await m.interact(seed,
        aid: used.aid,
        generation: state.generation,
        afterSn: state.tip.sn,
        afterDigest: state.tip.digest,
        anchors: anchor,
        witnessedBy: state.witnesses);
    expect(next.sn, used.ixn.sn + 1);
    expect(next.witnessed!.enough, isTrue);

    // The core was handed the recovered messaging seed: it accepts an event
    // anchoring that keyset, which it refuses for keys it does not hold.
    final keyset = await km
        .messagingKeySet(KeyManager.slip10Ed25519(seed, KeyPaths.messaging(0)));
    final again = await m.interact(seed,
        aid: used.aid,
        generation: state.generation,
        afterSn: next.sn,
        afterDigest: next.digest,
        anchors: [keyset],
        witnessedBy: state.witnesses);
    expect(again.sn, next.sn + 1);
  });

  test(
      'copies that differ at an establishment event stop recovery, and nothing '
      'is installed', () async {
    final m = TheKeyEventsThisDeviceMakes(before.client, before.base, km,
        witnesses: witnesses, held: TheIdentityThisDeviceHolds());
    final founded =
        await m.found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
    // Another device with this phrase rotated at the same place, and one
    // witness took its rotation first.
    final rival = await preparedAndSigned(
        before.client, before.base, before.km, seed, 1, {
      'aid': founded.aid,
      't': 'rot',
      'k': [KeyManager.keyAt(seed, 1).publicKeyEncoded],
      'kt': '1',
      'n': [
        await km.nextKeyDigest(KeyManager.keyAt(seed, 2).publicKeyEncoded),
        (await km.postQuantumNext(
                KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(1))))
            .digest
      ],
      'nt': '1',
      'a': anchor,
      'br': [],
      'ba': [],
      'bt': '2',
      'after': {'s': '0', 'd': founded.digest},
    });
    await w3.hold(founded.aid, rival);
    await m.rotate(seed,
        aid: founded.aid,
        generation: 0,
        afterSn: 0,
        afterDigest: founded.digest,
        toad: 2,
        witnessedBy: WitnessSet([w1.aid, w2.aid, w3.aid], 2));
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());

    await expectLater(
        RecoveringThisIdentity(after.client, after.base, km)
            .recover(seed, aid: founded.aid, witnessAddresses: addresses()),
        throwsA(isA<TheLogHasTwoHistories>().having((e) => e.sn, 'place', 1)));
    expect(await heldBy(after), isNull);
    expect(await TheIdentityThisDeviceHolds().read(), isNull,
        reason: 'a recovery that stops leaves the device holding nothing');
  });

  test(
      'a log too few witnesses can be read for is not recovered from the '
      'Identity Agent\'s copy alone', () async {
    final used = await anIdentityInUse();
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    w2.offline = true;
    w3.offline = true;
    await expectLater(
        RecoveringThisIdentity(after.client, after.base, km).recover(seed,
            aid: used.aid,
            witnessAddresses: addresses(),
            agentBase: before.base),
        throwsA(anyOf(isA<TheWitnessesDoNotSay>(), isA<RecoveryStopped>())));
    expect(await heldBy(after), isNull);
    expect(await TheIdentityThisDeviceHolds().read(), isNull);

    // Nothing was left behind, so it is tried again once the witnesses can
    // be read, and finishes.
    w2.offline = false;
    w3.offline = false;
    final recovered = await RecoveringThisIdentity(after.client, after.base, km)
        .recover(seed,
            aid: used.aid,
            witnessAddresses: addresses(),
            agentBase: before.base);
    expect(recovered.state.tip.digest, used.ixn.digest);
  });

  /// Founds an identity on [before] revealing this phrase's key 0 and
  /// committing to [next], anchoring nothing, witnessed by all three.
  Future<String> aFounding(List<String> next) async {
    final icp = await preparedAndSigned(
        before.client, before.base, before.km, seed, 0, {
      't': 'icp',
      'k': [KeyManager.keyAt(seed, 0).publicKeyEncoded],
      'kt': '1',
      'n': next,
      'nt': '1',
      'a': [],
      'b': [w1.aid, w2.aid, w3.aid],
      'bt': '2',
    });
    await commitTo(before.base, icp.rawB64, icp.sigs);
    final ev = await km.parseEvent(base64Decode(icp.rawB64));
    await witnesses.receipt(
        aid: ev.i,
        sn: 0,
        digest: ev.d,
        bytesB64: icp.rawB64,
        sigs: icp.sigs,
        set: WitnessSet([w1.aid, w2.aid, w3.aid], 2));
    return ev.i;
  }

  test(
      'a core that cannot protect the root seed refuses the identity with '
      'its own reason, and installs nothing', () async {
    final used = await anIdentityInUse();
    FlutterSecureStorage.setMockInitialValues({});
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
    after.client.answerInstead['/api/identity/restore'] =
        (412, RootSeedRefused.code);
    try {
      await expectLater(
          RecoveringThisIdentity(after.client, after.base, km).recover(seed,
              aid: used.aid,
              witnessAddresses: addresses(),
              agentBase: before.base),
          throwsA(isA<RootSeedRefused>()));
    } finally {
      after.client.answerInstead.remove('/api/identity/restore');
    }
    expect(await heldBy(after), isNull);
  });

  test(
      'an identity whose keys in force commit to keys this phrase does not '
      'derive is not recovered with it', () async {
    final stranger = Bip39.mnemonicToSeed(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' '));
    final aid = await aFounding([
      await km.nextKeyDigest(KeyManager.keyAt(stranger, 1).publicKeyEncoded)
    ]);
    await expectLater(
        RecoveringThisIdentity(after.client, after.base, km)
            .recover(seed, aid: aid, witnessAddresses: addresses()),
        throwsA(isA<TheKeyInForceIsNotThisPhrases>()));
    expect(await heldBy(after), isNull);
  });

  test(
      'an identity that anchors no messaging keyset of this phrase is '
      'recovered, and its messaging keys are to be replaced', () async {
    final pq = KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(0));
    final aid = await aFounding([
      await km.nextKeyDigest(KeyManager.keyAt(seed, 1).publicKeyEncoded),
      (await km.postQuantumNext(pq)).digest
    ]);
    final recovered = await RecoveringThisIdentity(after.client, after.base, km)
        .recover(seed, aid: aid, witnessAddresses: addresses());
    expect(recovered.messagingKeysToReplace, isTrue);
    expect(await heldBy(after), aid);
    expect((await TheIdentityThisDeviceHolds().read())!.generation, 0);
  });

  /// Founds an identity on [by]'s key 0, committing to [next]: what an old
  /// phrase's step 1 looks like to a device holding only the new phrase.
  Future<String> aFoundingBy(Uint8List by, List<String> next) async {
    final icp =
        await preparedAndSigned(before.client, before.base, before.km, by, 0, {
      't': 'icp',
      'k': [KeyManager.keyAt(by, 0).publicKeyEncoded],
      'kt': '1',
      'n': next,
      'nt': '1',
      'a': [],
      'b': [w1.aid, w2.aid, w3.aid],
      'bt': '2',
    });
    await commitTo(before.base, icp.rawB64, icp.sigs);
    final ev = await km.parseEvent(base64Decode(icp.rawB64));
    await witnesses.receipt(
        aid: ev.i,
        sn: 0,
        digest: ev.d,
        bytesB64: icp.rawB64,
        sigs: icp.sigs,
        set: WitnessSet([w1.aid, w2.aid, w3.aid], 2));
    return ev.i;
  }

  test(
      'a step 1 by the old phrase that commits to this phrase\'s classical '
      'key but another post-quantum one is not a move to this phrase',
      () async {
    final old = Bip39.mnemonicToSeed(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' '));
    final someOtherPq = (await km.postQuantumNext(
            KeyManager.slip10Ed25519(old, KeyPaths.postQuantum(5))))
        .digest;
    final aid = await aFoundingBy(old, [
      await km.nextKeyDigest(KeyManager.keyAt(seed, 1).publicKeyEncoded),
      someOtherPq
    ]);
    await expectLater(
        RecoveringThisIdentity(after.client, after.base, km)
            .recover(seed, aid: aid, witnessAddresses: addresses()),
        throwsA(isA<TheKeyInForceIsNotThisPhrases>()));
  });

  test(
      'the same step 1 committing to this phrase\'s post-quantum generation 0 '
      'is not refused as another phrase\'s', () async {
    final old = Bip39.mnemonicToSeed(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' '));
    final pq0 = (await km.postQuantumNext(
            KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(0))))
        .digest;
    final aid = await aFoundingBy(old, [
      await km.nextKeyDigest(KeyManager.keyAt(seed, 1).publicKeyEncoded),
      pq0
    ]);
    try {
      await RecoveringThisIdentity(after.client, after.base, km)
          .recover(seed, aid: aid, witnessAddresses: addresses());
    } catch (e) {
      expect(e, isNot(isA<TheKeyInForceIsNotThisPhrases>()),
          reason: 'the commitments are this phrase\'s: $e');
    }
  });
}
