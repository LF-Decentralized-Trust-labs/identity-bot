import 'dart:io';
import 'dart:math';

import 'package:agent_client/crypto/bip39.dart';
import 'package:agent_client/crypto/keys.dart';
import 'package:agent_client/services/key_math.dart';
import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:agent_client/services/the_identity_this_device_holds.dart';
import 'package:agent_client/services/the_key_events_this_device_makes.dart';
import 'package:agent_client/services/the_witnesses_of_this_devices_events.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

import 'support/a_core_that_misleads.dart';
import 'support/a_witness.dart';
import 'support/the_core.dart';

late String bin;

void main() {
  late Process core;
  late String base;
  late KeyMath km;
  late AWitness w1, w2, w3;
  late ACoreThatMisleads client;
  late TheWitnessesOfThisDevicesEvents witnesses;

  setUpAll(() async {
    bin = await buildTheCore('witnessed-core', dev: true);
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
        if ((await http.get(Uri.parse('$base/api/health'))).statusCode == 200) {
          break;
        }
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    w1 = await AWitness.start(km);
    w2 = await AWitness.start(km);
    w3 = await AWitness.start(km);
    client = ACoreThatMisleads(http.Client());
    witnesses = TheWitnessesOfThisDevicesEvents(
        http.Client(),
        km,
        KnownWitnesses({
          for (final w in [w1, w2, w3]) w.aid: w.base
        }));
  });

  tearDownAll(() async {
    core.kill();
    for (final w in [w1, w2, w3]) {
      await w.close();
    }
  });

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

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
  const another = [
    {
      'i': 'ESecondSecondSecondSecondSecondSecondSecon12',
      's': '0',
      'd': 'ESecondSecondSecondSecondSecondSecondSecon12'
    }
  ];

  // One identity is founded on this core, so the tests below follow on from
  // one another, in order.
  late String aid;
  late WitnessSet set;
  late Place tip;
  var generation = 0;

  TheKeyEventsThisDeviceMakes makes() =>
      TheKeyEventsThisDeviceMakes(client, base, km,
          witnesses: witnesses,
          retryDelays: const [Duration.zero, Duration.zero, Duration.zero]);

  test(
      'a founding reaches its witnesses though the core sends it to none, and '
      'only receipts that verify are counted', () async {
    w3.forgesReceipts = true;
    final founded =
        await makes().found(seed, witnesses: [w1.aid, w2.aid, w3.aid], toad: 2);
    w3.forgesReceipts = false;
    aid = founded.aid;
    set = WitnessSet([w1.aid, w2.aid, w3.aid], 2);
    tip = (sn: 0, digest: founded.digest);

    // The core knows none of these witnesses, so whatever reached them was
    // sent by the app.
    final w = founded.witnessed!;
    expect(w.receipts.keys, unorderedEquals([w1.aid, w2.aid]));
    expect(w.unreached, {w3.aid},
        reason: 'a receipt signed by another key is not counted');
    expect(w.enough, isTrue);
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty,
        reason: 'two of three receipts meet the threshold of two');
  });

  test(
      'an event too few witnesses receipt is kept, and is sent again until '
      'enough do, the witness that missed earlier events given them first',
      () async {
    w2.offline = true;
    final ixn = await makes().interact(seed,
        aid: aid,
        generation: generation,
        afterSn: tip.sn,
        afterDigest: tip.digest,
        anchors: anchor,
        witnessedBy: set);
    tip = (sn: ixn.sn, digest: ixn.digest);
    // w1 receipts; w3 forged the founding's receipt but kept the founding,
    // so it receipts this one.
    expect(ixn.witnessed!.receipts.keys, unorderedEquals([w1.aid, w3.aid]));

    // A witness that held nothing: it is given the founding and the
    // interaction from another witness's copies, then this event.
    final w4 = await AWitness.start(km);
    addTearDown(w4.close);
    final four = TheKeyEventsThisDeviceMakes(client, base, km,
        witnesses: TheWitnessesOfThisDevicesEvents(
            http.Client(),
            km,
            KnownWitnesses({
              for (final w in [w1, w2, w3, w4]) w.aid: w.base
            })));
    final wider = WitnessSet([w1.aid, w2.aid, w4.aid], 3);
    final next = await four.interact(seed,
        aid: aid,
        generation: generation,
        afterSn: tip.sn,
        afterDigest: tip.digest,
        anchors: another,
        witnessedBy: wider);
    tip = (sn: next.sn, digest: next.digest);
    expect(next.witnessed!.receipts.keys, unorderedEquals([w1.aid, w4.aid]));
    expect(w4.held[aid], hasLength(3),
        reason: 'the founding and interaction came from w1, then this');
    final kept = await TheEventsThisDeviceSigned().unfinished(aid);
    expect([for (final r in kept) (r.sn, r.recorded)], [(2, true)],
        reason: 'two receipts of three needed: the event is kept');

    w2.offline = false;
    final again = await four.finishSigned(aid, witnessedBy: wider);
    expect(again.single.witnessed!.receipts.keys,
        unorderedEquals([w1.aid, w2.aid, w4.aid]));
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty);
    // Bring the identity's own witnesses up to date for what follows.
    await witnesses.receipt(
        aid: aid,
        sn: next.sn,
        digest: next.digest,
        bytesB64: next.bytesB64,
        sigs: next.signatures,
        set: set);
  });

  test(
      'a rotation reaches its witnesses, a core that answers 201 and keeps '
      'nothing cannot stop it, and no receipt counts from a witness that has '
      'not agreed to witness it or answers in another\'s name', () async {
    client.answerTheNextCommit = (201, '');
    w3.witnessesOnly = {};
    w2.namesAnother = true;
    final rot = await makes().rotate(seed,
        aid: aid,
        generation: generation,
        afterSn: tip.sn,
        afterDigest: tip.digest,
        toad: 2,
        witnessedBy: set);
    generation++;
    tip = (sn: rot.sn, digest: rot.digest);
    expect(rot.witnessed!.receipts.keys, [w1.aid]);
    expect(rot.witnessed!.unreached, {w2.aid, w3.aid});
    final kept = await TheEventsThisDeviceSigned().unfinished(aid);
    expect([for (final r in kept) (r.recorded, r.witnessed)], [(true, false)],
        reason: 'the core said it had it; one receipt of two is not enough');

    w3.witnessesOnly = null;
    w2.namesAnother = false;
    final again = await makes().finishSigned(aid, witnessedBy: set);
    expect(again.single.witnessed!.receipts, hasLength(3));
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty);
    // The signed rotation is portable: it goes to the core as it went to the
    // witnesses.
    await commitTo(base, rot.bytesB64, rot.signatures);
  });

  test(
      'a place_taken the witnesses do not confirm is the core withholding the '
      'event: it goes to the witnesses and is kept', () async {
    client.answerTheNextCommit = (409, 'place_taken');
    late TheCoreWithholdsThisEvent withheld;
    try {
      await makes().interact(seed,
          aid: aid,
          generation: generation,
          afterSn: tip.sn,
          afterDigest: tip.digest,
          anchors: anchor,
          witnessedBy: set);
      fail('a faked place_taken was believed');
    } on TheCoreWithholdsThisEvent catch (e) {
      withheld = e;
    }
    expect(withheld.witnessed.enough, isTrue,
        reason: 'the witnesses took the event from the app');
    expect(withheld.reservation.witnessed, isTrue);
    expect(withheld.reservation.recorded, isFalse);
    // The core never got it: it is kept until it does, and finishing commits
    // it there too.
    final finished = await makes().finishSigned(aid, witnessedBy: set);
    expect(finished.single.status, 'recorded');
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty);
    tip = (sn: finished.single.sn, digest: finished.single.digest);
  });

  test(
      'a place_taken the witnesses confirm, with another event this phrase '
      'signed, lets this device\'s event go', () async {
    // Another device with the same phrase signed a different interaction at
    // the next place, and the witnesses hold it.
    final rival = await signedInteraction(
        client, base, km, seed, aid, generation, tip, another);
    for (final w in [w1, w2, w3]) {
      await w.hold(aid, rival);
    }
    client.answerTheNextCommit = (409, 'place_taken');
    await expectLater(
        makes().interact(seed,
            aid: aid,
            generation: generation,
            afterSn: tip.sn,
            afterDigest: tip.digest,
            anchors: anchor,
            witnessedBy: set),
        throwsA(isA<ThePlaceIsTaken>()
            .having((e) => e.held.length, 'witnesses confirming', 3)));
    expect(await TheEventsThisDeviceSigned().unfinished(aid), isEmpty,
        reason: 'this device\'s event at the taken place is dead');
    // The witnesses' copies now run past the core's: the rest of these tests
    // use a new identity.
  });

  test(
      'a place_taken the witnesses "confirm" with an event that does not '
      'verify is not believed', () async {
    final s2 = Bip39.mnemonicToSeed(
        'legal winner thank year wave sausage worth useful legal winner thank yellow'
            .split(' '));
    final more = await anotherCore(bin, km);
    addTearDown(more.close);
    final m = more.makes(witnesses);
    final founded = await m.found(s2, witnesses: [w1.aid, w2.aid], toad: 2);
    final s = WitnessSet([w1.aid, w2.aid], 2);
    // A rival signed with a key that is not this identity's.
    final forged = await signedInteraction(
        more.client,
        more.base,
        more.km,
        Bip39.mnemonicToSeed(
            'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' ')),
        founded.aid,
        0,
        (sn: 0, digest: founded.digest),
        another);
    for (final w in [w1, w2]) {
      await w.hold(founded.aid, forged);
    }
    more.client.answerTheNextCommit = (409, 'place_taken');
    await expectLater(
        m.interact(s2,
            aid: founded.aid,
            generation: 0,
            afterSn: 0,
            afterDigest: founded.digest,
            anchors: anchor,
            witnessedBy: s),
        throwsA(isA<TheCoreWithholdsThisEvent>()));
  });

  test(
      'an event the core refuses for good holds its place until the person lets '
      'it go, which needs enough witnesses to show no copy of the log has it',
      () async {
    final s3 = Bip39.mnemonicToSeed(
        'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
            .split(' '));
    final more = await anotherCore(bin, km);
    addTearDown(more.close);
    final m = more.makes(witnesses);
    // One receipt establishes an event, so all three must show they lack one
    // before it may be let go.
    final s = WitnessSet([w1.aid, w2.aid, w3.aid], 1);
    final founded =
        await m.found(s3, witnesses: [w1.aid, w2.aid, w3.aid], toad: 1);
    final at = (sn: 0, digest: founded.digest);
    void reach(bool on) {
      for (final w in [w1, w2, w3]) {
        w.offline = !on;
      }
    }

    // Refused, and no witness could be reached to take it either.
    reach(false);
    more.client.answerTheNextCommit = (403, 'not_authorised');
    await expectLater(
        m.interact(s3,
            aid: founded.aid,
            generation: 0,
            afterSn: at.sn,
            afterDigest: at.digest,
            anchors: anchor,
            witnessedBy: s),
        throwsA(isA<AnEventWasRefused>()
            .having((e) => e.refusal.code, 'code', 'not_authorised')));
    // It is shown again, not committed again, and nothing else is signed at
    // its place.
    await expectLater(m.finishSigned(founded.aid, witnessedBy: s),
        throwsA(isA<AnEventWasRefused>()));
    await expectLater(
        m.interact(s3,
            aid: founded.aid,
            generation: 0,
            afterSn: at.sn,
            afterDigest: at.digest,
            anchors: another,
            witnessedBy: s),
        throwsA(isA<PlaceAlreadyReserved>()));

    // Any one of them would establish it, so all three must show they lack
    // it: two answering is not enough.
    w1.offline = false;
    w2.offline = false;
    await expectLater(
        m.letGoOf(founded.aid, 1, witnessedBy: s), throwsA(isA<StateError>()));
    reach(true);
    expect(await m.letGoOf(founded.aid, 1, witnessedBy: s), LetGo.released);

    final ixn = await m.interact(s3,
        aid: founded.aid,
        generation: 0,
        afterSn: at.sn,
        afterDigest: at.digest,
        anchors: another,
        witnessedBy: s);
    expect(ixn.sn, 1);
    expect(ixn.witnessed!.enough, isTrue);

    // A core that adds an event and answers that it refused it: the event
    // still goes to the witnesses, who take it, so it is in the log.
    more.client.replaceTheNextCommitsAnswer = (403, 'not_authorised');
    final withheld = await m
        .interact(s3,
            aid: founded.aid,
            generation: 0,
            afterSn: ixn.sn,
            afterDigest: ixn.digest,
            anchors: anchor,
            witnessedBy: s)
        .then<Object>((c) => c, onError: (Object e) => e);
    expect(withheld, isA<TheCoreWithholdsThisEvent>());
    expect((withheld as TheCoreWithholdsThisEvent).witnessed.enough, isTrue);
    // Kept until the core says it has it, which it does when asked again.
    expect((await m.finishSigned(founded.aid, witnessedBy: s)).single.status,
        'already_recorded');
    expect(await TheEventsThisDeviceSigned().unfinished(founded.aid), isEmpty);
    final tip2 = withheld.reservation;

    // Refused while the witnesses were out of reach, though one of them
    // already had it: letting it go finds it in the log, and sends it on.
    reach(false);
    more.client.replaceTheNextCommitsAnswer = (403, 'not_authorised');
    Reservation? refused;
    try {
      await m.interact(s3,
          aid: founded.aid,
          generation: 0,
          afterSn: tip2.sn,
          afterDigest: tip2.digest,
          anchors: another,
          witnessedBy: s);
    } on AnEventWasRefused catch (e) {
      refused = e.reservation;
    }
    reach(true);
    await witnesses.receipt(
        aid: founded.aid,
        sn: refused!.sn,
        digest: refused.digest,
        bytesB64: refused.bytesB64,
        sigs: refused.signatures,
        set: WitnessSet([w1.aid], 1));
    expect(await m.letGoOf(founded.aid, 3, witnessedBy: s), LetGo.itIsInTheLog);
    expect(w2.held[founded.aid], hasLength(4),
        reason: 'found in one copy, it was sent to the other witnesses');
    // No longer refused: finishing commits it to the core, which has it.
    expect((await m.finishSigned(founded.aid, witnessedBy: s)).single.status,
        'already_recorded');
    expect(await TheEventsThisDeviceSigned().unfinished(founded.aid), isEmpty);
  });

  test(
      'a witness is counted once, by its one spelling, and at least one must '
      'receipt an event wherever there are witnesses', () {
    final s =
        WitnessSet([w1.aid, w1.aid, 'D${w2.aid.substring(1)}', w2.aid], 0);
    expect(s.witnesses, [w1.aid, w2.aid]);
    expect((s.toEstablish, s.toRuleOut), (1, 2));
    expect((WitnessSet.none.toEstablish, WitnessSet.none.toRuleOut), (0, 1));
    final four = WitnessSet([w1.aid, w2.aid, w3.aid, 'B${'A' * 43}'], 2);
    expect((four.toEstablish, four.toRuleOut), (2, 3));
    // The engine refuses a threshold of zero where witnesses are named; were
    // one to reach this device, no receipt would still not be enough.
    expect(Witnessed(WitnessSet([w1.aid], 0), {}, {}, {}).enough, isFalse);
    expect(Witnessed(WitnessSet([w1.aid], 0), {w1.aid: 'sig'}, {}, {}).enough,
        isTrue);
  });

  test(
      'a tip_moved before signing is prepared again after the tip read again, '
      'three times at most, and never for a recovery rotation', () async {
    final s4 = Bip39.mnemonicToSeed(
        'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'.split(' '));
    final more = await anotherCore(bin, km);
    addTearDown(more.close);
    var reads = 0;
    late Place at;
    var inForce = 0;
    final m = TheKeyEventsThisDeviceMakes(more.client, more.base, km,
        readTheKeyState: (_) async {
      reads++;
      return (
        tip: at,
        generation: inForce,
        witnesses: WitnessSet.none,
        keys: [KeyManager.publicKeyAt(s4, inForce)]
      );
    }, retryDelays: const [Duration.zero, Duration.zero, Duration.zero]);
    final founded = await m.found(s4);
    at = (sn: 0, digest: founded.digest);

    more.client.movePrepares = 2;
    final ixn = await m.interact(s4,
        aid: founded.aid,
        generation: 0,
        afterSn: 0,
        afterDigest: founded.digest,
        anchors: anchor);
    // One read says the identity is at stage one, then one per retry.
    expect((ixn.sn, reads), (1, 3));
    at = (sn: 1, digest: ixn.digest);

    more.client.movePrepares = 4;
    reads = 0;
    await expectLater(
        m.interact(s4,
            aid: founded.aid,
            generation: 0,
            afterSn: 1,
            afterDigest: ixn.digest,
            anchors: another),
        throwsA(isA<TheLogKeepsMoving>()
            .having((e) => e.rotatedElsewhere, 'rotated elsewhere', false)));
    expect(reads, 4);
    more.client.movePrepares = 0;

    // Read again, the keys in force are another generation's: another device
    // rotated, and nothing is signed with the old key.
    more.client.movePrepares = 1;
    inForce = 1;
    await expectLater(
        m.interact(s4,
            aid: founded.aid,
            generation: 0,
            afterSn: 1,
            afterDigest: ixn.digest,
            anchors: another),
        throwsA(isA<TheLogKeepsMoving>()
            .having((e) => e.rotatedElsewhere, 'rotated elsewhere', true)));
    inForce = 0;

    more.client.movePrepares = 1;
    reads = 0;
    await expectLater(
        m.rotate(s4,
            aid: founded.aid,
            generation: 0,
            afterSn: 0,
            afterDigest: founded.digest,
            recovery: true),
        throwsA(
            isA<KeyEventRefused>().having((e) => e.code, 'code', 'tip_moved')));
    expect(reads, 1,
        reason: 'one read says what stage it is at, and a recovery rotation '
            'is never moved to the tip after it');
    expect(await TheEventsThisDeviceSigned().unfinished(founded.aid), isEmpty,
        reason: 'nothing was signed for an event the core would not prepare');
  });
}
