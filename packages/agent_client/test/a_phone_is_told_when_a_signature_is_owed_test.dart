import 'package:agent_client/services/ownership_changes_in_progress.dart';
import 'package:agent_client/services/owed_signatures.dart';
import 'package:agent_client/services/the_ceremony_this_device_agreed_to.dart';
import 'package:agent_client/services/the_event_this_device_expects.dart' show CeremonyStage;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:test/test.dart';

// A phone whose Identity Agent app is closed finds out, by looking at what the
// organisation publishes for the code it was invited with, that a signature is
// owed to a change of owners, and tells its person once for each rotation. It
// forgets a change that is over, says once that one stopped, and signs nothing.

class Told implements TellsThePerson {
  final owed = <String>[];
  final stopped = <String>[];
  final takenBack = <String>[];
  @override
  Future<void> signatureIsOwed(AnOwnershipChange c, {required int rotation, required bool handOver}) async =>
      owed.add('${c.orgName}:$rotation:$handOver');
  @override
  Future<void> changeStopped(AnOwnershipChange c) async => stopped.add(c.orgName);
  @override
  Future<void> takeBack(AnOwnershipChange c) async => takenBack.add(c.orgName);
}

class Said implements RemembersWhatWasSaid {
  final keys = <String>{};
  @override
  Future<bool> was(String key) async => keys.contains(key);
  @override
  Future<void> remember(String key) async => keys.add(key);
}

CeremonyTerms terms(CeremonyStage stage, {bool handOver = true, required Map<String, bool> signed}) =>
    CeremonyTerms(
      stage: stage,
      handOver: handOver,
      threshold: 2,
      aid: 'EOrg',
      sn: 1,
      prior: 'P',
      digest: 'D',
      ownKey: '',
      ownNextDigests: const [],
      toad: 0,
      cuts: const [],
      adds: const [],
      anchors: const [],
      owners: [
        for (final e in signed.entries)
          CeremonyTermsOwner(name: e.key, aid: 'A-${e.key}', key: 'k', next: const [], signed: e.value),
      ],
    );

AnOwnershipChange change(String org, {String me = 'A-me', String token = 'tok'}) =>
    AnOwnershipChange(orgUrl: 'https://$org.example', token: '$token-$org', me: me, orgName: org);

void main() {
  late OwnershipChangesInProgress store;
  late Told told;
  late Said said;

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    store = OwnershipChangesInProgress();
    told = Told();
    said = Said();
  });

  OwedSignatures look(Map<String, CeremonyReading?> answers) => OwedSignatures(
        changes: store,
        read: (url, token) async {
          final a = answers[token];
          if (a == null && !answers.containsKey(token)) throw Exception('unreachable');
          return a;
        },
        tells: told,
        said: said,
      );

  test('a signature that is owed is told once for the rotation, however often the phone looks', () async {
    final c = change('Acme');
    await store.add(c);
    // Owners are named 'A-<name>' and this phone is 'A-me'.
    final w = look({c.token: CeremonyReading('signing', terms(CeremonyStage.first, signed: {'me': false, 'Bob': true}))});
    final first = await w.look();
    await w.look();
    await w.look();
    expect(first.owed.map((x) => x.orgName), ['Acme']);
    expect(told.owed, ['Acme:1:true']);
  });

  test('the second rotation of a hand-over is told again, once', () async {
    final c = change('Acme');
    await store.add(c);
    final w = look({c.token: CeremonyReading('signing', terms(CeremonyStage.first, signed: {'me': false}))});
    await w.look();
    final w2 = look({c.token: CeremonyReading('signing', terms(CeremonyStage.second, signed: {'me': false}))});
    await w2.look();
    await w2.look();
    expect(told.owed, ['Acme:1:true', 'Acme:2:true']);
  });

  test('nothing is told once this phone has signed, and a notice already shown is taken back', () async {
    final c = change('Acme');
    await store.add(c);
    final w = look({c.token: CeremonyReading('signing', terms(CeremonyStage.first, signed: {'me': true, 'Bob': false}))});
    final found = await w.look();
    expect(found.owed, isEmpty);
    expect(told.owed, isEmpty);
    expect(told.takenBack, ['Acme']);
  });

  test('nothing is told while the others have still to accept', () async {
    final c = change('Acme');
    await store.add(c);
    await look({c.token: const CeremonyReading('collecting', null)}).look();
    expect(told.owed, isEmpty);
    expect(await store.all(), hasLength(1));
  });

  test('a change that was made is forgotten and takes back its notice without a word', () async {
    final c = change('Acme');
    await store.add(c);
    final found = await look({c.token: const CeremonyReading('applied', null)}).look();
    expect(found.ended, hasLength(1));
    expect(await store.all(), isEmpty);
    expect(told.takenBack, ['Acme']);
    expect(told.stopped, isEmpty);
  });

  test('a change that failed or was dropped is forgotten and said once', () async {
    final a = change('Acme'), b = change('Beta');
    await store.add(a);
    await store.add(b);
    final answers = {
      a.token: const CeremonyReading('failed', null, detail: 'the identity\'s own signature was refused: a technical reason'),
      b.token: const CeremonyReading('abandoned', null),
    };
    await look(answers).look();
    await look(answers).look();
    // Said once each, and nothing of why: the organisation's words are for the screen the person opens.
    expect(told.stopped, ['Acme', 'Beta']);
    expect(await store.all(), isEmpty);
  });

  test('a change the organisation no longer knows is forgotten and said stopped', () async {
    final c = change('Acme');
    await store.add(c);
    await look({c.token: null}).look();
    expect(told.stopped, ['Acme']);
    expect(await store.all(), isEmpty);
  });

  test('an organisation that cannot be reached changes nothing and says nothing', () async {
    final c = change('Acme');
    await store.add(c);
    await look({}).look();
    expect(told.owed, isEmpty);
    expect(told.stopped, isEmpty);
    expect(await store.all(), hasLength(1));
  });

  test('a phone that is not one of the owners named is not told', () async {
    final c = change('Acme', me: 'A-someone-else');
    await store.add(c);
    await look({c.token: CeremonyReading('signing', terms(CeremonyStage.first, signed: {'me': false}))}).look();
    expect(told.owed, isEmpty);
  });

  test('each change is told on its own', () async {
    final a = change('Acme'), b = change('Beta');
    await store.add(a);
    await store.add(b);
    final t = terms(CeremonyStage.first, signed: {'me': false});
    await look({a.token: CeremonyReading('signing', t), b.token: CeremonyReading('signing', t)}).look();
    expect(told.owed.toSet(), {'Acme:1:true', 'Beta:1:true'});
  });

  test('the notice carries an identifier that is not the code and does not change', () {
    final c = change('Acme');
    final id = ownershipChangeNoticeId(c);
    expect(id, hasLength(16));
    expect(id, isNot(contains(c.token)));
    expect(ownershipChangeNoticeId(c), id);
    expect(ownershipChangeNoticeId(change('Beta')), isNot(id));
    expect(ownershipChangeNoticeNumber(c), ownershipChangeNoticeNumber(c));
  });

}
