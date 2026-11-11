import 'dart:io';

import 'package:agent_client/services/identity_profiles.dart';
import 'package:agent_client/services/profile_scope.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

/// Which identity is open, and which one was deliberately left.
///
/// These two decisions are what signing out depends on, and the obvious
/// implementation of each is wrong in a way that only shows up on the NEXT
/// start-up — which is the worst place to find it. They are separated from
/// where the answers are stored so they can be examined directly; the storage
/// and the paths need a device and are exercised there.
void main() {
  const one = 'EIdentityOne';
  const two = 'EIdentityTwo';

  group('is this the identity we were in', () {
    test('a first run is let through, having nothing to contradict it', () {
      // Refusing the only identity present because nothing has been written
      // down yet would make a fresh install look broken.
      expect(IdentityProfiles.decideIsTheOneWeWereIn(null, one), isTrue);
      expect(IdentityProfiles.decideIsTheOneWeWereIn('', one), isTrue);
    });

    test('the one we were in is recognised again', () {
      expect(IdentityProfiles.decideIsTheOneWeWereIn(one, one), isTrue);
    });

    test('a different identity at the same address is not ours', () {
      // The reason an address is not an identity: same machine, same port,
      // somebody else's Identity Agent answering.
      expect(IdentityProfiles.decideIsTheOneWeWereIn(one, two), isFalse);
    });
  });

  group('did we leave this identity', () {
    test('signing out does not make the identity a stranger', () {
      // The trap, and the reason these are two separate questions. After
      // signing out the identity is still RECOGNISED — it is still the one we
      // were in, and has not been handed to anybody. Only the choice to leave
      // changed.
      //
      // If signing out were implemented by forgetting which identity was
      // opened, this pair would read (true, false): a forgotten identity is a
      // first run, a first run is let through, and somebody who signed out
      // would be signed straight back in on the next start-up.
      expect(IdentityProfiles.decideIsTheOneWeWereIn(one, one), isTrue);
      expect(IdentityProfiles.decideDidWeLeave(one, one), isTrue);
    });

    test('an identity nobody left opens normally', () {
      expect(IdentityProfiles.decideDidWeLeave(null, one), isFalse);
    });

    test('leaving one identity does not lock out another', () {
      // Why what is stored is WHICH identity rather than a flag. Point this
      // installation at a different identity afterwards and that one was never
      // left, so it should open.
      expect(IdentityProfiles.decideDidWeLeave(one, two), isFalse);
    });

    test('an empty identity is never one we left', () {
      expect(IdentityProfiles.decideDidWeLeave(one, ''), isFalse);
      expect(IdentityProfiles.decideDidWeLeave(null, ''), isFalse);
    });
  });

  group('logging out locks an identity and a new one gets its own profile', () {
    late Directory root;
    late List<String> started;
    var stopped = 0;

    setUp(() async {
      SharedPreferences.setMockInitialValues({});
      ProfileScope.resetCacheForTest();
      root = Directory.systemTemp.createTempSync('profiles_test');
      IdentityProfiles.rootOverride = root.path;
      started = [];
      stopped = 0;
      IdentityProfiles.coreStarter = (dir) async => started.add(dir);
      IdentityProfiles.coreStopper = () async => stopped++;
      IdentityProfiles.openOneHoldsAnIdentity = () async => true;
      IdentityProfiles.authenticateOwner = (_) async => true;
    });

    tearDown(() {
      IdentityProfiles.rootOverride = null;
      IdentityProfiles.coreStarter = null;
      IdentityProfiles.coreStopper = null;
      root.deleteSync(recursive: true);
    });

    test('a logged-out identity is not started again, on launch or resume',
        () async {
      final id = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      expect(stopped, 1);
      expect(await IdentityProfiles.isLocked(id), isTrue);

      await IdentityProfiles.startTheActiveOne();
      expect(started, isEmpty,
          reason: 'starting a locked identity puts it back within reach '
              'without its owner having authenticated');
    });

    test('it is offered by name while locked, and opens only after '
        'authenticating', () async {
      final id = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      final offered = await IdentityProfiles.all();
      expect(offered.map((p) => p.name), ['Ada']);

      IdentityProfiles.authenticateOwner = (_) async => false;
      expect(await IdentityProfiles.openAfterAuthenticating(id), isFalse);
      expect(await IdentityProfiles.isLocked(id), isTrue);
      expect(started, isEmpty);

      IdentityProfiles.authenticateOwner = (_) async => true;
      expect(await IdentityProfiles.openAfterAuthenticating(id), isTrue);
      expect(await IdentityProfiles.isLocked(id), isFalse);
      expect(started, hasLength(1));
    });

    test('a locked identity whose agent will not start is locked again',
        () async {
      final id = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      IdentityProfiles.coreStarter = (_) async => throw Exception('no');
      await expectLater(
          IdentityProfiles.openAfterAuthenticating(id), throwsException);
      expect(await IdentityProfiles.isLocked(id), isTrue);
    });

    test('creating after logging out begins a second profile and leaves the '
        'first where it was', () async {
      final first = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      IdentityProfiles.openOneHoldsAnIdentity = () async => false;

      expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
      final second = await ProfileScope.activeId();
      expect(second, isNot(first));
      expect(started.single, contains(second),
          reason: 'the new profile is the one whose core was started');
      expect(await IdentityProfiles.isLocked(first), isTrue);
      expect(await IdentityProfiles.isLocked(second), isFalse);
    });

    test('an empty profile is reused, and one holding an identity is not',
        () async {
      IdentityProfiles.openOneHoldsAnIdentity = () async => false;
      expect(await IdentityProfiles.makeRoomForANewOne(), isFalse);
      IdentityProfiles.openOneHoldsAnIdentity = () async => true;
      expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
    });
  });
}
