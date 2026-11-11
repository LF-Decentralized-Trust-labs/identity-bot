import 'dart:io';

import 'package:agent_client/services/controller_signing_client.dart'
    show VouchedAuthentication;
import 'package:agent_client/services/identity_profiles.dart';
import 'package:agent_client/services/local_auth_service.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:agent_client/services/profile_scope.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
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
  final realOpenOneHolds = IdentityProfiles.openOneHoldsAnIdentity;
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
      IdentityProfiles.providerOnThisDevice = null;
      IdentityProfiles.vouchedByThePersonsDevice = null;
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

    test(
        'it is offered by name while locked, and opens only after '
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

    test('logging out locks EVERY identity on the device, and each needs its '
        'own person', () async {
      final first = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      IdentityProfiles.authenticateOwner = (_) async => true;
      await IdentityProfiles.openAfterAuthenticating(first);
      final second = await IdentityProfiles.beginANewOne();
      await IdentityProfiles.remember(aid: 'Bchild', name: 'Ben');
      expect(await IdentityProfiles.isLocked(first), isFalse);
      expect(await IdentityProfiles.isLocked(second), isFalse);

      // The child logs out; the parent's identity locks too.
      await IdentityProfiles.lockTheOpenOne(aid: 'Bchild', name: 'Ben');
      expect(await IdentityProfiles.isLocked(second), isTrue);
      expect(await IdentityProfiles.isLocked(first), isTrue,
          reason: 'any logout locks every identity on the device');
    });

    test('the list says who is asked and why only when something is locked',
        () {
      expect(IdentityProfiles.listNotice(lockedNames: [], noScreenLock: false),
          isNull);
      final one = IdentityProfiles.listNotice(
          lockedNames: ['Ada'], noScreenLock: false)!;
      expect(one, startsWith('Logging out locked everything'));
      expect(one, contains('Ada is asked to authenticate'));
      final two = IdentityProfiles.listNotice(
          lockedNames: ['Ada', 'Ben'], noScreenLock: true)!;
      expect(two, contains('Each owner is asked'));
      expect(two, contains('has no screen lock'));
      expect(
          IdentityProfiles.listNotice(
              lockedNames: [], noScreenLock: true, what: 'organisation'),
          contains('this organisation'));
    });

    group('getting back in', () {
      final now = DateTime.now().toUtc();
      test('80 opens, 79 does not, an unmeasured or stale one does not', () {
        bool opens(int score,
                {bool measured = true,
                DateTime? at,
                bool vouching = false,
                String by = ''}) =>
            IdentityProfiles.scoreOpens(
                measured: measured,
                score: score,
                at: at ?? now,
                needsVouching: vouching,
                vouchedBy: by,
                now: now);
        expect(opens(80), isTrue);
        expect(opens(79), isFalse);
        expect(opens(100, measured: false), isFalse);
        expect(opens(100, at: now.subtract(const Duration(minutes: 5))),
            isFalse);
        expect(opens(100, at: now.add(const Duration(minutes: 5))), isFalse);
        expect(opens(100, at: now.add(const Duration(seconds: 10))), isTrue,
            reason: 'a phone a few seconds fast is not refused');
        // A computer may not score itself.
        expect(opens(100, vouching: true), isFalse);
        expect(opens(100, vouching: true, by: 'sig'), isTrue);
      });

      test('with a provider, a failed score is not rescued by the screen lock',
          () async {
        final id = await ProfileScope.activeId();
        await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
        var screenLockAsked = false;
        IdentityProfiles.authenticateOwner = (_) async {
          screenLockAsked = true;
          return true;
        };
        IdentityProfiles.providerOnThisDevice = (_) async => MeasuredScore(
            measured: true, score: 79, at: DateTime.now().toUtc());
        IdentityProfiles.vouchedByThePersonsDevice = (_) async =>
            VouchedAuthentication(
                level: 'verified',
                at: DateTime.now().toUtc(),
                score: 79,
                vouchedBy: 'sig');
        addTearDown(() {
          IdentityProfiles.providerOnThisDevice = null;
          IdentityProfiles.vouchedByThePersonsDevice = null;
        });
        expect(await IdentityProfiles.openAfterAuthenticating(id), isFalse);
        expect(screenLockAsked, isFalse);
        expect(await IdentityProfiles.isLocked(id), isTrue);

        IdentityProfiles.providerOnThisDevice = (_) async => MeasuredScore(
            measured: true, score: 85, at: DateTime.now().toUtc());
        IdentityProfiles.vouchedByThePersonsDevice = (_) async =>
            VouchedAuthentication(
                level: 'verified',
                at: DateTime.now().toUtc(),
                score: 85,
                vouchedBy: 'sig');
        expect(await IdentityProfiles.openAfterAuthenticating(id), isTrue);
      });

      test('with no provider the screen lock stands in, and the lock screen '
          'says nothing measured the person', () {
        expect(IdentityProfiles.howItWillBeChecked(),
            UnlockMethod.deviceScreenLockNoProvider);
        final text = IdentityProfiles.lockScreenExplanation('Ada');
        expect(text, contains('Ada'));
        expect(text, contains('nothing has measured who you are'));
        expect(text, contains('locked everything on this device'));
        expect(IdentityProfiles.lockScreenExplanation('Acme', what: 'organisation'),
            contains('this organisation can only'));
        expect(
            IdentityProfiles.lockScreenExplanation('Ada',
                method: UnlockMethod.providerVouchedByAnotherDevice),
            contains('phone or black box'));
      });
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

    test(
        'creating after logging out begins a second profile and leaves the '
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

    test('a stop that fails is reported, and the identity stays locked',
        () async {
      final id = await ProfileScope.activeId();
      IdentityProfiles.coreStopper = () async => throw Exception('refused');
      await expectLater(IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada'),
          throwsA(isA<TheCoreDidNotStop>()));
      expect(await IdentityProfiles.isLocked(id), isTrue,
          reason: 'the marker is not undone by a stop that did not work');
    });

    test('an open that fails stops the core it started, and locks again',
        () async {
      final id = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      stopped = 0;
      // The start gets as far as having a core, then fails after it.
      IdentityProfiles.coreStarter = (_) async => throw Exception('late');
      await expectLater(
          IdentityProfiles.openAfterAuthenticating(id), throwsException);
      expect(stopped, greaterThanOrEqualTo(2),
          reason: 'once leaving the old, once after the failure');
      expect(await IdentityProfiles.isLocked(id), isTrue);
    });

    group('is the open profile occupied (decided locally, failing closed)', () {
      setUp(() {
        FlutterSecureStorage.setMockInitialValues({});
        IdentityProfiles.openOneHoldsAnIdentity = realOpenOneHolds;
        SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
      });
      tearDown(SecureKeyStore.holdPhraseInTheCore);

      test('an empty profile is not', () async {
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isFalse);
      });
      test('a card means it is', () async {
        await IdentityProfiles.remember(aid: one, name: 'Ada');
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isTrue);
      });
      test('a lock marker means it is', () async {
        await IdentityProfiles.lockTheOpenOne();
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isTrue);
      });
      test('a held phrase means it is', () async {
        await SecureKeyStore.saveMnemonic(['abandon', 'about']);
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isTrue);
      });
      test('a data directory with an identity in it means it is, with no card, '
          'lock or phrase', () async {
        // A desktop controller profile, or one founded before cards existed
        // and never logged out: nothing but the core's own files says so.
        final id = await ProfileScope.activeId();
        final data = await IdentityProfiles.dataDirectoryFor(id);
        File('$data${Platform.pathSeparator}.port').writeAsStringSync('1');
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isFalse,
            reason: 'the files that only say where a core listens are not an '
                'identity');
        File('$data${Platform.pathSeparator}identity.db').writeAsStringSync('x');
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isTrue);
        expect(await IdentityProfiles.makeRoomForANewOne(), isTrue,
            reason: 'Create must not found where an identity already is');
        expect(await ProfileScope.activeId(), isNot(id));
      });
      test('a core that cannot be asked is not an empty profile', () async {
        SecureKeyStore.holdPhraseWith(_ARefusingHolder());
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isTrue,
            reason: 'an error must begin a new profile, never found in the '
                'occupied one');
        final first = await ProfileScope.activeId();
        expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
        expect(await ProfileScope.activeId(), isNot(first));
      });
    });

    test('a founding this run started is resumed, not abandoned', () async {
      final id = await ProfileScope.activeId();
      IdentityProfiles.openOneHoldsAnIdentity = () async => true;
      expect(await IdentityProfiles.foundingWasStarted(), isFalse);
      await IdentityProfiles.markFoundingStarted();
      expect(await IdentityProfiles.foundingWasStarted(), isTrue);
      expect(await IdentityProfiles.makeRoomForANewOne(), isFalse,
          reason: 'its words are held in this profile');
      expect(await ProfileScope.activeId(), id);
      await IdentityProfiles.clearFoundingMarker();
      expect(await IdentityProfiles.foundingWasStarted(), isFalse);
    });

    test('the founding marker names the identity the core prepared', () async {
      expect(await IdentityProfiles.foundingAid(), isNull);
      await IdentityProfiles.markFoundingStarted();
      expect(await IdentityProfiles.foundingWasStarted(), isTrue);
      expect(await IdentityProfiles.foundingAid(), isNull,
          reason: 'started, but the core has prepared nothing yet');
      await IdentityProfiles.recordFoundingAid('EPrepared');
      expect(await IdentityProfiles.foundingAid(), 'EPrepared');
      await IdentityProfiles.markFoundingStarted();
      expect(await IdentityProfiles.foundingAid(), 'EPrepared',
          reason: 'a retry keeps the identifier an earlier run recorded');
      await IdentityProfiles.clearFoundingMarker();
      expect(await IdentityProfiles.foundingAid(), isNull);
    });

    test('a profile id that is not a profile id names no directory', () async {
      for (final bad in ['../evil', '/etc', 'a/b', '..', '', r'a\b']) {
        await expectLater(
            IdentityProfiles.directoryFor(bad), throwsArgumentError,
            reason: bad);
      }
      expect(await IdentityProfiles.directoryFor('abcdefghij12'),
          startsWith(root.path));
    });
  });

  group('no screen lock', () {
    test('local_auth\'s not-enrolled and passcode-not-set are no lock', () {
      for (final c in ['NotEnrolled', 'PasscodeNotSet', 'passcodeNotSet']) {
        expect(LocalAuthService.isNoScreenLockCode(c), isTrue, reason: c);
      }
      expect(LocalAuthService.isNoScreenLockCode('LockedOut'), isFalse);
      expect(LocalAuthService.isNoScreenLockCode('auth_in_progress'), isFalse);
    });

    test('the message says so plainly and where to set one, per platform', () {
      final where = {
        'android': 'Android Settings > Security > Screen lock',
        'ios': 'iOS Settings > Face ID & Passcode',
        'windows': 'Windows Settings > Accounts > Sign-in options',
        'macos': 'macOS System Settings > Lock Screen / Touch ID & Password',
      };
      where.forEach((os, text) {
        final m = IdentityProfiles.noScreenLockMessage(platform: os);
        expect(m, contains('no screen lock'));
        final computer = os == 'windows' || os == 'macos';
        expect(m, contains(computer ? 'anyone using it can open this identity'
            : 'anyone holding it can open this identity'));
        expect(m, contains(text));
      });
    });

    test('an organisation says "this organisation", never "this identity"', () {
      final m = IdentityProfiles.noScreenLockMessage(
          platform: 'macos', what: 'organisation');
      expect(m, contains('can open this organisation'));
      expect(m, isNot(contains('this identity')));
    });

    test('a log-out that failed says so in plain words, not the exception',
        () async {
      final said = <String>[];
      final went = await IdentityProfiles.logOutAndTell(
          what: 'organisation',
          logOut: () async =>
              throw const TheCoreDidNotStop('SocketException: connection reset by 127.0.0.1:5050'),
          say: (title, body) async => said.add('$title|$body'));
      expect(went, isFalse);
      expect(said.single, startsWith('Not logged out|'));
      expect(said.single, contains('this organisation'));
      expect(said.single, isNot(contains('Socket')));
      expect(said.single, isNot(contains('5050')));
    });
  });
}

class _ARefusingHolder implements PhraseHolder {
  @override
  Future<void> hold(String phrase, {bool replacing = false}) async =>
      throw StateError('no core');
  @override
  Future<String?> open() async => throw StateError('no core');
  @override
  Future<bool> isHeld() async => throw StateError('no core');
  @override
  Future<String?> protection() async => throw StateError('no core');
  @override
  Future<bool> forget() async => throw StateError('no core');
}
