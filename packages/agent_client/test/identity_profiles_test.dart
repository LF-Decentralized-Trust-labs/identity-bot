import 'dart:io';

import 'package:agent_client/services/identity_profiles.dart';
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
    late _FakeDevice device;
    var stopped = 0;

    setUp(() async {
      SharedPreferences.setMockInitialValues({});
      ProfileScope.resetCacheForTest();
      root = Directory.systemTemp.createTempSync('profiles_test');
      IdentityProfiles.rootOverride = root.path;
      started = [];
      stopped = 0;
      device = _FakeDevice();
      IdentityProfiles.coreStarter = (dir) async {
        started.add(dir);
        await device.start(dir);
      };
      IdentityProfiles.coreStopper = () async {
        stopped++;
        await device.stop();
      };
      IdentityProfiles.openOneHoldsAnIdentity = () async => true;
      IdentityProfiles.loginProvider = LoginProvider.fixedMinimum();
    });

    tearDown(() {
      IdentityProfiles.rootOverride = null;
      IdentityProfiles.coreStarter = null;
      IdentityProfiles.coreStopper = null;
      IdentityProfiles.loginProvider = LoginProvider.fixedMinimum();
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

      IdentityProfiles.loginProvider = _providerAnswering(79);
      expect(await IdentityProfiles.openAfterAuthenticating(id), isFalse);
      expect(await IdentityProfiles.isLocked(id), isTrue);
      expect(started, isEmpty);

      IdentityProfiles.loginProvider = LoginProvider.fixedMinimum();
      expect(await IdentityProfiles.openAfterAuthenticating(id), isTrue);
      expect(await IdentityProfiles.isLocked(id), isFalse);
      expect(started, hasLength(1));
    });

    test(
        'logging out locks EVERY identity on the device, and each needs its '
        'own person', () async {
      final first = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
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

    test(
        'the list says who logs in, and always that nothing measures them', () {
      expect(IdentityProfiles.listNotice(lockedNames: []),
          IdentityProfiles.placeholderProviderNotice,
          reason: 'the placeholder is named even when nobody is logged out');
      expect(
          IdentityProfiles.listNotice(
              lockedNames: [], method: UnlockMethod.provider),
          isNull);
      final one = IdentityProfiles.listNotice(lockedNames: ['Ada'])!;
      expect(one, contains('Only one identity is logged in on this device'));
      expect(one, contains('Choosing it logs Ada in'));
      expect(one, contains('No authentication provider is built yet'));
      expect(one, contains('nothing measures who you are'));
      expect(IdentityProfiles.listNotice(lockedNames: ['Ada', 'Ben']),
          contains('logs a person in'));
      expect(
          IdentityProfiles.listNotice(
              lockedNames: ['Acme'], what: 'organisation'),
          contains('Only one organisation is logged in'));
    });

    test(
        'with three identities on one phone, choosing each logs that one in '
        'and the others out', () async {
      final a = await ProfileScope.activeId();
      await IdentityProfiles.remember(aid: 'Aada', name: 'Ada');
      final b = await IdentityProfiles.beginANewOne();
      await IdentityProfiles.remember(aid: 'Bben', name: 'Ben');
      final c = await IdentityProfiles.beginANewOne();
      await IdentityProfiles.remember(aid: 'Ccat', name: 'Cat');
      // Everyone has been logged out, as a log-out does.
      await IdentityProfiles.lockTheOpenOne(aid: 'Ccat', name: 'Cat');

      Future<List<bool>> loggedIn() async => [
            for (final id in [a, b, c]) !await IdentityProfiles.isLocked(id)
          ];
      expect(await loggedIn(), [false, false, false]);

      for (final (i, id) in [a, b, c, a, c, b].indexed) {
        started.clear();
        expect(await IdentityProfiles.openAfterAuthenticating(id), isTrue,
            reason: 'tapping the profile logs that person in');
        final want = [
          for (final x in [a, b, c]) x == id
        ];
        expect(await loggedIn(), want,
            reason: 'step $i: only the chosen identity is logged in');
        expect(await ProfileScope.activeId(), id);
        expect(started.single, contains(id));
        expect(device.serving, {await IdentityProfiles.dataDirectoryFor(id)},
            reason: 'step $i: exactly the chosen profile\'s directory is '
                'served, so the previous core really stopped');
      }
    });

    test(
        'two identities opened at once leave only one unlocked and only that '
        'one served', () async {
      final a = await ProfileScope.activeId();
      await IdentityProfiles.remember(aid: 'Aada', name: 'Ada');
      final b = await IdentityProfiles.beginANewOne();
      await IdentityProfiles.remember(aid: 'Bben', name: 'Ben');
      await IdentityProfiles.lockTheOpenOne(aid: 'Bben', name: 'Ben');
      expect(await IdentityProfiles.isLocked(a), isTrue);
      expect(await IdentityProfiles.isLocked(b), isTrue);

      final both = await Future.wait([
        IdentityProfiles.openAfterAuthenticating(a),
        IdentityProfiles.openAfterAuthenticating(b),
      ]);
      expect(both, [true, true]);

      final active = await ProfileScope.activeId();
      final unlocked = [
        for (final id in [a, b])
          if (!await IdentityProfiles.isLocked(id)) id
      ];
      expect(unlocked, [active],
          reason: 'the one that is open is the only one not locked');
      expect(device.serving, {await IdentityProfiles.dataDirectoryFor(active)},
          reason: 'nothing locked is being served');
    });

    test('every identity is marked locked even when one cannot be marked',
        () async {
      final a = await ProfileScope.activeId();
      await IdentityProfiles.remember(aid: 'Aada', name: 'Ada');
      final b = await IdentityProfiles.beginANewOne();
      final c = await IdentityProfiles.beginANewOne();
      // b's marker cannot be written: a folder is where the file must go.
      Directory('${await IdentityProfiles.directoryFor(b)}/locked')
          .createSync(recursive: true);

      final said = <String>[];
      final went = await IdentityProfiles.logOutAndTell(
          logOut: () => IdentityProfiles.lockTheOpenOne(aid: 'Ccat', name: 'C'),
          say: (title, body) async => said.add(body));
      expect(went, isFalse);
      expect(await IdentityProfiles.isLocked(a), isTrue);
      expect(await IdentityProfiles.isLocked(c), isTrue,
          reason: 'one that cannot be marked does not stop the rest');
      expect(said.single, contains('could not be marked as logged out'));
      expect(said.single, isNot(contains('could not be stopped')));
    });

    test('an id that cannot name a directory counts as one not marked',
        () async {
      await ProfileScope.setActive('not a profile id');
      await expectLater(
          IdentityProfiles.lockTheOpenOne(),
          throwsA(isA<TheCoreDidNotStop>()
              .having((e) => e.notMarked, 'notMarked', isTrue)));
    });

    test('starting an identity on a locked device asks about the device\'s '
        'person, not about the locked profile', () async {
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      IdentityProfiles.openOneHoldsAnIdentity = () async => false;
      final asked = <String?>[];
      IdentityProfiles.loginProvider = LoginProvider(
          name: 'test',
          isPlaceholder: false,
          measure: (id) async {
            asked.add(id);
            return MeasuredScore(
                measured: true, score: 90, at: DateTime.now().toUtc());
          });
      expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
      expect(asked, [null]);
    });

    test('the words say what is true', () {
      final ada = IdentityProfiles.lockScreenExplanation('Ada',
          anotherIsOpen: false);
      expect(ada, isNot(contains('logs out the one that is open')));
      expect(IdentityProfiles.lockScreenExplanation('Ada'),
          contains('logs out the one that is open'));
      expect(IdentityProfiles.placeholderProviderNotice,
          contains('Anyone who taps a profile is logged in as that person'));
      expect(IdentityProfiles.placeholderProviderNotice,
          isNot(contains('minimum score')));
      expect(const NotAuthenticated().toString(),
          isNot(contains('You were not authenticated')));
      expect(const NotAuthenticated('organisation').toString(),
          contains('starting a new organisation'));
    });

    test('choosing a profile while another is logged in logs the other out',
        () async {
      final a = await ProfileScope.activeId();
      expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
      final b = await ProfileScope.activeId();
      // b is open and a was left behind: a is locked, b is not.
      expect(await IdentityProfiles.isLocked(a), isTrue);
      expect(await IdentityProfiles.isLocked(b), isFalse);
      expect(await IdentityProfiles.openAfterAuthenticating(a), isTrue);
      expect(await IdentityProfiles.isLocked(b), isTrue);
      expect(await IdentityProfiles.isLocked(a), isFalse);
    });

    test('the login provider is the placeholder and the screens say so', () {
      expect(IdentityProfiles.loginProvider.name, 'fixed-minimum');
      expect(IdentityProfiles.howItWillBeChecked(),
          UnlockMethod.placeholderProvider);
    });

    group('getting back in', () {
      final now = DateTime.now().toUtc();
      test('80 opens, 79 does not, an unmeasured or stale one does not', () {
        bool opens(int score, {bool measured = true, DateTime? at}) =>
            IdentityProfiles.scoreOpens(
                measured: measured, score: score, at: at ?? now, now: now);
        expect(opens(80), isTrue);
        expect(opens(79), isFalse);
        expect(opens(100, measured: false), isFalse);
        expect(
            opens(100, at: now.subtract(const Duration(minutes: 5))), isFalse);
        expect(opens(100, at: now.add(const Duration(minutes: 5))), isFalse);
        expect(opens(100, at: now.add(const Duration(seconds: 10))), isTrue,
            reason: 'a clock a few seconds fast is not refused');
      });

      test('a score under 80 does not log in, and nothing else rescues it',
          () async {
        final id = await ProfileScope.activeId();
        await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
        IdentityProfiles.loginProvider = _providerAnswering(79);
        expect(await IdentityProfiles.openAfterAuthenticating(id), isFalse);
        expect(await IdentityProfiles.isLocked(id), isTrue);
        IdentityProfiles.loginProvider = _providerAnswering(85);
        expect(await IdentityProfiles.openAfterAuthenticating(id), isTrue);
      });

      test('a provider that errors or says nothing does not log in', () async {
        final id = await ProfileScope.activeId();
        await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
        IdentityProfiles.loginProvider = LoginProvider(
            name: 'x',
            isPlaceholder: false,
            measure: (_) async => throw Exception('unreachable'));
        expect(await IdentityProfiles.openAfterAuthenticating(id), isFalse);
        IdentityProfiles.loginProvider = LoginProvider(
            name: 'x', isPlaceholder: false, measure: (_) async => null);
        expect(await IdentityProfiles.openAfterAuthenticating(id), isFalse);
        expect(await IdentityProfiles.isLocked(id), isTrue);
      });

      test('the lock screen says the provider is a placeholder', () {
        expect(IdentityProfiles.howItWillBeChecked(),
            UnlockMethod.placeholderProvider);
        final text = IdentityProfiles.lockScreenExplanation('Ada');
        expect(text, contains('Ada'));
        expect(text, contains('No authentication provider is built yet'));
        expect(text, contains('Only one identity is logged in'));
        expect(
            IdentityProfiles.lockScreenExplanation('Acme',
                what: 'organisation'),
            contains('Only one organisation is logged in'));
        expect(
            IdentityProfiles.lockScreenExplanation('Ada',
                method: UnlockMethod.provider),
            contains('score of 80 or more logs in'));
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

    test(
        'a new identity on a locked device needs the same check, and begins '
        'nothing without it', () async {
      final first = await ProfileScope.activeId();
      await IdentityProfiles.lockTheOpenOne(aid: one, name: 'Ada');
      IdentityProfiles.openOneHoldsAnIdentity = () async => false;
      started.clear();

      IdentityProfiles.loginProvider = _providerAnswering(79);
      await expectLater(IdentityProfiles.makeRoomForANewOne(),
          throwsA(isA<NotAuthenticated>()));
      expect(await ProfileScope.activeId(), first);
      expect(started, isEmpty);

      IdentityProfiles.loginProvider = _providerAnswering(80);
      expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
      expect(await ProfileScope.activeId(), isNot(first));
    });

    test('a new identity logs out the one that was open', () async {
      final first = await ProfileScope.activeId();
      expect(await IdentityProfiles.isLocked(first), isFalse);
      expect(await IdentityProfiles.makeRoomForANewOne(), isTrue);
      expect(await IdentityProfiles.isLocked(first), isTrue,
          reason: 'two identities are never open at once');
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
      test(
          'a data directory with an identity in it means it is, with no card, '
          'lock or phrase', () async {
        // A desktop controller profile, or one founded before cards existed
        // and never logged out: nothing but the core's own files says so.
        final id = await ProfileScope.activeId();
        final data = await IdentityProfiles.dataDirectoryFor(id);
        File('$data${Platform.pathSeparator}.port').writeAsStringSync('1');
        expect(await IdentityProfiles.openOneHoldsAnIdentity(), isFalse,
            reason: 'the files that only say where a core listens are not an '
                'identity');
        File('$data${Platform.pathSeparator}identity.db')
            .writeAsStringSync('x');
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

  group('log-out', () {
    test('a log-out that failed says so in plain words, not the exception',
        () async {
      final said = <String>[];
      final went = await IdentityProfiles.logOutAndTell(
          what: 'organisation',
          logOut: () async => throw const TheCoreDidNotStop(
              'SocketException: connection reset by 127.0.0.1:5050'),
          say: (title, body) async => said.add('$title|$body'));
      expect(went, isFalse);
      expect(said.single, startsWith('Not logged out|'));
      expect(said.single, contains('this organisation'));
      expect(said.single, isNot(contains('Socket')));
      expect(said.single, isNot(contains('5050')));
    });
  });
}

/// What the device is serving: the data directories whose Identity Agent is
/// answering. Starting a second while one answers is what a switch that did not
/// stop the first would do.
class _FakeDevice {
  final serving = <String>{};
  Future<void> start(String dir) async {
    if (serving.isNotEmpty) {
      throw StateError('started $dir while $serving still answers');
    }
    serving.add(dir);
  }

  Future<void> stop() async => serving.clear();
}

LoginProvider _providerAnswering(int score) => LoginProvider(
    name: 'test',
    isPlaceholder: false,
    measure: (_) async => MeasuredScore(
        measured: true, score: score, at: DateTime.now().toUtc()));

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
