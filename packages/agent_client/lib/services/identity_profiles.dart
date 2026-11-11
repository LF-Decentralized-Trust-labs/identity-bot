import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'backend_process_service.dart';
import 'controller_signing_client.dart' show VouchedAuthentication;
import 'local_auth_service.dart';
import 'mobile_core_service.dart';
import 'profile_scope.dart';
import 'secure_key_store.dart';
import 'point_this_app_at_its_agent.dart';
import 'the_core_is_settled.dart';

/// One identity this installation holds, as it can be described while its
/// Identity Agent is not running.
@immutable
class IdentityProfile {
  /// Which profile holds it. Never shown to anybody — it is how the app finds
  /// the identity again, not something a person recognises.
  final String profileId;

  final String aid;

  /// What a person recognises. A display name, not an identifier.
  final String name;

  /// A small picture, or null. Small deliberately — see [IdentityProfiles.remember].
  final Uint8List? picture;

  final DateTime? lastOpened;

  const IdentityProfile({
    required this.profileId,
    required this.aid,
    required this.name,
    this.picture,
    this.lastOpened,
  });
}

/// A fresh measurement of the person holding a device, from its authentication
/// provider (identity-agent-core/authprovider `Result`).
@immutable
class MeasuredScore {
  const MeasuredScore({
    required this.measured,
    required this.score,
    required this.at,
  });
  final bool measured;
  final int score;
  final DateTime at;
}

/// What a locked identity is opened with on this device.
enum UnlockMethod {
  /// A phone: the provider runs here.
  providerOnThisDevice,

  /// A Mac or PC: the person's phone or black box measured and vouched.
  providerVouchedByAnotherDevice,

  /// No provider exists yet: the device's own screen lock, and nothing
  /// measured the person.
  deviceScreenLockNoProvider,
}

/// Logging out could not be confirmed: a core may still answer for the
/// identity. The marker is set, but the person must be told, not shown the
/// next screen as though it were done.
class TheCoreDidNotStop implements Exception {
  const TheCoreDidNotStop([this.detail]);
  final String? detail;
  @override
  String toString() => 'The Identity Agent for this identity could not be '
      'stopped${detail == null ? '' : ' ($detail)'}, so it is not logged out. '
      'Quit the app and open it again.';
}

/// The identities on this installation: where each one's data lives, which is
/// open, and enough about the others to offer them.
///
/// The core keeps **one identity per data directory** — one row in its identity
/// table — so an installation with a single directory holds exactly one
/// identity, for ever. Creating a second has nowhere to put it and comes back
/// "an identity already exists".
///
/// [ProfileScope] already mints an id per profile, records which is active, and
/// scopes every stored key to it. What was missing is a place on disk for each
/// profile's Identity Agent, and a way to move between them. That is this.
///
///     <root>/data                  ← where a single identity used to live
///     <root>/profiles/<id>/data    ← where each one lives now
///     <root>/profiles/<id>/card.json
///
/// **One identity is open at a time.** Moving to another stops the Identity
/// Agent serving the current one and starts it against the new directory.
/// Nothing is deleted by that: the one being left is exactly where it was.
///
/// Desktop and mobile run the core differently — a spawned process against
/// AGENT_DATA_DIR, or an embedded one told its directory when it starts — so
/// both are handled here rather than in every app that has the problem.
class IdentityProfiles {
  /// The embedded core, on mobile. Set once at start-up, before anything else
  /// here is called.
  ///
  /// Held rather than created because the app owns this object's lifetime: it
  /// carries whether the core is running, and a second instance would answer
  /// that question wrongly. On desktop it stays null and is never consulted.
  static MobileCoreService? mobileCore;

  /// Replace starting and stopping the core, for tests, which cannot run one.
  @visibleForTesting
  static Future<void> Function(String dataDir)? coreStarter;
  @visibleForTesting
  static Future<void> Function()? coreStopper;

  /// Replace where this installation keeps everything, for tests.
  @visibleForTesting
  static String? rootOverride;

  static const _cardFile = 'card.json';
  static const _openedKey = 'opened_aid';
  static const _leftKey = 'left_aid';

  // ── where things live ────────────────────────────────────────────────────

  /// The directory belonging to [profileId] — the profile itself, not the data
  /// inside it. Anything ABOUT a profile lives here; anything its Identity
  /// Agent owns lives under [dataDirectoryFor].
  ///
  /// Refuses anything but a minted id ([isAProfileId]) or an id this
  /// installation already knows from before minting, so a value from outside can never name a path above or beside
  /// the profiles directory.
  static Future<String> directoryFor(String profileId) async {
    if (!isAProfileId(profileId) &&
        !(_safeEarlierForm.hasMatch(profileId) &&
            (await ProfileScope.knownIds()).contains(profileId))) {
      throw ArgumentError.value(profileId, 'profileId',
          'neither a minted profile id nor one this installation already knows');
    }
    return '${await _profilesRoot()}${Platform.pathSeparator}$profileId';
  }

  static final _mintedForm = RegExp(r'^[a-z0-9]{12}$');

  /// Whether [id] is the form this class mints.
  static bool isAProfileId(String id) => _mintedForm.hasMatch(id);

  static final _safeEarlierForm = RegExp(r'^[A-Za-z0-9_-]{1,64}$');

  /// Where [profileId]'s Identity Agent keeps its data, created if absent.
  static Future<String> dataDirectoryFor(String profileId) async {
    final dir = Directory(
        '${await directoryFor(profileId)}${Platform.pathSeparator}data');
    await dir.create(recursive: true);
    return dir.path;
  }

  /// Where the active profile's Identity Agent keeps its data.
  static Future<String> dataDirectoryForActive() async =>
      dataDirectoryFor(await ProfileScope.activeId());

  // ── opening, and moving between ──────────────────────────────────────────

  /// Point the core at the active profile and start it.
  ///
  /// Call before anything talks to the Identity Agent. On desktop the
  /// directory is handed to the process that gets spawned; on mobile it is
  /// handed to the embedded core when it starts. Either way the core reads it
  /// once, at start — which is why moving between identities means restarting.
  static Future<void> startTheActiveOne() async {
    // A locked profile is not started. Logging out stopped its Identity Agent;
    // starting it again here — on launch, or when the app resumes — would put
    // the identity back within reach of anything on this device that can open
    // a local port, without its owner having done anything. It starts when
    // [openAfterAuthenticating] has been through.
    if (await activeIsLocked()) {
      await stopALeftoverCoreOfTheLockedOne();
      return;
    }

    final dir = await dataDirectoryForActive();

    final starter = coreStarter;
    if (starter != null) return starter(dir);

    if (BackendProcessService.isDesktopPlatform) {
      BackendProcessService.dataDirOverride = dir;
      if (!await BackendProcessService.instance.start()) {
        throw Exception(BackendProcessService.instance.startupError ??
            'the Identity Agent did not start');
      }
      // WHICH HALF THIS APP IS RUNNING IS A PROPERTY OF THE OPEN PROFILE, so it
      // is settled here — the one place that is passed through at start-up, on
      // a switch, and when a profile is begun.
      //
      // Doing it only at start-up is the trap. One profile may be the front end
      // for a sealed machine while another holds its own identity, and the
      // answer lives in a process-wide value: a switch that did not redo this
      // would leave every screen in the newly opened profile sending its
      // requests to the PREVIOUS profile's agent, signed as this machine, and
      // getting entirely plausible answers about the wrong identity — until the
      // app was restarted.
      await pointThisAppAtItsAgent();
      return;
    }

    final core = mobileCore;
    if (core == null) {
      throw StateError('IdentityProfiles.mobileCore was never set, so there is '
          'no embedded core to start. Set it once at start-up.');
    }
    await core.startCore(dataDir: dir);
    // AFTER it is answering, not merely after it was asked to start. Telling it
    // which half this app runs is a request like any other, and sending it into
    // a core still binding its port spends the whole retry budget before the
    // code that actually knows when it is ready has run — so on the slowest
    // cold starts, the ones where it matters most, it would give up.
    if (!await core.waitForReady()) {
      throw StateError('the Identity Agent core did not become ready, so this '
          'app could not tell it which half it is running');
    }
    await pointThisAppAtItsAgent();
  }

  /// Re-establish the embedded core if it has stopped answering.
  ///
  /// iOS suspends a backgrounded app and tears down the core's listener; on
  /// resume the Dart side still believes it is running, so the next request
  /// fails with connection-refused until the app is force-quit and reopened.
  /// Called on resume: a no-op when the core is healthy, and otherwise it drops
  /// the stale server and starts the active profile's core again. Desktop has
  /// no embedded mobile core, so it returns at once there.
  /// Guards against overlapping rebinds. iOS can deliver `resumed` in bursts,
  /// and two concurrent runs could both see the core unhealthy, both stop it,
  /// and race to start — one tearing down what the other just bound. Reusing the
  /// in-flight future collapses a burst into a single restart.
  static Future<void>? _ensuring;

  static Future<void> ensureActiveOneRunning() {
    return _ensuring ??=
        _ensureActiveOneRunning().whenComplete(() => _ensuring = null);
  }

  static Future<void> _ensureActiveOneRunning() async {
    final core = mobileCore;
    if (core == null) return;
    if (await core.isHealthy()) return;
    await core.forceStopped();
    await startTheActiveOne();
  }

  /// Make [profileId] the open one.
  ///
  /// Stops the Identity Agent serving whatever was open and starts it against
  /// the new directory. Nothing is deleted and nothing is unenrolled — the
  /// identity being left is exactly where it was, and can be returned to.
  static Future<void> switchTo(String profileId) async {
    await ProfileScope.setActive(profileId);
    await _stopAndVerify();
    await startTheActiveOne();
    debugPrint('[profiles] now on $profileId');
  }

  /// Begin a profile that has never held anything, and open it.
  ///
  /// The id is minted here rather than by [ProfileScope], which mints one only
  /// when none is active. Registering it through `setActive` is what puts it in
  /// `knownIds`, so a profile is never created without being listed — one that
  /// existed but could not be found again would be the worst of both.
  static Future<String> beginANewOne() async {
    final id = _mintProfileId();
    await switchTo(id);
    return id;
  }

  // ── locking ──────────────────────────────────────────────────────────────

  static const _lockedFile = 'locked';

  /// How the owner is asked to prove it is them, before a locked identity is
  /// opened. The device's own authentication — Face ID, a fingerprint, Windows
  /// Hello, Touch ID, or the device passcode. A seam for tests.
  @visibleForTesting
  static Future<bool> Function(String reason) authenticateOwner =
      _authenticateOnThisDevice;

  /// The least a measured score may be to open a locked identity: the same
  /// bar as an ordinary action, `permission.DefaultMinimumScore` in
  /// identity-agent-core.
  static const minimumScore = 80;

  /// How recent a measurement must be to count. A score is about a moment.
  static const scoreFreshFor = Duration(minutes: 2);

  /// The authentication provider running ON THIS DEVICE (a phone), asked for a
  /// fresh measurement of whoever is holding it. Null while none exists: only
  /// `authprovider.NotConfigured` does today. A seam for tests and for the
  /// provider when it arrives.
  static Future<MeasuredScore?> Function(String profileId)?
      providerOnThisDevice;

  /// What the person's phone or black box vouches for, for a Mac or PC. A
  /// machine may not score itself, so on a computer the score counts only when
  /// the device holding the root identity has signed it
  /// ([VouchedAuthentication.vouchedBy]). Null while no such device offers
  /// one.
  static Future<VouchedAuthentication?> Function(String profileId)?
      vouchedByThePersonsDevice;

  /// How a locked identity will be opened on this device right now, so the
  /// lock screen can say it before anyone is asked.
  static UnlockMethod howItWillBeChecked() {
    if (BackendProcessService.isDesktopPlatform) {
      return vouchedByThePersonsDevice != null
          ? UnlockMethod.providerVouchedByAnotherDevice
          : UnlockMethod.deviceScreenLockNoProvider;
    }
    return providerOnThisDevice != null
        ? UnlockMethod.providerOnThisDevice
        : UnlockMethod.deviceScreenLockNoProvider;
  }

  /// Plain words for the lock screen: who is being asked to authenticate, why,
  /// and how it will be checked — including, when it is true, that nothing
  /// measured the person. One place, for both apps.
  static String lockScreenExplanation(String name,
      {UnlockMethod? method, String what = 'identity'}) {
    final who = name.isEmpty ? 'the owner of this identity' : name;
    final m = method ?? howItWillBeChecked();
    final why = 'Logging out locked everything on this device, so that '
        'nobody can open one that is not theirs. $who is asked to '
        'authenticate because this $what can only be opened by its own '
        'person.';
    switch (m) {
      case UnlockMethod.providerOnThisDevice:
        return '$why The authentication provider will measure who is holding '
            'this device; a score of $minimumScore or more opens it.';
      case UnlockMethod.providerVouchedByAnotherDevice:
        return '$why This computer cannot score a person itself, so your '
            'phone or black box will measure you and vouch for the result; '
            'a score of $minimumScore or more opens it.';
      case UnlockMethod.deviceScreenLockNoProvider:
        return '$why No authentication provider is set up yet, so nothing '
            'has measured who you are. This device\'s own screen lock is '
            'used instead, and it only shows that someone who can unlock '
            'this device is here.';
    }
  }

  /// What the list of identities says above itself: who is asked to
  /// authenticate and why when any listed one is locked, and that the device
  /// has no screen lock when it has none. Null when there is nothing to say.
  /// One place, so both apps say the same thing.
  static String? listNotice({
    required List<String> lockedNames,
    required bool noScreenLock,
    String what = 'identity',
    UnlockMethod? method,
  }) {
    final parts = <String>[
      if (lockedNames.isNotEmpty)
        lockScreenExplanation(
            lockedNames.length == 1 ? lockedNames.first : 'Each owner',
            method: method,
            what: what),
      if (noScreenLock) noScreenLockMessage(),
    ];
    return parts.isEmpty ? null : parts.join(' ');
  }

  /// Whether [m] is a measurement that opens an identity: measured, fresh,
  /// at least [minimumScore], and on a computer vouched for. Pure, so it can be
  /// tested without a provider.
  static bool scoreOpens({
    required bool measured,
    required int score,
    required DateTime at,
    required bool needsVouching,
    String vouchedBy = '',
    DateTime? now,
  }) {
    if (!measured) return false;
    if (needsVouching && vouchedBy.isEmpty) return false;
    if (score < minimumScore) return false;
    final age = (now ?? DateTime.now().toUtc()).difference(at.toUtc());
    return age <= scoreFreshFor && !age.isNegative;
  }

  /// Passes only when the owner of [profileId] proves it is them. With a
  /// provider configured this is the provider's fresh score and nothing else:
  /// failing it does NOT fall back to the screen lock. With none configured
  /// the device's own screen lock stands in ([authenticateOwner]).
  static Future<bool> proveItIsThem(String profileId, String reason) async {
    final method = howItWillBeChecked();
    try {
      switch (method) {
        case UnlockMethod.providerOnThisDevice:
          final m = await providerOnThisDevice!(profileId);
          return m != null &&
              scoreOpens(
                  measured: m.measured,
                  score: m.score,
                  at: m.at,
                  needsVouching: false);
        case UnlockMethod.providerVouchedByAnotherDevice:
          final v = await vouchedByThePersonsDevice!(profileId);
          return v != null &&
              scoreOpens(
                  measured: true,
                  score: v.score,
                  at: v.at,
                  needsVouching: true,
                  vouchedBy: v.vouchedBy);
        case UnlockMethod.deviceScreenLockNoProvider:
          return await authenticateOwner(reason);
      }
    } catch (_) {
      return false; // could not be established: not opened
    }
  }

  static Future<bool> _authenticateOnThisDevice(String reason) async {
    // A device with no screen lock has nothing to ask. There is no second
    // secret anywhere in this app to fall back to, and refusing would lock an
    // owner out of their own identity for good, so it opens — and
    // [deviceHasNoScreenLock] is how the screens say so, plainly, before and
    // after. local_auth reports "not enrolled" and "passcode not set" as
    // errors; they mean the same thing, not a failed attempt.
    final check = await LocalAuthService.checkOwner(reason: reason);
    return check != OwnerCheck.notUnlocked;
  }

  /// Whether this device has no screen lock, so anyone holding it can open a
  /// locked identity. A seam for tests.
  static Future<bool> Function() deviceHasNoScreenLock = () async {
    try {
      return !await LocalAuthService.isSupported();
    } catch (_) {
      return false; // cannot tell: claim nothing
    }
  };

  /// What to tell a person whose device has no screen lock: that the lock on a
  /// logged-out [what] ("identity", or "organisation" in the organisation app)
  /// is only as strong as the device's own, and where to set one. [platform] is
  /// one of android, ios, windows, macos. On a computer it is "anyone using
  /// it", on a phone "anyone holding it".
  static String noScreenLockMessage({String? platform, String what = 'identity'}) {
    final p = platform ?? Platform.operatingSystem;
    final where = switch (p) {
      'android' => 'Android Settings > Security > Screen lock',
      'ios' => 'iOS Settings > Face ID & Passcode',
      'windows' => 'Windows Settings > Accounts > Sign-in options',
      'macos' => 'macOS System Settings > Lock Screen / Touch ID & Password',
      _ => "this device's settings",
    };
    final computer = p == 'windows' || p == 'macos' || p == 'linux';
    return 'This ${computer ? 'computer' : 'device'} has no screen lock, so '
        'anyone ${computer ? 'using' : 'holding'} it can open this $what. '
        'Set one in $where.';
  }

  /// Why an identity or organisation did not open, in plain words. The detail
  /// of [error] goes to the log, not to the person.
  static String couldNotOpenBecause(Object error, {String what = 'identity'}) {
    debugPrint('[profiles] could not open: $error');
    return 'Could not open this $what: its Identity Agent did not start or '
        'did not answer. Try again, or quit the app and open it again.';
  }

  static Future<File> _lockedMarker(String profileId) async =>
      File('${await directoryFor(profileId)}${Platform.pathSeparator}$_lockedFile');

  /// Whether [profileId] was logged out of and has not been opened since.
  static Future<bool> isLocked(String profileId) async =>
      (await _lockedMarker(profileId)).existsSync();

  static Future<bool> activeIsLocked() async =>
      isLocked(await ProfileScope.activeId());

  /// Log out of the open identity: stop its Identity Agent and mark it locked.
  ///
  /// Nothing of it is reachable afterwards — its core is not running, and
  /// nothing here starts it again — until [openAfterAuthenticating] succeeds.
  /// Nothing is deleted.
  ///
  /// The card is written first, from what the running agent says, so the
  /// identity can still be offered by name while nothing is running. The
  /// marker is written BEFORE the core is stopped: the other order leaves a
  /// window in which an interruption has stopped the agent but left the
  /// identity looking open.
  static Future<void> lockTheOpenOne({
    String? aid,
    String? name,
    Uint8List? picture,
  }) async {
    if (aid != null && aid.isNotEmpty) {
      await remember(aid: aid, name: name ?? '', picture: picture);
      await rememberWeLeft(aid);
    }
    // EVERY identity on this device locks, not only the open one. One person
    // has one identity, and several people may share a device (a parent and a
    // child on one phone): when anyone logs out, nobody is left open for the
    // next person to pick up. Each person gets back in only by passing
    // [proveItIsThem] for their own identity.
    final active = await ProfileScope.activeId();
    for (final id in {active, ...await ProfileScope.knownIds()}) {
      if (!isAProfileId(id) && !_safeEarlierForm.hasMatch(id)) continue;
      final marker = await _lockedMarker(id);
      await marker.parent.create(recursive: true);
      await marker.writeAsString(DateTime.now().toUtc().toIso8601String());
    }
    // The marker stays set whatever happens next: a profile that could not be
    // confirmed stopped is still locked. What is not allowed is saying it is
    // done. Stopped is verified (the core no longer answers), and when it is
    // not, [TheCoreDidNotStop] reaches the screen instead of the next one.
    await _stopAndVerify();
  }

  /// Log out with [logOut] and tell the person what happened, through [say].
  /// Returns whether to go on to the start-up screen.
  ///
  /// A stop that could not be confirmed is SHOWN and nothing proceeds: a core
  /// may still be answering, so "logged out" would be untrue. A device with no
  /// screen lock is told so now (see [noScreenLockMessage]). One place, for
  /// both apps, so they cannot say different things.
  ///
  /// [what] is "identity", or "organisation" in the organisation app. What
  /// failed is said in plain words; its detail is in the log.
  static Future<bool> logOutAndTell({
    required Future<void> Function() logOut,
    required Future<void> Function(String title, String body) say,
    String what = 'identity',
  }) async {
    try {
      await logOut();
    } on TheCoreDidNotStop catch (e) {
      debugPrint('[profiles] not logged out: ${e.detail}');
      await say(
          'Not logged out',
          'The Identity Agent for this $what could not be stopped, so it is '
              'not logged out. Quit the app and open it again.');
      return false;
    }
    if (await deviceHasNoScreenLock()) {
      await say('Logged out', noScreenLockMessage(what: what));
    }
    return true;
  }

  /// Stops whatever runs and confirms nothing answers. Throws
  /// [TheCoreDidNotStop] when a stop throws or a core still answers.
  static Future<void> _stopAndVerify() async {
    try {
      if (!await _stopWhateverIsRunning()) throw const TheCoreDidNotStop();
    } on TheCoreDidNotStop {
      rethrow;
    } catch (e) {
      throw TheCoreDidNotStop('$e');
    }
  }

  /// Open [profileId], first making its owner authenticate if it is locked.
  /// Held inside [TheCoreIsSettled.during], like every switch.
  ///
  /// Returns false, and changes nothing, when authentication did not succeed.
  /// A profile that fails to start is locked again, and whatever core the
  /// failed switch got started is stopped and verified stopped, rather than
  /// left open.
  static Future<bool> openAfterAuthenticating(String profileId) async {
    final locked = await isLocked(profileId);
    if (locked &&
        !await proveItIsThem(
            profileId, 'Unlock this identity on this device')) {
      return false;
    }
    final marker = await _lockedMarker(profileId);
    if (locked) marker.deleteSync();
    try {
      await TheCoreIsSettled.during(() => switchTo(profileId));
    } catch (_) {
      if (locked) {
        await marker.parent.create(recursive: true);
        await marker.writeAsString(DateTime.now().toUtc().toIso8601String());
      }
      // A core switchTo already started must not be left answering for a
      // profile that is marked locked.
      try {
        await _stopAndVerify();
      } catch (stopFailed) {
        debugPrint('[profiles] could not stop the core after a failed '
            'open: $stopFailed');
      }
      rethrow;
    }
    return true;
  }

  /// What says whether the open profile may already hold an identity. A seam
  /// for tests.
  ///
  /// DECIDED FROM LOCAL FACTS AND FAILING CLOSED. It used to ask the core and
  /// answer "no" on any error, so a core that was stopped, slow or refusing
  /// looked like an empty profile; the app founded in the occupied one, the
  /// core said "already exists", and the interrupted-founding repair opened
  /// the previous identity. Now a card, a lock marker, a phrase held (or one
  /// that cannot be ruled out), or ANYTHING in the profile's data directory
  /// each mean "occupied": a new profile is begun. The data directory counts
  /// because an identity can be there with none of the others: a desktop
  /// controller profile keeps no phrase, and one founded before cards existed
  /// and never logged out has no card or lock. The only "no" is a profile with
  /// none of them.
  ///
  /// The cost is that a profile whose core has run (it writes its store when
  /// it starts) is occupied even when nothing was founded in it, so a retry
  /// after a failure before the founding begins another profile and leaves
  /// that one empty and unlisted. An empty directory is the price of never
  /// founding on top of an identity.
  @visibleForTesting
  static Future<bool> Function() openOneHoldsAnIdentity = () async {
    final id = await ProfileScope.activeId();
    if (File(await _cardPathFor(id)).existsSync()) return true;
    if (await isLocked(id)) return true;
    try {
      if (await _dataDirectoryHoldsAnything(id)) return true;
    } catch (_) {
      return true; // cannot be ruled out, so not empty
    }
    try {
      if (await SecureKeyStore.hasMnemonic()) return true;
    } catch (_) {
      return true; // cannot be ruled out, so not empty
    }
    return false;
  };

  /// Whether [profileId]'s data directory holds anything but the files a
  /// running core leaves to say where it listens (`.port`, `.pid`). Does not
  /// create the directory.
  static Future<bool> _dataDirectoryHoldsAnything(String profileId) async {
    final dir = Directory(
        '${await directoryFor(profileId)}${Platform.pathSeparator}data');
    if (!dir.existsSync()) return false;
    await for (final entry in dir.list(followLinks: false)) {
      final name = entry.uri.pathSegments
          .lastWhere((s) => s.isNotEmpty, orElse: () => '');
      if (name == '.port' || name == '.pid') continue;
      return true;
    }
    return false;
  }

  // ── a founding this run started ──────────────────────────────────────────

  static const _foundingFile = 'founding';

  static Future<File> _foundingMarker(String profileId) async => File(
      '${await directoryFor(profileId)}${Platform.pathSeparator}$_foundingFile');

  /// Written before the words are saved and before the founding is asked of
  /// the core. A repair of an "already exists" answer is only for a founding
  /// this run started; without the marker the identity that is there is
  /// somebody else's, and is not opened.
  ///
  /// Written first of all because the words are saved next: a kill between
  /// the two the other way round leaves a profile that holds a phrase and
  /// nothing saying why. An existing marker is kept as it is, with the
  /// identifier it already names.
  static Future<void> markFoundingStarted() async {
    final f = await _foundingMarker(await ProfileScope.activeId());
    if (f.existsSync()) return;
    await f.parent.create(recursive: true);
    await f.writeAsString(jsonEncode(
        {'started': DateTime.now().toUtc().toIso8601String(), 'aid': ''}));
  }

  /// Records the identifier the core prepared for this founding, before it is
  /// signed or committed. A repair opens only an identity with this one.
  static Future<void> recordFoundingAid(String aid) async {
    final f = await _foundingMarker(await ProfileScope.activeId());
    await f.parent.create(recursive: true);
    await f.writeAsString(jsonEncode(
        {'started': DateTime.now().toUtc().toIso8601String(), 'aid': aid}));
  }

  /// The identifier the open profile's founding was prepared for, or null
  /// when none was recorded (the run ended before the core prepared one).
  static Future<String?> foundingAid() async {
    final f = await _foundingMarker(await ProfileScope.activeId());
    if (!f.existsSync()) return null;
    try {
      final body = jsonDecode(await f.readAsString());
      final aid = body is Map ? body['aid'] : null;
      return aid is String && aid.isNotEmpty ? aid : null;
    } catch (_) {
      return null;
    }
  }

  /// Whether the open profile has a founding that was started and not
  /// finished.
  static Future<bool> foundingWasStarted() async =>
      (await _foundingMarker(await ProfileScope.activeId())).existsSync();

  /// Removed once the founding is finished or repaired.
  static Future<void> clearFoundingMarker() async {
    final f = await _foundingMarker(await ProfileScope.activeId());
    if (f.existsSync()) f.deleteSync();
  }

  /// Make room for an identity about to be created, on every platform.
  ///
  /// The core keeps one identity per data directory, so a second cannot be
  /// founded in the directory that holds the first. When the open profile
  /// holds one (by local facts, [openOneHoldsAnIdentity]) or is a locked one, a
  /// new profile is begun and opened. A profile with a founding in progress
  /// is the exception: it is resumed, because beginning another would strand
  /// the words it already holds.
  ///
  /// An empty profile is used as it is — beginning a fresh one on every Create
  /// press would leave an empty directory behind each abandoned attempt.
  /// Returns whether a new profile was begun.
  static Future<bool> makeRoomForANewOne() async {
    if (!await activeIsLocked()) {
      if (await foundingWasStarted()) return false;
      if (!await openOneHoldsAnIdentity()) return false;
    }
    // Held shut while the core moves to the new profile's data, as for any other
    // switch: a request in between would be signed by the old core.
    await TheCoreIsSettled.during(beginANewOne);
    return true;
  }

  /// Whether nothing answers afterwards.
  static Future<bool> _stopWhateverIsRunning() async {
    final stopper = coreStopper;
    if (stopper != null) {
      await stopper();
      return true;
    }
    if (BackendProcessService.isDesktopPlatform) {
      // By the profile's data directory, so a core this app adopted rather than
      // spawned is ended too — see [BackendProcessService.stop].
      BackendProcessService.dataDirOverride ??=
          await dataDirectoryForActive();
      return BackendProcessService.instance.stop();
    }
    final core = mobileCore;
    if (core == null) return true;
    await core.stopCore();
    return !await core.isHealthy();
  }

  /// At launch, for a profile that is locked: end any core still answering on
  /// its data (a leftover from before it was locked or from a crash). Desktop
  /// only. Returns whether nothing answers afterwards.
  static Future<bool> stopALeftoverCoreOfTheLockedOne() async {
    if (!BackendProcessService.isDesktopPlatform || coreStopper != null) {
      return true;
    }
    if (!await activeIsLocked()) return true;
    BackendProcessService.dataDirOverride = await dataDirectoryForActive();
    return BackendProcessService.instance.stop();
  }

  // ── describing them without running them ─────────────────────────────────

  /// Record what is true of the identity now open, so it can be offered later.
  ///
  /// Call once its details have been read FROM the running Identity Agent,
  /// never before. A card written from what is about to happen, rather than
  /// from what did, is a lie waiting for the next start-up.
  ///
  /// [picture] should already be small. It lands in a plain file that anything
  /// on this device can read, so it wants to be enough for the owner to
  /// recognise at a glance and not much else.
  static Future<void> remember({
    required String aid,
    required String name,
    Uint8List? picture,
  }) async {
    if (aid.isEmpty) return;
    try {
      final f = File(await _cardPathFor(await ProfileScope.activeId()));
      await f.parent.create(recursive: true);
      await f.writeAsString(jsonEncode({
        'aid': aid,
        'name': name,
        'picture': picture == null ? '' : base64Encode(picture),
        'lastOpened': DateTime.now().toUtc().toIso8601String(),
      }));
    } catch (e) {
      // A missing card costs a row on a list. It must never cost a start-up.
      debugPrint('[profiles] could not write the card: $e');
    }
  }

  /// Every identity this installation can offer, most recently opened first.
  ///
  /// A profile with no card is skipped rather than listed blank: it was begun
  /// and abandoned before anything was created, and a row that says nothing is
  /// worse than no row.
  ///
  /// **A card is a cache and never evidence.** Choosing one still starts its
  /// Identity Agent and still compares the AID before anything opens. If they
  /// disagree the running Identity Agent is right and the card is rewritten.
  static Future<List<IdentityProfile>> all() async {
    final out = <IdentityProfile>[];
    for (final id in await ProfileScope.knownIds()) {
      try {
        final f = File(await _cardPathFor(id));
        if (!f.existsSync()) continue;
        final m = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
        final aid = (m['aid'] ?? '').toString();
        if (aid.isEmpty) continue;
        final pic = (m['picture'] ?? '').toString();
        out.add(IdentityProfile(
          profileId: id,
          aid: aid,
          name: (m['name'] ?? '').toString(),
          picture: pic.isEmpty ? null : base64Decode(pic),
          lastOpened: DateTime.tryParse((m['lastOpened'] ?? '').toString()),
        ));
      } catch (e) {
        debugPrint('[profiles] skipping $id: $e');
      }
    }
    out.sort((a, b) =>
        (b.lastOpened ?? DateTime(0)).compareTo(a.lastOpened ?? DateTime(0)));
    return out;
  }

  // ── which one we were in, and which we left ──────────────────────────────

  /// Remember the identity now open, and that it is no longer one we left.
  ///
  /// Called once it really is open, never on the way in: an app that records
  /// what it is about to do, and then fails, has recorded something it will
  /// believe next time.
  static Future<void> rememberWeOpened(String aid) async {
    if (aid.isEmpty) return;
    final p = await SharedPreferences.getInstance();
    await p.setString(await ProfileScope.key(_openedKey), aid);
    await p.remove(await ProfileScope.key(_leftKey));
  }

  /// Whether the Identity Agent answering is the one this profile was in.
  ///
  /// A first run has nothing to compare against and is let through — there is
  /// no evidence either way, and refusing the only identity present because
  /// nothing has been written down yet would make a fresh install look broken.
  static Future<bool> isTheOneWeWereIn(String aid) async {
    final p = await SharedPreferences.getInstance();
    return decideIsTheOneWeWereIn(
        p.getString(await ProfileScope.key(_openedKey)), aid);
  }

  /// The decision behind [isTheOneWeWereIn], separated from where the answer is
  /// stored so it can be examined on its own. It has been got wrong before, and
  /// the cost of getting it wrong is somebody dropped into an identity that is
  /// not theirs.
  @visibleForTesting
  static bool decideIsTheOneWeWereIn(String? remembered, String aid) {
    if (remembered == null || remembered.isEmpty) return true;
    return remembered == aid;
  }

  /// Record that this identity was deliberately left.
  ///
  /// Signing out cannot be recorded by forgetting which identity was opened: a
  /// forgotten identity is a first run, and a first run is let through — so
  /// forgetting on the way out signs you back in on the way in. Nor can it be a
  /// flag, because an installation later pointed at a DIFFERENT identity was
  /// never left and should open normally. So what is stored is which one.
  static Future<void> rememberWeLeft(String aid) async {
    if (aid.isEmpty) return;
    final p = await SharedPreferences.getInstance();
    await p.setString(await ProfileScope.key(_leftKey), aid);
  }

  /// Whether this identity is one somebody signed out of and has not returned
  /// to. False for any other identity, including on a first run.
  static Future<bool> didWeLeave(String aid) async {
    if (aid.isEmpty) return false;
    final p = await SharedPreferences.getInstance();
    return decideDidWeLeave(p.getString(await ProfileScope.key(_leftKey)), aid);
  }

  /// The decision behind [didWeLeave], separated for the same reason. Note it
  /// compares WHICH identity was left rather than answering a flag: signing out
  /// of one identity must not lock out a different one.
  @visibleForTesting
  static bool decideDidWeLeave(String? left, String aid) {
    if (aid.isEmpty) return false;
    return left == aid;
  }

  // ── the one-directory installations that came before ─────────────────────

  /// Move an installation that kept its identity in a single directory into the
  /// active profile, once.
  ///
  /// Copy, verify, then remove — never remove first, and not at all if the
  /// verify does not hold. What is being moved is a signing key with no second
  /// copy anywhere: an interruption between a delete and a write leaves
  /// nothing, and an installation that starts empty beside its own data is
  /// indistinguishable from a fresh one.
  ///
  /// Returns false if anything did not line up, leaving the original exactly
  /// where it is so a caller can keep using it rather than pretend.
  static Future<bool> migrateTheSingleDirectory() async {
    final legacy =
        Directory('${await _root()}${Platform.pathSeparator}data');
    if (!legacy.existsSync()) return true; // nothing was ever there

    final target = Directory(await dataDirectoryForActive());
    if (target.listSync().isNotEmpty) return true; // already done, or founded here

    // NOT WHILE A CORE ANSWERS. A running core has its database open and is
    // writing it: a copy taken now can be torn halfway through a write, and the
    // original then removed. Left where it is, the identity keeps working.
    if (await _aCoreAnswersOn(legacy) && !await _endTheCoreOn(legacy)) {
      debugPrint('[profiles] a core is running on the old directory — not '
          'moving it now');
      return false;
    }

    // What a running core leaves to say where it was and who it was, not data.
    bool isCoreRuntimeNote(String rel) => rel == '.port' || rel == '.pid';

    final files = legacy
        .listSync(recursive: true, followLinks: false)
        .whereType<File>()
        .where((f) => !isCoreRuntimeNote(f.path.substring(legacy.path.length + 1)))
        .toList();

    try {
      for (final f in files) {
        final rel = f.path.substring(legacy.path.length + 1);
        final dest = File('${target.path}${Platform.pathSeparator}$rel');
        await dest.parent.create(recursive: true);
        await f.copy(dest.path);
      }
    } catch (e) {
      debugPrint('[profiles] copy failed, original left in place: $e');
      _clear(target);
      return false;
    }

    // Verified by content, not length: a copy of a database taken while it was
    // being written has the right length and the wrong bytes.
    for (final f in files) {
      final rel = f.path.substring(legacy.path.length + 1);
      final dest = File('${target.path}${Platform.pathSeparator}$rel');
      if (!dest.existsSync() ||
          sha256.convert(await dest.readAsBytes()) !=
              sha256.convert(await f.readAsBytes())) {
        debugPrint('[profiles] $rel did not survive the copy — '
            'original left in place');
        _clear(target);
        return false;
      }
    }

    try {
      legacy.deleteSync(recursive: true);
    } catch (e) {
      // The copy is verified; failing to tidy up is not failing to migrate.
      // Leaving both is safe, because the new one is what gets opened.
      debugPrint('[profiles] migrated, old directory not removed: $e');
    }
    return true;
  }

  /// Empties a half-made copy, so the next launch does not take it for a
  /// finished move ("target not empty").
  static void _clear(Directory target) {
    try {
      for (final e in target.listSync()) {
        e.deleteSync(recursive: true);
      }
    } catch (e) {
      debugPrint('[profiles] could not clear the partial copy: $e');
    }
  }

  /// Ends this app's own leftover core on [dataDir], once it has proved it is
  /// this directory's. Desktop only; elsewhere nothing is ended.
  static Future<bool> _endTheCoreOn(Directory dataDir) async {
    if (!BackendProcessService.isDesktopPlatform || coreStopper != null) {
      return false;
    }
    final before = BackendProcessService.dataDirOverride;
    BackendProcessService.dataDirOverride = dataDir.path;
    try {
      return await BackendProcessService.instance.stopTheCoreOnThisData();
    } finally {
      BackendProcessService.dataDirOverride = before;
    }
  }

  /// Where a single-directory installation kept its identity. An app whose
  /// [migrateTheSingleDirectory] returned false keeps running on this, rather
  /// than start empty beside an identity it did not move.
  static Future<String> legacyDirectory() async =>
      '${await _root()}${Platform.pathSeparator}data';

  static Future<bool> _aCoreAnswersOn(Directory dataDir) async {
    try {
      final f = File('${dataDir.path}${Platform.pathSeparator}.port');
      if (!f.existsSync()) return false;
      final port = int.tryParse(f.readAsStringSync().trim());
      if (port == null) return false;
      final client = HttpClient()
        ..connectionTimeout = const Duration(milliseconds: 600);
      try {
        final req = await client
            .getUrl(Uri.parse('http://127.0.0.1:$port/api/health'))
            .timeout(const Duration(milliseconds: 800));
        final resp = await req.close().timeout(const Duration(milliseconds: 800));
        await resp.drain<void>();
        return true; // anything answering there is a reason not to move it
      } finally {
        client.close(force: true);
      }
    } catch (_) {
      return false;
    }
  }

  // ── paths ────────────────────────────────────────────────────────────────

  static Future<String> _cardPathFor(String profileId) async =>
      '${await directoryFor(profileId)}${Platform.pathSeparator}$_cardFile';

  static Future<String> _profilesRoot() async =>
      '${await _root()}${Platform.pathSeparator}profiles';

  /// Where this installation keeps everything.
  ///
  /// On mobile this is the app's own container, which the operating system
  /// gives us and which is the only place an app may write. On desktop it is
  /// the per-application support directory the spawned core already used —
  /// computed the same way, because the point of [migrateTheSingleDirectory]
  /// is to find what that produced. Deriving it differently would look for an
  /// existing identity where it never was, find nothing, and start empty.
  static Future<String> _root() async {
    final over = rootOverride;
    if (over != null) return over;
    if (!BackendProcessService.isDesktopPlatform) {
      return (await getApplicationSupportDirectory()).path;
    }

    return BackendProcessService.desktopInstallationRoot();
  }

  /// Short, random, and only unique within this installation — which is all it
  /// has to distinguish. Not the AID: a profile's directory has to exist before
  /// an identity does, and a scheme that cannot name a profile until it has an
  /// AID cannot hold the thing that produces one.
  static String _mintProfileId() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    final rng = Random.secure();
    return List.generate(12, (_) => alphabet[rng.nextInt(alphabet.length)])
        .join();
  }
}
