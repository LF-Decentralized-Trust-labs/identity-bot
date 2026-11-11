import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'backend_process_service.dart';
import 'core_service.dart';
import 'local_auth_service.dart';
import 'mobile_core_service.dart';
import 'profile_scope.dart';
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
  static Future<String> directoryFor(String profileId) async =>
      '${await _profilesRoot()}${Platform.pathSeparator}$profileId';

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
    if (await activeIsLocked()) return;

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
    await _stopWhateverIsRunning();
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

  static Future<bool> _authenticateOnThisDevice(String reason) async {
    // A device with no screen lock and no biometrics has nothing to ask. There
    // is no second secret anywhere in this app to fall back to, and refusing
    // would lock an owner out of their own identity for good, so it opens.
    // The lock is as strong as the device's own.
    if (!await LocalAuthService.isSupported()) return true;
    return LocalAuthService.authenticate(reason: reason);
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
    final marker = await _lockedMarker(await ProfileScope.activeId());
    await marker.parent.create(recursive: true);
    await marker.writeAsString(DateTime.now().toUtc().toIso8601String());
    await _stopWhateverIsRunning();
  }

  /// Open [profileId], first making its owner authenticate if it is locked.
  /// Held inside [TheCoreIsSettled.during], like every switch.
  ///
  /// Returns false, and changes nothing, when authentication did not succeed.
  /// A profile that fails to start is locked again rather than left open.
  static Future<bool> openAfterAuthenticating(String profileId) async {
    final locked = await isLocked(profileId);
    if (locked &&
        !await authenticateOwner('Unlock this identity on this device')) {
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
      rethrow;
    }
    return true;
  }

  /// What says whether the open profile already holds an identity. A seam for
  /// tests.
  @visibleForTesting
  static Future<bool> Function() openOneHoldsAnIdentity = () async {
    final core = CoreService();
    try {
      final identity = await core.getIdentity();
      return identity.initialized && (identity.aid ?? '').isNotEmpty;
    } catch (_) {
      // Nothing answering is not a reason to abandon this profile: the core may
      // simply not be up yet, and beginning another would strand the first.
      return false;
    } finally {
      core.dispose();
    }
  };

  /// Make room for an identity about to be created, on every platform.
  ///
  /// The core keeps one identity per data directory, so a second cannot be
  /// founded in the directory that holds the first: it comes back "already
  /// exists", and an app that treats that as an interrupted founding opens the
  /// identity that is there. So when the open profile holds one, or is a
  /// locked one, a new profile is begun and opened.
  ///
  /// An empty profile is used as it is — beginning a fresh one on every Create
  /// press would leave an empty directory behind each abandoned attempt.
  /// Returns whether a new profile was begun.
  static Future<bool> makeRoomForANewOne() async {
    if (!await activeIsLocked() && !await openOneHoldsAnIdentity()) {
      return false;
    }
    // Held shut while the core moves to the new profile's data, as for any other
    // switch: a request in between would be signed by the old core.
    await TheCoreIsSettled.during(beginANewOne);
    return true;
  }

  static Future<void> _stopWhateverIsRunning() async {
    final stopper = coreStopper;
    if (stopper != null) return stopper();
    if (BackendProcessService.isDesktopPlatform) {
      await BackendProcessService.instance.stop();
    } else {
      await mobileCore?.stopCore();
    }
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

    final files =
        legacy.listSync(recursive: true, followLinks: false).whereType<File>();

    try {
      for (final f in files) {
        final rel = f.path.substring(legacy.path.length + 1);
        final dest = File('${target.path}${Platform.pathSeparator}$rel');
        await dest.parent.create(recursive: true);
        await f.copy(dest.path);
      }
    } catch (e) {
      debugPrint('[profiles] copy failed, original left in place: $e');
      return false;
    }

    for (final f in files) {
      final rel = f.path.substring(legacy.path.length + 1);
      final dest = File('${target.path}${Platform.pathSeparator}$rel');
      if (!dest.existsSync() || dest.lengthSync() != f.lengthSync()) {
        debugPrint('[profiles] $rel did not survive the copy — '
            'original left in place');
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

    final sep = Platform.pathSeparator;
    final home = Platform.environment['HOME'] ??
        Platform.environment['USERPROFILE'] ??
        '';
    var appName = 'IdentityAgent';
    try {
      final resolved = Platform.resolvedExecutable.split(sep).last;
      if (resolved.isNotEmpty) appName = resolved;
    } catch (_) {/* keep the default */}

    if (Platform.isMacOS) {
      return '$home${sep}Library${sep}Application Support$sep$appName';
    }
    if (Platform.isWindows) {
      final appData =
          Platform.environment['APPDATA'] ?? '$home${sep}AppData${sep}Roaming';
      return '$appData$sep$appName';
    }
    final xdg = Platform.environment['XDG_DATA_HOME'];
    return (xdg != null && xdg.isNotEmpty)
        ? '$xdg$sep$appName'
        : '$home$sep.local${sep}share$sep$appName';
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
