import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'profile_scope.dart';
import 'root_seed_handoff.dart';
import 'the_owner_at_this_computer.dart';

/// Where the recovery phrase is held while the app needs it.
///
/// THE PHRASE RECREATES THE ROOT SEED, so it is held where the seed is held:
/// by the core on this computer, under the same hardware wrapper (macOS Secure
/// Enclave, Windows TPM, iOS Secure Enclave, Android StrongBox/TEE). The app's
/// own secure storage is not that: it is DPAPI (software) on Windows and
/// whatever the plugin's options give elsewhere. A production core refuses to
/// hold the phrase where it cannot wrap it, with the same root-seed refusal as
/// the seed ([RootSeedRefused]); a development core holds it unwrapped and says
/// so ([PhraseHolder.protection]).
abstract class PhraseHolder {
  /// Holds [phrase]. Throws [RootSeedRefused] when this computer cannot protect
  /// it, and [StateError] when the core could not be reached or did not take it.
  Future<void> hold(String phrase);

  /// The held phrase, or null when none is held. Throws [RootSeedRefused] when
  /// one is held and this build refuses to serve it.
  Future<String?> open();

  /// Whether one is held, without opening it.
  Future<bool> isHeld();

  /// What protects the held phrase (`hardware-wrapped`, `sealed-volume`,
  /// `unwrapped`), or null when none is held.
  Future<String?> protection();

  /// Deletes the held phrase. True only when it is gone.
  Future<bool> forget();
}

/// The phrase held by the local core, over `/api/keystore/recovery-phrase`.
class CorePhraseHolder implements PhraseHolder {
  CorePhraseHolder({this.baseUrl, this.client}) : _path = _inForcePath;

  /// The holder of the second phrase, kept during a phrase move, in the same
  /// core and under the same wrapper.
  CorePhraseHolder.movingTo({this.baseUrl, this.client})
      : _path = '$_inForcePath/moving-to';

  final String? baseUrl;
  final http.Client? client;

  static const _inForcePath = '/api/keystore/recovery-phrase';
  final String _path;

  String get _url {
    final url = baseUrl ?? AgentConfig.coreBaseUrl;
    // The phrase is the identity. It goes to the core on THIS computer only,
    // for the reason RootSeedHandoff.register gives.
    if (!RootSeedHandoff.isLocalCore(url)) {
      throw StateError('the recovery phrase is held by the core on this '
          'computer, and $url is not it');
    }
    return url;
  }

  Future<http.Response> _send(
      String method, String suffix, Object? body) async {
    final c = ProvingThisComputer.over(client);
    try {
      final req = http.Request(method, Uri.parse('$_url$_path$suffix'));
      if (body != null) {
        req.headers['Content-Type'] = 'application/json';
        req.body = jsonEncode(body);
      }
      final resp = await http.Response.fromStream(
          await c.send(req).timeout(const Duration(seconds: 10)));
      RootSeedRefused.throwIfRefused(resp);
      return resp;
    } finally {
      if (client == null) c.close();
    }
  }

  @override
  Future<void> hold(String phrase) async {
    final r = await _send('PUT', '', {'phrase': phrase});
    if (r.statusCode != 200 && r.statusCode != 201) {
      throw StateError('the core did not take the recovery phrase '
          '(${r.statusCode})');
    }
  }

  @override
  Future<String?> open() async {
    final r = await _send('POST', '/open', null);
    if (r.statusCode == 404) return null;
    if (r.statusCode != 200) {
      throw StateError('the core could not open the recovery phrase '
          '(${r.statusCode})');
    }
    final p = (jsonDecode(r.body) as Map)['phrase'];
    return p is String && p.isNotEmpty ? p : null;
  }

  Future<Map?> _state() async {
    final r = await _send('GET', '', null);
    if (r.statusCode != 200) {
      throw StateError('the core could not say whether it holds the recovery '
          'phrase (${r.statusCode})');
    }
    return jsonDecode(r.body) as Map;
  }

  @override
  Future<bool> isHeld() async => (await _state())?['held'] == true;

  @override
  Future<String?> protection() async {
    final s = await _state();
    return s?['held'] == true ? s!['protection'] as String? : null;
  }

  @override
  Future<bool> forget() async {
    final r = await _send('DELETE', '', null);
    return r.statusCode == 200 && !(await isHeld());
  }
}

/// A phrase kept in memory only. For tests, and nothing else: it is the
/// software holding the production rule forbids.
@visibleForTesting
class InMemoryPhraseHolder implements PhraseHolder {
  String? _phrase;
  @override
  Future<void> hold(String phrase) async => _phrase = phrase;
  @override
  Future<String?> open() async => _phrase;
  @override
  Future<bool> isHeld() async => _phrase != null;
  @override
  Future<String?> protection() async => _phrase == null ? null : 'unwrapped';
  @override
  Future<bool> forget() async {
    _phrase = null;
    return true;
  }
}

/// Holds the BIP39 mnemonic for as long as the app needs it.
///
/// It is held by the core under the same hardware wrapper as the root seed
/// (see [PhraseHolder]), never by this app's own storage. [FlutterSecureStorage]
/// is touched here for one purpose only: a phrase an earlier version left in it
/// is moved to the core and then deleted ([migrateLegacyMnemonic]).
///
/// Why held, rather than kept in memory until the owner confirms it is written
/// down: the seed is derived from the phrase one way, so the core cannot give
/// the phrase back. An app closed before the confirmation would lose the only
/// copy, the identity would exist, and nobody could ever recover it. Held
/// wrapped, it survives a restart and is gone as soon as it is confirmed
/// ([forgetWordsAfterRecording]).
///
/// There is one phrase per core, as there is one root seed per core; profiles
/// share a core, so a second profile's phrase needs its own core data
/// directory, as its seed does.
///
/// Not applicable on the web build, which holds no phrase: a page is never the
/// owner of the core it was served from.
class SecureKeyStore {
  // Where earlier versions kept the phrase. Read to move it, never written.
  static const _legacyStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    mOptions: MacOsOptions(useDataProtectionKeyChain: false),
  );

  static PhraseHolder _holder = CorePhraseHolder();

  /// Where the second phrase is held while an identity moves to a new one.
  static PhraseHolder _movingToHolder = CorePhraseHolder.movingTo();

  /// Holds the phrase in force with [holder], and the phrase moved to with
  /// [movingTo] (a fresh in-memory one when not given).
  @visibleForTesting
  static void holdPhraseWith(PhraseHolder holder, {PhraseHolder? movingTo}) {
    _holder = holder;
    _movingToHolder = movingTo ?? InMemoryPhraseHolder();
  }

  @visibleForTesting
  static void holdPhraseInTheCore() {
    _holder = CorePhraseHolder();
    _movingToHolder = CorePhraseHolder.movingTo();
  }

  /// The name the phrase used to be stored under, before profiles existed.
  static const _legacyMnemonicKey = 'agent_mnemonic';

  /// The name within a profile, in the app's own storage, as earlier versions
  /// wrote it.
  static const _mnemonicName = 'mnemonic';

  /// Single-spaced, trimmed: the shape the core accepts and compares.
  static String _normalised(String s) =>
      s.trim().split(RegExp(r'\s+')).join(' ');

  static Future<String> _scopedKey() => ProfileScope.key(_mnemonicName);

  /// Moves a phrase an earlier version left in this app's own storage (software
  /// on Windows) into the core's hardware-wrapped hold.
  ///
  /// Holds it, opens it again and compares, and only then deletes the original.
  /// Never the other way round: this is the one value in the app where an
  /// interrupted move means an identity nobody can recover.
  ///
  /// Each old key is judged on its own: one that equals what the core holds is
  /// deleted, whenever it is found, so a crash between holding and deleting
  /// does not leave the software copy for good. Only the key that was checked
  /// is deleted, never its sibling.
  ///
  /// Returns true when nothing is left in the old places. Returns false,
  /// leaving the original exactly where it was, when the core did not take it
  /// or holds a different phrase. Throws [RootSeedRefused] when this computer
  /// cannot protect the phrase: the old copy is not served in its place.
  ///
  /// [hasMnemonic] runs it (apps ask that at startup), and so does every [loadMnemonic].
  static Future<bool> migrateLegacyMnemonic() async {
    var clean = true;
    for (final key in {await _scopedKey(), _legacyMnemonicKey}) {
      final raw = await _legacyStorage.read(key: key);
      if (raw == null) continue;
      if (raw.trim().isEmpty) {
        await _legacyStorage.delete(key: key);
        continue;
      }
      final found = _normalised(raw);

      // The old copy is deleted only once the core is shown to hold THE SAME
      // phrase: a different one already held is not a reason to destroy this.
      final held = await _holder.open();
      if (held == null) {
        await _holder.hold(found);
        if (await _holder.open() != found) {
          debugPrint('[SecureKeyStore] the phrase did not survive the move — '
              'leaving the original');
          clean = false;
          continue;
        }
      } else if (held != found) {
        debugPrint('[SecureKeyStore] the core holds a different phrase — '
            'leaving the original');
        clean = false;
        continue;
      }
      await _legacyStorage.delete(key: key);
    }
    return clean;
  }

  /// Holds the phrase. Throws [RootSeedRefused] where the core will not.
  static Future<void> saveMnemonic(List<String> words) async {
    final phrase = _normalised(words.join(' '));
    await _holder.hold(phrase);
    if (await _holder.open() != phrase) {
      throw StateError('the recovery phrase did not read back from the core');
    }
  }

  static Future<List<String>?> loadMnemonic() async {
    // Every time, not only when the core holds nothing: an old copy left by a
    // crash after the hold must still be deleted.
    final settled = await migrateLegacyMnemonic();
    final value = await _holder.open();
    if (!settled && value == null) return null;
    if (value == null || value.isEmpty) return null;
    return value.split(' ');
  }

  static Future<bool> hasMnemonic() async {
    // An app asks this at startup, so an interrupted move (held, old copy not
    // yet deleted) is finished here without waiting for the first load.
    try {
      await migrateLegacyMnemonic();
      await _migrateLegacyPhraseMovingTo();
    } on RootSeedRefused {
      // This computer cannot hold the phrase; the old copy stays and is not served.
    }
    if (await _holder.isHeld()) return true;
    return await _legacyStorage.containsKey(key: await _scopedKey()) ||
        await _legacyStorage.containsKey(key: _legacyMnemonicKey);
  }

  /// What protects the held phrase, for a screen to show: `hardware-wrapped`,
  /// `sealed-volume` or `unwrapped` (a development build, flagged), or null.
  static Future<String?> protection() => _holder.protection();

  static Future<void> clearMnemonic() async {
    await _holder.forget();
    await _legacyStorage.delete(key: await _scopedKey());
    await _legacyStorage.delete(key: _legacyMnemonicKey);
  }

  /// The name within a profile of the phrase an identity is moving to, as an
  /// earlier version kept it in this app's own storage (ADR-061 section 10).
  /// Read to move it, never written.
  static const _movingToName = 'mnemonic_moving_to';

  /// Keeps the phrase the identity is moving to, and reads it back: the move
  /// starts only once it is safely kept.
  ///
  /// It is held by the core under the root seed's hardware wrapper, exactly
  /// like the phrase in force, and never by this app's own storage: between the
  /// move's two rotations both phrases are needed, and losing either loses the
  /// identity. Throws [RootSeedRefused] where the core will not hold it.
  static Future<bool> savePhraseMovingTo(List<String> words) async {
    final value = _normalised(words.join(' '));
    await _movingToHolder.hold(value);
    return await _movingToHolder.open() == value;
  }

  /// The phrase the identity is moving to, or null when no move is under way.
  ///
  /// One an earlier version left in this app's own storage is moved to the core
  /// first, by the rule [migrateLegacyMnemonic] follows: held, opened again and
  /// compared, and only then deleted.
  static Future<List<String>?> loadPhraseMovingTo() async {
    var value = await _movingToHolder.open();
    if (value == null) {
      if (await _migrateLegacyPhraseMovingTo()) {
        value = await _movingToHolder.open();
      }
    }
    if (value == null || value.isEmpty) return null;
    return value.split(' ');
  }

  /// Drops a move that cannot happen, keeping the phrase in force.
  static Future<void> clearPhraseMovingTo() async {
    await _movingToHolder.forget();
    await _legacyStorage.delete(key: await ProfileScope.key(_movingToName));
  }

  /// Makes the phrase moved to the phrase in force, once the move's second
  /// rotation is in the log: held and opened again first, and only then is the
  /// record of the move forgotten. Returns false, changing nothing it cannot
  /// confirm, when the new phrase did not survive the write.
  static Future<bool> finishMovingToThePhrase(List<String> words) async {
    final value = _normalised(words.join(' '));
    await _holder.hold(value);
    if (await _holder.open() != value) return false;
    // An older copy of the phrase just replaced, left in this app's own
    // storage, is no longer the phrase in force.
    await _legacyStorage.delete(key: await _scopedKey());
    await _legacyStorage.delete(key: _legacyMnemonicKey);
    await clearPhraseMovingTo();
    return true;
  }

  /// Moves a moving-to phrase an earlier version left in this app's own
  /// storage into the core. True when nothing is left in the old place.
  static Future<bool> _migrateLegacyPhraseMovingTo() async {
    final key = await ProfileScope.key(_movingToName);
    final raw = await _legacyStorage.read(key: key);
    if (raw == null) return true;
    if (raw.trim().isEmpty) {
      await _legacyStorage.delete(key: key);
      return true;
    }
    final found = _normalised(raw);
    // Deleted only once the core is shown to hold THE SAME phrase: a different
    // one already held is not a reason to destroy this.
    final held = await _movingToHolder.open();
    if (held == null) {
      await _movingToHolder.hold(found);
      if (await _movingToHolder.open() != found) {
        debugPrint('[SecureKeyStore] the phrase being moved to did not '
            'survive the move — leaving the original');
        return false;
      }
    } else if (held != found) {
      debugPrint('[SecureKeyStore] the core holds a different phrase being '
          'moved to — leaving the original');
      return false;
    }
    await _legacyStorage.delete(key: key);
    return true;
  }

  /// Forgets the words, once their owner has confirmed they are written down.
  ///
  /// The words and the seed are different things, kept for different lengths of
  /// time. The SEED stays — every new pairwise contact key, login relationship,
  /// asset key and the credential vault derives from it, so a root device that
  /// discarded it could not form another relationship. The WORDS are only an
  /// encoding of that seed, and once they are on paper the copy here is a
  /// second place to steal them from and nothing else.
  ///
  /// Verifies the deletion rather than assuming it. Reporting success while the
  /// words remain would be worse than not offering this at all: the owner would
  /// stop protecting something they believe no longer exists.
  static Future<bool> forgetWordsAfterRecording() async {
    final gone = await _holder.forget();
    await _legacyStorage.delete(key: await _scopedKey());
    await _legacyStorage.delete(key: _legacyMnemonicKey);
    return gone &&
        !(await _holder.isHeld()) &&
        !(await _legacyStorage.containsKey(key: await _scopedKey())) &&
        !(await _legacyStorage.containsKey(key: _legacyMnemonicKey));
  }
}
