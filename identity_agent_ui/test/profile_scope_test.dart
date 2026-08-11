import 'package:flutter_test/flutter_test.dart';
import 'package:agent_client/services/profile_scope.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The migration is the part worth testing hardest.
///
/// Namespacing is cheap to get right and cheap to get wrong, and the difference
/// only shows up on somebody's installed device with real data under the old
/// names. The value that matters most — the recovery phrase — has no second
/// copy anywhere, so a migration that deletes before it has confirmed the write
/// does not lose a setting, it loses an identity.
void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ProfileScope.resetCacheForTest();
  });

  test('a profile is created on first use and then stays put', () async {
    final first = await ProfileScope.activeId();
    expect(first, isNotEmpty);

    ProfileScope.resetCacheForTest();
    expect(await ProfileScope.activeId(), first,
        reason: 'a new id each launch would orphan the previous launch\'s data');
  });

  test('keys are scoped, and the active-profile key itself is not', () async {
    final key = await ProfileScope.key('mnemonic');
    final id = await ProfileScope.activeId();

    expect(key, 'profile.$id.mnemonic');
    expect(key.contains('active_profile_id'), isFalse,
        reason: 'the key that records the scope cannot itself be scoped');
  });

  test('two profiles do not see each other', () async {
    final a = await ProfileScope.activeId();
    final keyA = await ProfileScope.key('mnemonic');

    await ProfileScope.setActive('second');
    final keyB = await ProfileScope.key('mnemonic');

    expect(keyA, isNot(keyB),
        reason: 'sharing a slot is how one identity reads another\'s phrase');
    expect(await ProfileScope.knownIds(), containsAll(<String>[a, 'second']));
  });

  group('migration', () {
    test('moves a legacy value and removes the original', () async {
      final store = <String, String>{'agent_mode': 'createNew'};

      final ok = await ProfileScope.migrateValue(
        legacyName: 'agent_mode',
        read: (k) async => store[k],
        write: (k, v) async => store[k] = v,
        remove: (k) async => store.remove(k),
      );

      expect(ok, isTrue);
      expect(store.containsKey('agent_mode'), isFalse);
      expect(store[await ProfileScope.key('agent_mode')], 'createNew');
    });

    test('leaves the original in place when the copy does not survive',
        () async {
      // A store that silently drops writes — the shape of failure that a
      // delete-first migration turns into permanent loss.
      final store = <String, String>{'agent_mnemonic': 'abandon abandon art'};

      final ok = await ProfileScope.migrateValue(
        legacyName: 'agent_mnemonic',
        read: (k) async => store[k],
        write: (k, v) async {/* dropped */},
        remove: (k) async => store.remove(k),
      );

      expect(ok, isFalse, reason: 'a failed move must report failure');
      expect(store['agent_mnemonic'], 'abandon abandon art',
          reason: 'the only copy of the phrase must survive a failed migration');
    });

    test('does not touch a legacy value once the new one exists', () async {
      final scoped = await ProfileScope.key('server_url');
      final store = <String, String>{
        'server_url': 'http://old',
        scoped: 'http://current',
      };

      await ProfileScope.migrateValue(
        legacyName: 'server_url',
        read: (k) async => store[k],
        write: (k, v) async => store[k] = v,
        remove: (k) async => store.remove(k),
      );

      expect(store[scoped], 'http://current',
          reason: 'a migration must never overwrite what is already in use');
    });

    test('is safe to run repeatedly', () async {
      final store = <String, String>{'entity_type': 'individual'};
      Future<bool> run() => ProfileScope.migrateValue(
            legacyName: 'entity_type',
            read: (k) async => store[k],
            write: (k, v) async => store[k] = v,
            remove: (k) async => store.remove(k),
          );

      expect(await run(), isTrue);
      expect(await run(), isTrue);
      expect(await run(), isTrue);
      expect(store[await ProfileScope.key('entity_type')], 'individual');
    });

    test('nothing to move is success, not failure', () async {
      final store = <String, String>{};
      final ok = await ProfileScope.migrateValue(
        legacyName: 'never_written',
        read: (k) async => store[k],
        write: (k, v) async => store[k] = v,
        remove: (k) async => store.remove(k),
      );
      expect(ok, isTrue);
      expect(store, isEmpty);
    });
  });
}
