import 'package:agent_client/services/identity_profiles.dart';
import 'package:agent_client/services/profile_scope.dart';
import 'package:agent_client/services/secure_key_store.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:test/test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _phrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/// A phrase an earlier version kept under no profile belongs to the profile the
/// installation began with. Offered to whichever profile is open, it founded
/// the PREVIOUS identity again inside a brand-new profile.
void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({'agent_mnemonic': _phrase});
    SharedPreferences.setMockInitialValues({});
    ProfileScope.resetCacheForTest();
    SecureKeyStore.holdPhraseWith(InMemoryPhraseHolder());
  });
  tearDown(SecureKeyStore.holdPhraseInTheCore);

  test('the profile the installation began with receives it', () async {
    await ProfileScope.activeId(); // the first profile, minted now
    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
    expect(await const FlutterSecureStorage().readAll(), isEmpty);
  });

  test('a profile begun afterwards does not, and does not disturb it',
      () async {
    final first = await ProfileScope.activeId();
    await ProfileScope.setActive('abcdefghij12'); // a new one is begun
    expect(await SecureKeyStore.loadMnemonic(), isNull,
        reason: 'a brand-new profile holds no identity');
    expect(await SecureKeyStore.hasMnemonic(), isFalse);
    expect(await SecureKeyStore.forgetWordsAfterRecording(), isTrue);
    expect(
        await const FlutterSecureStorage().read(key: 'agent_mnemonic'), _phrase,
        reason: 'forgetting in another profile must not delete the first '
            "profile's only copy");

    await ProfileScope.setActive(first);
    expect(await SecureKeyStore.loadMnemonic(), _phrase.split(' '));
  });

  test('the first profile stays known', () async {
    final first = await ProfileScope.activeId();
    await ProfileScope.setActive('abcdefghij12');
    expect(await ProfileScope.firstId(), first);
    expect(IdentityProfiles.isAProfileId('abcdefghij12'), isTrue);
  });
}
