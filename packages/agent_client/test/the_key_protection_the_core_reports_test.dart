import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

void main() {
  test('the development flag and the refusal are carried to the app', () {
    final r = EnclaveStatusResponse.fromJson({
      'hardwareBacked': true,
      'backingType': 'android_keystore',
      'backingLabel': 'Android Keystore',
      'keyProtection': {
        'status': 'usable',
        'kind': 'android_tee',
        'rootKeyPermitted': true,
        'seedWrapped': false,
        'seedWrapScheme': 'none',
        'rootKeyRefusal': 'this phone\'s secure hardware is not available to this app yet',
        'seedProtection': {
          'stored': false,
          'hardwareProtected': false,
          'notProtectedWhy': 'no wrapper',
          'developmentBuild': true,
        },
      },
    });
    final k = r.keyProtection!;
    expect(k.rootKeyRefusal, contains('not available'));
    expect(k.seedProtection!.developmentBuild, isTrue);
    expect(k.seedProtection!.hardwareProtected, isFalse);
    expect(k.seedProtection!.notProtectedWhy, 'no wrapper');
  });

  test('an older core that reports none leaves them absent, never protected', () {
    final r = EnclaveStatusResponse.fromJson(
        {'hardwareBacked': false, 'backingType': 'software', 'backingLabel': 'Software'});
    expect(r.keyProtection, isNull);
    final bare = KeyProtectionDto.fromJson({'status': 'usable', 'seedProtection': {}});
    expect(bare.seedProtection!.hardwareProtected, isFalse);
    expect(bare.seedProtection!.developmentBuild, isFalse);
  });
}
