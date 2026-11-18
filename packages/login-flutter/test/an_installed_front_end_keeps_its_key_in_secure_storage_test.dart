import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:login_dart/installed_app.dart';
import 'package:login_flutter/login_flutter.dart';

import '../../login-dart/test/support/fake_app.dart';

// Where the app's owner does not require a hardware key and this device's hardware
// is not one they accept, the installed front end signs in with a key held in
// software (ADR-072 Amendment 17). That key is kept in the platform's secure
// storage, beside the grant and never in a plain file, so it is the same key after a
// restart.

void main() {
  test('a key in software is kept in secure storage and is the same key after a restart',
      () async {
    FlutterSecureStorage.setMockInitialValues({});
    final app = FakeApp();
    // The ask accepts Apple's hardware and software; the tests run as Android, so
    // this device's hardware is not one the owner accepts.
    final key = await openInstalledFrontEndKey(app.link);
    final proof = await key.prove(InstalledAsk('a', app.assetId,
        'ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM', 'e',
        accepts: const ['apple', 'software']));
    expect(proof!.platform, InstalledPlatform.software);
    final again = await openInstalledFrontEndKey(app.link);
    expect(again.thumbprint, key.thumbprint);
    expect(again.grade, KeyGrade.software);
  });
}
