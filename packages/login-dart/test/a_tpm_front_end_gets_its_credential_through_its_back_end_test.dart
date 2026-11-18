import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:login_dart/app_session.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:login_dart/installed_app.dart';
import 'package:login_dart/tpm_evidence.dart';
import 'package:test/test.dart';

import 'support/fake_app.dart';

// A TPM's evidence needs a credential only the Identity Agent can make
// (identity-agent-core/secureenclave/tpm_make_credential.go), so a TPM front end's
// sign-in has one more call with its back end than the other platforms': keys out,
// credential back, then the evidence. This is that call, through the SDK, with a
// stand-in for the TPM (the TPM itself is the plugin's native code).

class _FakeTpm extends FakeHardware {
  TpmEnrolment? enrolled;
  Uint8List? opened;
  @override
  String get platform => InstalledPlatform.tpm;

  @override
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge,
      {CredentialExchange? exchange}) async {
    if (exchange == null) throw StateError('no credential exchange');
    enrolled = TpmEnrolment(
        ekPublic: Uint8List.fromList([0, 2, 1, 1]),
        ekCert: Uint8List.fromList([48, 3, 2, 1, 1]),
        akPublic: Uint8List.fromList([0, 2, 7, 7]),
        ekChain: [Uint8List.fromList([48, 3, 2, 1, 2])]);
    final c = await exchange(enrolled!);
    // The TPM releases what is inside the credential: here, the blob's bytes.
    opened = c.credentialBlob;
    final made = await super.attestNewKey(label, challenge);
    return (
      point: made.point,
      evidence: tpmEvidence(
          enrolled!,
          TpmAttested(
              keyPublic: Uint8List.fromList([0, 1, 5]),
              certifyInfo: Uint8List.fromList([1, 2, 3]),
              certifySignature: Uint8List.fromList([4, 5, 6]),
              credentialSecret: c.credentialBlob))
    );
  }
}

AppSession open(FakeApp app, FrontEndKey key) =>
    AppSession(app.client, app.link, key, now: () => app.clock);

void main() {
  test('a TPM front end sends its keys for the ask and signs in on what comes back',
      () async {
    final app = FakeApp();
    final hw = _FakeTpm();
    final key = await HardwareFrontEndKey.open(hw, 'k');
    final s = open(app, key);
    await s.start();
    final asked = app.credentialAskedWith!;
    expect(asked['ask'], app.asked,
        reason: 'the credential is asked for the ask the back end gave');
    expect(base64.decode(asked['ek_cert'] as String), [48, 3, 2, 1, 1]);
    expect(base64.decode(asked['ek_public'] as String), [0, 2, 1, 1]);
    expect(base64.decode(asked['ak_public'] as String), [0, 2, 7, 7]);
    expect((asked['ek_chain'] as List).map((c) => base64.decode(c as String)),
        [
      [48, 3, 2, 1, 2]
    ]);
    expect(hw.opened, [0, 3, 1, 2, 3]);
    final proof = app.startedWith!['proof'] as Map<String, dynamic>;
    expect(proof['platform'], 'tpm');
    final ev = jsonDecode(utf8.decode(base64.decode(proof['evidence'] as String)))
        as Map<String, dynamic>;
    expect(base64.decode(ev['credential_secret'] as String), [0, 3, 1, 2, 3],
        reason: 'the evidence carries what the TPM released');
    expect(ev.keys.toSet(), {
      'key_public',
      'certify_info',
      'certify_signature',
      'ak_public',
      'ek_cert',
      'ek_chain',
      'credential_secret'
    });
  });

  test('a back end that refuses the credential says why, and no sign-in starts',
      () async {
    final app = FakeApp()..refuseCredential = true;
    final key = await HardwareFrontEndKey.open(_FakeTpm(), 'k');
    await expectLater(
        open(app, key).start(),
        throwsA(isA<SignInFailed>().having((e) => e.message, 'message',
            contains('not a TPM manufacturer'))));
    expect(app.startedWith, isNull);
  });

  test('a start reports its phases in order, and a TPM has the credential phase in between',
      () async {
    final tpm = <SignInPhase>[];
    await open(FakeApp(), await HardwareFrontEndKey.open(_FakeTpm(), 'k'))
        .start(onPhase: tpm.add);
    expect(tpm, [SignInPhase.proveKey, SignInPhase.credential, SignInPhase.start]);
    final other = <SignInPhase>[];
    await open(FakeApp(), await HardwareFrontEndKey.open(FakeHardware(), 'k'))
        .start(onPhase: other.add);
    expect(other, [SignInPhase.proveKey, SignInPhase.start],
        reason: 'only a TPM asks the app for a credential');
  });

  test('a refusal with a reason says it; one with none says what to do, never an HTTP status',
      () async {
    const sentence =
        'This app\'s owner has not allowed sign-in from a Windows computer\'s security chip. Ask them to allow it, or sign in from a phone.';
    final refused = FakeApp()
      ..startStatus = 403
      ..startRefusal = sentence;
    await expectLater(
        open(refused, await HardwareFrontEndKey.open(_FakeTpm(), 'k')).start(),
        throwsA(isA<SignInFailed>().having((e) => e.message, 'message', sentence)));
    final bare = FakeApp()..startStatus = 500;
    await expectLater(
        open(bare, await HardwareFrontEndKey.open(FakeHardware(), 'k')).start(),
        throwsA(isA<SignInFailed>().having(
            (e) => e.message,
            'message',
            allOf(contains('The app had a problem signing you in'),
                isNot(contains('500')), isNot(contains('HTTP'))))));
  });

  test('the evidence is the document the core reads', () {
    // identity-agent-core/secureenclave/testdata/tpm_credential_exchange_rsa.json
    // is what a software TPM made and the core accepts; rebuilt from its parts,
    // the SDK's document is the same one.
    for (final f in ['rsa', 'ecc']) {
      final v = jsonDecode(File(
                  '../../identity-agent-core/secureenclave/testdata/tpm_credential_exchange_$f.json')
              .readAsStringSync())
          as Map<String, dynamic>;
      final ev = v['evidence'] as Map<String, dynamic>;
      Uint8List b(String k) => base64.decode(ev[k] as String);
      final built = jsonDecode(utf8.decode(tpmEvidence(
          TpmEnrolment(
              ekPublic: base64.decode(v['ek_public'] as String),
              ekCert: b('ek_cert'),
              akPublic: b('ak_public'),
              ekChain: [for (final c in ev['ek_chain'] as List) base64.decode(c as String)]),
          TpmAttested(
              keyPublic: b('key_public'),
              certifyInfo: b('certify_info'),
              certifySignature: b('certify_signature'),
              credentialSecret: b('credential_secret')))));
      expect(built, ev, reason: f);
    }
  });
}
