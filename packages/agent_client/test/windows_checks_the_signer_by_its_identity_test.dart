import 'package:agent_client/services/key_math.dart';
import 'package:test/test.dart';

/// On Windows the core binary is run for an app when the app's signer signed
/// it too, named in a way that survives Azure Artifact Signing replacing its
/// certificate every day; an app with no signature runs it on its hash alone
/// (ADR-061 section 7).
void main() {
  const marker = WindowsSignature.artifactSigningMarker;
  const identity = '1.3.6.1.4.1.311.97.123456789.1';
  const subject = 'CN=Grape ID, O=Grape ID, L=Austin, S=Texas, C=US';
  const microsoft = 'CN=Microsoft ID Verified CS EOC CA 01, '
      'O=Microsoft Corporation, C=US';
  WindowsSignature artifact(String thumbprint,
          {String status = 'Valid',
          String id = identity,
          String s = subject}) =>
      WindowsSignature(
          status: status,
          thumbprint: thumbprint,
          subject: s,
          issuer: microsoft,
          ekus: ['1.3.6.1.5.5.7.3.3', marker, id]);
  WindowsSignature bought(String thumbprint, {String status = 'Valid'}) =>
      WindowsSignature(
          status: status,
          thumbprint: thumbprint,
          subject: subject,
          ekus: const ['1.3.6.1.5.5.7.3.3']);
  const unsigned = WindowsSignature(status: 'NotSigned');

  test(
      'an app and a core signed by Artifact Signing on different days, with '
      'different certificates, are the same signer', () {
    expect(
        windowsSignerRefusal(app: artifact('AAAA'), binary: artifact('BBBB')),
        isNull);
  });

  test(
      'another Artifact Signing identity is another signer, whatever its '
      'name says', () {
    expect(
        windowsSignerRefusal(
            app: artifact('AAAA'),
            binary: artifact('BBBB', id: '1.3.6.1.4.1.311.97.999.1')),
        contains('not signed by the signer'));
    expect(
        windowsSignerRefusal(
            app: artifact('AAAA'),
            binary: artifact('BBBB', s: 'CN=Somebody Else, C=US')),
        contains('not signed by the signer'));
  });

  test('a bought certificate is the signer by its thumbprint', () {
    expect(windowsSignerRefusal(app: bought('aaaa'), binary: bought('AAAA')),
        isNull);
    expect(windowsSignerRefusal(app: bought('AAAA'), binary: bought('CCCC')),
        contains('not signed by the signer'));
  });

  test('a signed app runs no core whose signature does not verify', () {
    expect(windowsSignerRefusal(app: artifact('AAAA'), binary: unsigned),
        contains('not valid'));
    expect(
        windowsSignerRefusal(
            app: artifact('AAAA'),
            binary: artifact('AAAA', status: 'HashMismatch')),
        contains('HashMismatch'));
  });

  test('an unsigned app runs its core on the hash alone', () {
    expect(windowsSignerRefusal(app: unsigned, binary: unsigned), isNull);
    expect(
        windowsSignerRefusal(app: unsigned, binary: artifact('AAAA')), isNull);
  });

  test('an app whose own signature no longer verifies runs nothing', () {
    expect(
        windowsSignerRefusal(
            app: artifact('AAAA', status: 'HashMismatch'),
            binary: artifact('AAAA')),
        contains('own signature does not verify'));
    expect(
        windowsSignerRefusal(
            app: const WindowsSignature.unreadable(), binary: unsigned),
        isNotNull,
        reason: 'a signature PowerShell could not read is not "unsigned"');
  });

  test('the signature PowerShell reports is read, its EKUs joined or listed',
      () {
    final s = WindowsSignature.fromJson({
      'status': 'Valid',
      'thumbprint': 'AAAA',
      'subject': subject,
      'issuer': microsoft,
      'ekus': '1.3.6.1.5.5.7.3.3,$marker,$identity'
    });
    expect((s.valid, s.signer), (true, 'artifact-signing|$subject|$identity'));
    expect(
        WindowsSignature.fromJson({
          'status': 'Valid',
          'thumbprint': 'AAAA',
          'subject': subject,
          'issuer': microsoft,
          'ekus': [marker, identity]
        }).signer,
        s.signer);
    expect(
        WindowsSignature.fromJson({
          'status': 'NotSigned',
          'thumbprint': '',
          'subject': '',
          'ekus': '1.3.6.1.5.5.7.3.3'
        }).unsigned,
        isTrue);
  });

  test('the durable identity is taken only with the marker, from Microsoft',
      () {
    // The marker with no durable identity, an identity with no marker, or both
    // from another issuer: each is named by its thumbprint, so a renewal is
    // another signer and a look-alike is never the same one.
    for (final w in [
      WindowsSignature(
          status: 'Valid',
          thumbprint: 'AAAA',
          subject: subject,
          issuer: microsoft,
          ekus: const [marker]),
      WindowsSignature(
          status: 'Valid',
          thumbprint: 'AAAA',
          subject: subject,
          issuer: microsoft,
          ekus: const [identity]),
      WindowsSignature(
          status: 'Valid',
          thumbprint: 'AAAA',
          subject: subject,
          issuer: 'CN=Some CA, O=Someone Else, C=US',
          ekus: const [marker, identity]),
    ]) {
      expect(w.signer, 'thumbprint|AAAA');
    }
  });

  test('several durable identities are compared whatever order they come in',
      () {
    const other = '1.3.6.1.4.1.311.97.555.1';
    WindowsSignature two(List<String> ekus) => WindowsSignature(
        status: 'Valid',
        thumbprint: 'X',
        subject: subject,
        issuer: microsoft,
        ekus: ekus);
    expect(two([marker, identity, other]).signer,
        two([other, marker, identity]).signer);
  });

  test(
      'a signed app runs no core whose signature cannot be read, and an empty '
      'verdict is not "unsigned"', () {
    expect(
        windowsSignerRefusal(
            app: artifact('AAAA'), binary: const WindowsSignature.unreadable()),
        isNotNull);
    expect(
        windowsSignerRefusal(
            app: const WindowsSignature(status: ''), binary: unsigned),
        isNotNull);
  });
}
