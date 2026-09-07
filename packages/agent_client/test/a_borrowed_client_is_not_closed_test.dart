import 'package:agent_client/services/controller_signing_client.dart';
import 'package:agent_client/services/owner_signing_client.dart';
import 'package:agent_client/services/signing_as_the_identity_that_owns_a_machine.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

/// A signing wrapper closes only the transport it created — never one handed in.
///
/// The controller poll wraps ONE shared client per attempt and closes the
/// wrapper each time; when that also closed the borrowed inner, the first
/// successful poll shut the client the very next call needed, and the ceremony
/// died one step after being approved with "Client is already closed". These
/// pin that a borrowed inner survives the wrapper's close.
class _TracksClose extends http.BaseClient {
  bool closed = false;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async =>
      http.StreamedResponse(const Stream.empty(), 200);
  @override
  void close() => closed = true;
}

void main() {
  test('ControllerSigningClient leaves a borrowed inner open', () {
    final inner = _TracksClose();
    ControllerSigningClient(
      agentOrigin: 'https://agent.example',
      localCoreOrigin: 'http://127.0.0.1:5050',
      inner: inner,
    ).close();
    expect(inner.closed, isFalse,
        reason: 'the poll still needs the client it handed in');
  });

  test('OwnerSigningClient leaves a borrowed inner open', () {
    final inner = _TracksClose();
    OwnerSigningClient(
      agentOrigin: 'https://agent.example',
      ownerSeed: () async => null,
      ownerAid: 'EOwner',
      inner: inner,
    ).close();
    expect(inner.closed, isFalse);
  });

  test('SigningAsTheIdentityThatOwnsAMachine leaves a borrowed inner open', () {
    final inner = _TracksClose();
    SigningAsTheIdentityThatOwnsAMachine(
      machineOrigin: 'https://agent.example',
      localCoreOrigin: 'http://127.0.0.1:5050',
      ownerAid: () async => 'EOwner',
      inner: inner,
    ).close();
    expect(inner.closed, isFalse);
  });
}
