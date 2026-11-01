import 'dart:io';

import 'package:agent_client/services/key_math.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';

/// A signature check that accepts, for running a locally built core in a test.
/// What it stands in for is the platform's own check, which a locally built
/// binary would fail; the hash check is still made.
class SignedByUs implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async {}
}

/// Builds the core in this checkout into a new temporary directory and returns
/// the binary's path. [dev] makes a development build, which founds an
/// identity on a machine that cannot attest, as a production build rightly
/// refuses to; [purpose] names the directory.
Future<String> buildTheCore(String purpose, {bool dev = false}) async {
  final dir = await Directory.systemTemp.createTemp(purpose);
  final bin =
      '${dir.path}/identity-agent-core${Platform.isWindows ? '.exe' : ''}';
  final built = await Process.run(
      'go',
      [
        'build',
        if (dev) ...[
          '-ldflags',
          '-X identity-agent-core/buildmode.rawMode=dev'
        ],
        '-o',
        bin,
        '.'
      ],
      workingDirectory: '../../identity-agent-core');
  if (built.exitCode != 0) {
    fail('the core could not be built for this test: ${built.stderr}');
  }
  return bin;
}

/// The SHA-256 of the binary at [bin], as an app's build records it.
Future<String> sha256Of(String bin) async =>
    crypto.sha256.convert(await File(bin).readAsBytes()).toString();

/// The core's key arithmetic run from the binary at [bin], which passes the
/// hash check and stands in for the platform's signature check.
Future<KeyMath> keyMathOf(String bin) async => CommandKeyMath(
    binaryPath: bin,
    expectedSha256: await sha256Of(bin),
    signature: SignedByUs());
