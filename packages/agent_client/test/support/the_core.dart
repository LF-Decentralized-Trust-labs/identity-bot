import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:agent_client/services/key_math.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
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
/// refuses to; [purpose] names the directory. [tags] are Go build tags, such as
/// `kerigo_pqtest`, the only build that reads post-quantum keys and signatures.
Future<String> buildTheCore(String purpose,
    {bool dev = false, List<String> tags = const []}) async {
  final dir = await Directory.systemTemp.createTemp(purpose);
  final bin =
      '${dir.path}/identity-agent-core${Platform.isWindows ? '.exe' : ''}';
  final built = await Process.run(
      'go',
      [
        'build',
        if (tags.isNotEmpty) '-tags=${tags.join(',')}',
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

/// A core a test started, reached at [base].
class TheCoreRunning {
  TheCoreRunning(this.process, this.base, this.logs);
  final Process process;

  /// Where it answers, such as `http://127.0.0.1:53124`.
  final String base;

  /// Everything it wrote to its standard output and error.
  final StringBuffer logs;
}

/// The line a core logs once it holds its port, naming the port.
final _listening = RegExp(r'Server listening on [0-9.]+:(\d+)\s*$');

/// Starts the core at [bin] with its data in [dataDir] and [ownerSecret] as
/// the secret its owner's requests carry, on a port the system gives it, and
/// returns once it answers `/api/health` there. Test files run in parallel, so
/// a port picked by the test could be taken by another file's core before
/// this one binds it. The core names the port it took in its log, and that is
/// the port used. A core that exits, or does not answer within [within] (well
/// inside a test's own 30 s limit, so the core's log is not lost to it), fails
/// the test with everything it logged. [arguments] are given to the binary,
/// for a test of a core that never answers.
Future<TheCoreRunning> startTheCore(String bin,
    {required String dataDir,
    required String ownerSecret,
    Duration within = const Duration(seconds: 15),
    List<String> arguments = const []}) async {
  final p = await Process.start(bin, arguments, environment: {
    ...Platform.environment,
    'PORT': '0',
    'HOST': '127.0.0.1',
    'AGENT_DATA_DIR': dataDir,
    'IDENTITY_AGENT_LOCAL_OWNER_SECRET': ownerSecret,
  });
  final logs = StringBuffer();
  final port = Completer<int>();
  // Each whole line as it arrives, so a port split across two reads is never
  // taken for a shorter one.
  void line(String l) {
    logs.writeln(l);
    final m = port.isCompleted ? null : _listening.firstMatch(l);
    if (m != null) port.complete(int.parse(m[1]!));
  }

  Future<void> read(Stream<List<int>> s) => s
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .listen(line)
      .asFuture<void>();
  final reading = Future.wait([read(p.stdout), read(p.stderr)]);
  int? exitCode;
  unawaited(p.exitCode.then((c) => exitCode = c));

  Future<Never> notStarted(String why) async {
    if (exitCode == null) {
      p.kill(ProcessSignal.sigkill);
      await p.exitCode.timeout(const Duration(seconds: 5), onTimeout: () => -1);
    }
    // Everything it wrote, which ends once its output is closed.
    await reading.timeout(const Duration(seconds: 5),
        onTimeout: () => const []);
    fail('the core at $bin $why. What it logged:\n$logs');
  }

  final deadline = DateTime.now().add(within);
  final bound = await Future.any<int?>([
    port.future,
    p.exitCode.then((_) => null),
  ]).timeout(within, onTimeout: () => null);
  if (bound == null) {
    return notStarted(exitCode != null
        ? 'exited with code $exitCode before it took a port'
        : 'did not say which port it took within ${within.inSeconds} s');
  }
  final base = 'http://127.0.0.1:$bound';
  while (DateTime.now().isBefore(deadline)) {
    if (exitCode != null) {
      return notStarted('exited with code $exitCode before it answered');
    }
    try {
      final res = await http
          .get(Uri.parse('$base/api/health'))
          .timeout(const Duration(seconds: 2));
      if (res.statusCode == 200) return TheCoreRunning(p, base, logs);
    } catch (_) {}
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  return notStarted('did not answer at $base/api/health within '
      '${within.inSeconds} s');
}
