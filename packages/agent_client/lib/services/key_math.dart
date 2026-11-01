import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// The key arithmetic an app holding an identity's keys does, run from the
/// core's own code (ADR-061): deriving the post-quantum next key and the
/// messaging keyset, signing with ML-DSA-65, the next-key digest, and parsing
/// an event to check before it is signed. There is one implementation of each,
/// in the core; this is how an app reaches it. A phone runs it linked into the
/// app ([BridgeKeyMath]); a desktop runs the core binary as a one-shot command
/// ([CommandKeyMath]).
abstract class KeyMath {
  /// Runs one keymath operation with its JSON request and returns the JSON
  /// answer. Throws [KeyMathRefused] when the operation refuses the request.
  Future<Map<String, dynamic>> run(String op, Map<String, dynamic> request);
}

/// A keymath operation refused its request. The message is about the request,
/// never repeats it, and carries no secret.
class KeyMathRefused implements Exception {
  KeyMathRefused(this.op, this.reason);
  final String op;
  final String reason;
  @override
  String toString() => 'keymath $op refused: $reason';
}

/// The core binary did not pass the checks made before it is run.
class KeyMathBinaryRefused implements Exception {
  KeyMathBinaryRefused(this.reason);
  final String reason;
  @override
  String toString() => 'the core binary was not run: $reason';
}

/// One field of a parsed event, in the order the event serialises it.
class EventField {
  EventField(this.name, this.value);
  final String name;

  /// The field's JSON value, decoded.
  final Object? value;
}

/// An event as the core's parser reads it: its type, digest, identifier,
/// place and prior, and every field in order.
class ParsedEvent {
  ParsedEvent._(this.t, this.d, this.i, this.s, this.p, this.fields);

  factory ParsedEvent.fromJson(Map<String, dynamic> j) {
    final fields = <EventField>[];
    for (final f in (j['fields'] as List? ?? const [])) {
      final m = f as Map<String, dynamic>;
      fields.add(EventField(m['name'] as String, m['value']));
    }
    return ParsedEvent._(
        j['t'] as String? ?? '',
        j['d'] as String? ?? '',
        j['i'] as String? ?? '',
        (j['s'] as num?)?.toInt() ?? -1,
        j['p'] as String? ?? '',
        fields);
  }

  final String t;
  final String d;
  final String i;
  final int s;
  final String p;
  final List<EventField> fields;

  /// The names of the fields, in order.
  List<String> get names => [for (final f in fields) f.name];

  /// The value of the field [name], or null when the event has none.
  Object? operator [](String name) {
    for (final f in fields) {
      if (f.name == name) return f.value;
    }
    return null;
  }
}

/// The post-quantum next key a seed derives: its qb64 under the reserved code,
/// and the digest an establishment event commits to.
class PostQuantumNext {
  PostQuantumNext(this.verkey, this.digest);
  final String verkey;
  final String digest;
}

/// Typed calls over a [KeyMath].
extension KeyMathOperations on KeyMath {
  /// Parses an event's bytes with the core's parser.
  Future<ParsedEvent> parseEvent(List<int> raw) async => ParsedEvent.fromJson(
      await run('parse_event', {'raw_b64': base64Encode(raw)}));

  /// The digest an establishment event commits to for [key].
  Future<String> nextKeyDigest(String key) async =>
      (await run('next_key_digest', {'key': key}))['digest'] as String;

  /// The post-quantum next key of a 32-byte child seed.
  Future<PostQuantumNext> postQuantumNext(Uint8List seed) async {
    final a = await run('pq_next', {'seed_hex': _hex(seed)});
    return PostQuantumNext(a['verkey'] as String, a['digest'] as String);
  }

  /// The messaging keyset's founding anchor for a 32-byte child seed.
  Future<Map<String, dynamic>> messagingKeySet(Uint8List seed) async =>
      (await run('messaging_keyset', {'seed_hex': _hex(seed)}))['anchor']
          as Map<String, dynamic>;

  /// An ML-DSA-65 signature by a 32-byte child seed over [message].
  Future<Uint8List> signMlDsa65(Uint8List seed, List<int> message) async {
    final a = await run('sign_mldsa65',
        {'seed_hex': _hex(seed), 'msg_b64': base64Encode(message)});
    return base64Decode(a['sig_b64'] as String);
  }
}

String _hex(List<int> b) =>
    [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

/// Keymath linked into the app, on a phone: [call] is the app's bridge to the
/// core's `mobilecore.KeyMath(op, request)`, which answers JSON or throws.
class BridgeKeyMath implements KeyMath {
  BridgeKeyMath(this.call);
  final Future<String> Function(String op, String request) call;

  @override
  Future<Map<String, dynamic>> run(
      String op, Map<String, dynamic> request) async {
    final String answer;
    try {
      answer = await call(op, jsonEncode(request));
    } catch (e) {
      throw KeyMathRefused(op, '$e');
    }
    return jsonDecode(answer) as Map<String, dynamic>;
  }
}

/// Whether a binary is signed by the same signer as this app.
abstract class BinarySignature {
  /// Throws [KeyMathBinaryRefused] unless [binary] carries a valid code
  /// signature by the signer of [app].
  Future<void> requireSameSigner(String binary, String app);

  /// The check this platform makes: `codesign` on macOS, Authenticode on
  /// Windows. Other platforms have no desktop app, so nothing is run there.
  static BinarySignature forThisPlatform() {
    if (Platform.isMacOS) return _MacCodeSignature();
    if (Platform.isWindows) return _WindowsAuthenticode();
    return _NoDesktopApp();
  }
}

class _MacCodeSignature implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async {
    final check = await Process.run(
        '/usr/bin/codesign', ['--verify', '--strict', binary]);
    if (check.exitCode != 0) {
      throw KeyMathBinaryRefused('its code signature does not verify');
    }
    final mine = await _team(app);
    final its = await _team(binary);
    if (mine == null || its == null || mine != its) {
      throw KeyMathBinaryRefused(
          'it is not signed by the team that signed this app');
    }
  }

  Future<String?> _team(String path) async {
    final r = await Process.run('/usr/bin/codesign', ['-dv', path]);
    // codesign writes the details to standard error.
    for (final line in '${r.stderr}'.split('\n')) {
      if (line.startsWith('TeamIdentifier=')) {
        final team = line.substring('TeamIdentifier='.length).trim();
        return team.isEmpty || team == 'not set' ? null : team;
      }
    }
    return null;
  }
}

class _WindowsAuthenticode implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async {
    final mine = await _signer(app);
    final its = await _signer(binary);
    if (its == null)
      throw KeyMathBinaryRefused('its Authenticode signature is not valid');
    if (mine == null || mine != its) {
      throw KeyMathBinaryRefused(
          'it is not signed by the certificate that signed this app');
    }
  }

  /// The thumbprint of a file's valid Authenticode signer, or null.
  Future<String?> _signer(String path) async {
    final quoted = path.replaceAll("'", "''");
    final r = await Process.run('powershell', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "\$s = Get-AuthenticodeSignature -LiteralPath '$quoted'; "
          "if (\$s.Status -eq 'Valid') { \$s.SignerCertificate.Thumbprint }",
    ]);
    final out = '${r.stdout}'.trim();
    return r.exitCode == 0 && out.isNotEmpty ? out : null;
  }
}

class _NoDesktopApp implements BinarySignature {
  @override
  Future<void> requireSameSigner(String binary, String app) async {
    throw KeyMathBinaryRefused(
        'this platform has no desktop app to run it for');
  }
}

/// Keymath on a desktop: the core binary run as `<core> keymath <op>`, with the
/// request on standard input and the answer on standard output.
///
/// Before each run the binary is checked, with no fallback: its SHA-256 is the
/// one the app's build recorded ([expectedSha256]), and its code signature is
/// valid and by the signer of this app. A binary that fails either is never
/// run, since it would be handed the identity's seeds.
class CommandKeyMath implements KeyMath {
  CommandKeyMath({
    required this.binaryPath,
    required this.expectedSha256,
    BinarySignature? signature,
    String? appPath,
  })  : _signature = signature ?? BinarySignature.forThisPlatform(),
        _appPath = appPath ?? Platform.resolvedExecutable;

  final String binaryPath;

  /// The binary's SHA-256 in lowercase hexadecimal, as the build recorded it.
  final String expectedSha256;
  final BinarySignature _signature;
  final String _appPath;

  /// How long one operation may take before it is abandoned.
  static const timeout = Duration(seconds: 20);

  /// Throws [KeyMathBinaryRefused] unless the binary is the one built and
  /// signed with this app.
  Future<void> requireTheBinaryIsOurs() async {
    final file = File(binaryPath);
    if (!await file.exists())
      throw KeyMathBinaryRefused('it is not at $binaryPath');
    final digest = crypto.sha256.convert(await file.readAsBytes()).toString();
    if (expectedSha256.isEmpty || digest != expectedSha256.toLowerCase()) {
      throw KeyMathBinaryRefused(
          'it is not the binary this app was built with');
    }
    await _signature.requireSameSigner(binaryPath, _appPath);
  }

  @override
  Future<Map<String, dynamic>> run(
      String op, Map<String, dynamic> request) async {
    await requireTheBinaryIsOurs();
    final p =
        await Process.start(binaryPath, ['keymath', op], runInShell: false);
    final out = p.stdout.transform(utf8.decoder).join();
    final err = p.stderr.transform(utf8.decoder).join();
    p.stdin.add(utf8.encode(jsonEncode(request)));
    await p.stdin.close();
    final code = await p.exitCode.timeout(timeout, onTimeout: () {
      p.kill();
      return -1;
    });
    if (code != 0) {
      final why = (await err).trim();
      throw KeyMathRefused(op, why.isEmpty ? 'it exited with $code' : why);
    }
    return jsonDecode((await out).trim()) as Map<String, dynamic>;
  }
}
