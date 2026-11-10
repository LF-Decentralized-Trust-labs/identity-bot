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

/// The core's key arithmetic could not be reached at all: the app's bridge to
/// it is missing or failed. Not a verdict on the request, so it is never read
/// as one, unlike [KeyMathRefused].
class KeyMathUnavailable implements Exception {
  KeyMathUnavailable(this.op, this.reason);
  final String op;
  final String reason;
  @override
  String toString() => 'keymath $op could not be reached: $reason';
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

/// The key state a copy of an identity's key log establishes, as the core's
/// engine judges it from the founding: where the log ends, the keys in force,
/// their commitments and the witnesses.
class LogState {
  LogState.fromJson(Map<String, dynamic> j)
      : aid = j['aid'] as String? ?? '',
        sn = (j['sn'] as num?)?.toInt() ?? -1,
        digest = j['digest'] as String? ?? '',
        ilk = j['ilk'] as String? ?? '',
        establishment = (j['establishment'] as num?)?.toInt() ?? -1,
        keys = [for (final k in (j['keys'] as List? ?? const [])) '$k'],
        next = [for (final n in (j['next'] as List? ?? const [])) '$n'],
        witnesses = [
          for (final w in (j['witnesses'] as List? ?? const [])) '$w'
        ],
        toad = (j['toad'] as num?)?.toInt() ?? 0,
        events = [
          for (final e in (j['events'] as List? ?? const []))
            LoggedEvent.fromJson(e as Map<String, dynamic>)
        ];
  final String aid;
  final int sn;
  final String digest;
  final String ilk;
  final int establishment;
  final List<String> keys;
  final List<String> next;
  final List<String> witnesses;
  final int toad;

  /// Every event of the log in order, as verified.
  final List<LoggedEvent> events;
}

/// One event of a verified log: its place, digest and type, and the keys,
/// commitments and witnesses in force after it.
class LoggedEvent {
  LoggedEvent(this.sn, this.digest, this.ilk, this.keys, this.next,
      this.witnesses, this.toad,
      {this.messagingKeysets = const []});
  LoggedEvent.fromJson(Map<String, dynamic> j)
      : sn = (j['sn'] as num?)?.toInt() ?? -1,
        digest = j['digest'] as String? ?? '',
        ilk = j['ilk'] as String? ?? '',
        keys = [for (final k in (j['keys'] as List? ?? const [])) '$k'],
        next = [for (final n in (j['next'] as List? ?? const [])) '$n'],
        witnesses = [
          for (final w in (j['witnesses'] as List? ?? const [])) '$w'
        ],
        toad = (j['toad'] as num?)?.toInt() ?? 0,
        messagingKeysets = [
          for (final m in (j['messaging_keysets'] as List? ?? const []))
            Map<String, dynamic>.from(m as Map)
        ];
  final int sn;
  final String digest;
  final String ilk;
  final List<String> keys;

  /// The messaging keyset anchors the event carries.
  final List<Map<String, dynamic>> messagingKeysets;

  /// The next-key commitments in force after it.
  final List<String> next;
  final List<String> witnesses;
  final int toad;

  /// Whether it is an establishment event.
  bool get establishment => ilk != 'ixn';
}

/// A credential as the core's engine reads it, its identifier checked to be the
/// digest of the whole.
class CheckedCredential {
  CheckedCredential.fromJson(Map<String, dynamic> j)
      : said = j['said'] as String? ?? '',
        issuer = j['issuer'] as String? ?? '',
        schema = j['schema'] as String? ?? '',
        registry = j['registry'] as String? ?? '',
        recipient = j['recipient'] as String? ?? '',
        attributes = Map<String, dynamic>.from(
            (j['attributes'] as Map?) ?? const <String, dynamic>{}),
        hasEdges = j['edges'] != null,
        fields =
            j['fields'] is List ? List<String>.from(j['fields'] as List) : null;
  final String said;
  final String issuer;
  final String schema;
  final String registry;
  final String recipient;

  /// The attribute block: its own digest `d`, the recipient `i` where there is
  /// one, and the claims.
  final Map<String, dynamic> attributes;
  final bool hasEdges;

  /// Every top-level field the credential carries, whatever the engine reads
  /// of it: a rules block, a salt or an unknown field is named here. Null where
  /// the answer does not say, as an older keymath's does not: nothing can then
  /// be said of what the credential carries.
  final List<String>? fields;
}

/// A presentation as the core's engine reads it, in its one serialisation.
class CheckedPresentation {
  CheckedPresentation.fromJson(Map<String, dynamic> j)
      : said = j['said'] as String? ?? '',
        credential = j['credential'] as String? ?? '',
        holder = j['holder'] as String? ?? '',
        issuer = j['issuer'] as String? ?? '',
        schema = j['schema'] as String? ?? '',
        defaultSchema = j['default_schema'] as String? ?? '';
  final String said;
  final String credential;
  final String holder;
  final String issuer;
  final String schema;

  /// The schema a presentation is made under when none is asked for.
  final String defaultSchema;
}

/// An event's bytes, base64, with its controller signatures, as a witness
/// holds it.
class SignedCopy {
  SignedCopy(this.rawB64, this.sigs);
  final String rawB64;
  final List<String> sigs;
  Map<String, Object> toJson() => {'raw_b64': rawB64, 'sigs': sigs};
}

/// Typed calls over a [KeyMath].
extension KeyMathOperations on KeyMath {
  /// Parses an event's bytes with the core's parser.
  Future<ParsedEvent> parseEvent(List<int> raw) async => ParsedEvent.fromJson(
      await run('parse_event', {'raw_b64': base64Encode(raw)}));

  /// Reads a credential's bytes with the core's engine: canonical, and its
  /// identifier the digest of the whole. Throws [KeyMathRefused] otherwise.
  Future<CheckedCredential> checkCredential(List<int> raw) async =>
      CheckedCredential.fromJson(
          await run('check_credential', {'raw_b64': base64Encode(raw)}));

  /// Reads a presentation's bytes with the core's engine. Throws
  /// [KeyMathRefused] for anything else: a key event, a presentation with a
  /// field of its own beyond the format, one whose identifiers are not digests.
  Future<CheckedPresentation> checkPresentation(List<int> raw) async =>
      CheckedPresentation.fromJson(
          await run('check_presentation', {'raw_b64': base64Encode(raw)}));

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

  /// Whether [sig] is the witness [witness]'s receipt over the event whose
  /// digest is [digest]. A witness's name is its key, so nothing is fetched.
  ///
  /// A receipt signed over the serialised event, which is the form keripy
  /// makes, can be checked only with the event: pass it as [eventB64].
  Future<bool> isReceipt(String witness, String digest, String sig,
      {String? eventB64}) async {
    try {
      await run('verify_receipt', {
        'witness': witness,
        'digest': digest,
        'sig': sig,
        if (eventB64 != null) 'event_b64': eventB64,
      });
      return true;
    } on KeyMathRefused {
      return false;
    }
  }

  /// Judges [events] as [aid]'s key log from its founding, and returns the
  /// state it ends in. Throws [KeyMathRefused] when it is not that identity's
  /// correctly signed log.
  Future<LogState> verifyLog(String aid, List<SignedCopy> events) async =>
      LogState.fromJson(await run('verify_log', {
        'aid': aid,
        'events': [for (final e in events) e.toJson()]
      }));

  /// An ML-DSA-65 signature by a 32-byte child seed over [message].
  Future<Uint8List> signMlDsa65(Uint8List seed, List<int> message) async {
    final a = await run('sign_mldsa65',
        {'seed_hex': _hex(seed), 'msg_b64': base64Encode(message)});
    return base64Decode(a['sig_b64'] as String);
  }

  /// A raw Ed25519 signature written as an indexed one, at key place [index]
  /// and prior-next place [ondex]: how an event several keys sign names which
  /// key made each signature.
  /// With [currentOnly] the signature opens no prior commitment, as an
  /// interaction's does not, and carries no prior-next place.
  Future<String> indexEd25519Signature(List<int> signature,
          {required int index,
          int ondex = 0,
          bool currentOnly = false}) async =>
      (await run('index_ed25519_sig', {
        'sig_b64': base64Encode(signature),
        'index': index,
        'ondex': ondex,
        if (currentOnly) 'current_only': true
      }))['sig_qb64'] as String;

  /// A raw Ed25519 signature by the one key of an identity, written as
  /// everything this device signs with one key is: at place 0 of the key list
  /// and place 0 of the prior commitment, which is how the core reads an
  /// unindexed one. An event signed by more keys names each key's place with
  /// [indexEd25519Signature] instead.
  Future<String> signatureByTheOnlyKey(List<int> signature) =>
      indexEd25519Signature(signature, index: 0, ondex: 0);

  /// A raw Ed25519 signature that is not on a key event, written unindexed
  /// (code 0B): the form the core's verifiers read against a bare public key.
  /// Only a signature on a key event, judged against a key state, is indexed
  /// ([signatureByTheOnlyKey]).
  Future<String> unindexedEd25519Signature(List<int> signature) async =>
      (await run('ed25519_sig', {'sig_b64': base64Encode(signature)}))['sig_qb64']
          as String;

  /// A raw ML-DSA-65 signature written as an indexed one at [index] and
  /// [ondex]. Only a core built for tests can: CESR has assigned no such
  /// code, so any other refuses with [KeyMathRefused].
  Future<String> indexMlDsa65Signature(List<int> signature,
          {required int index,
          int ondex = 0,
          bool currentOnly = false}) async =>
      (await run('index_mldsa65_sig', {
        'sig_b64': base64Encode(signature),
        'index': index,
        'ondex': ondex,
        if (currentOnly) 'current_only': true
      }))['sig_qb64'] as String;
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
    } on KeyMathRefused {
      rethrow;
    } on KeyMathUnavailable {
      rethrow;
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
    final why = windowsSignerRefusal(
        app: await _signature(app), binary: await _signature(binary));
    if (why != null) throw KeyMathBinaryRefused(why);
  }

  /// A file's Authenticode signature as Windows judges it, read by
  /// PowerShell. The path goes in through the environment, never into the
  /// command, so no character in it can change what the command does.
  Future<WindowsSignature> _signature(String path) async {
    // By its full path, as macOS's codesign is: a 'powershell' found on PATH
    // could be any program placed earlier on it, and it is what decides here
    // whether the binary is ours.
    final windows = Platform.environment['SystemRoot'] ?? r'C:\Windows';
    final powershell =
        '$windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    final r = await Process.run(
        powershell,
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          "\$s = Get-AuthenticodeSignature -LiteralPath \$env:IA_SIGNED_FILE; "
              "\$c = \$s.SignerCertificate; \$e = @(); "
              "if (\$c) { \$e = @(\$c.Extensions | Where-Object { \$_ -is "
              "[System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | "
              "ForEach-Object { \$_.EnhancedKeyUsages } | ForEach-Object { \$_.Value }) }; "
              "[pscustomobject]@{ status = [string]\$s.Status; "
              "thumbprint = [string]\$c.Thumbprint; subject = [string]\$c.Subject; "
              "issuer = [string]\$c.Issuer; ekus = (\$e -join ',') } | "
              "ConvertTo-Json -Compress",
        ],
        environment: {'IA_SIGNED_FILE': path});
    if (r.exitCode != 0) return const WindowsSignature.unreadable();
    try {
      return WindowsSignature.fromJson(
          jsonDecode('${r.stdout}'.trim()) as Map<String, dynamic>);
    } catch (_) {
      return const WindowsSignature.unreadable();
    }
  }
}

/// A file's Authenticode signature as Windows judges it.
class WindowsSignature {
  const WindowsSignature(
      {required this.status,
      this.thumbprint = '',
      this.subject = '',
      this.issuer = '',
      this.ekus = const []});
  const WindowsSignature.unreadable()
      : status = 'Unreadable',
        thumbprint = '',
        subject = '',
        issuer = '',
        ekus = const [];

  /// As PowerShell writes it: the EKUs joined with commas, or a list.
  factory WindowsSignature.fromJson(Map<String, dynamic> j) {
    final e = j['ekus'];
    return WindowsSignature(
        status: '${j['status'] ?? ''}',
        thumbprint: '${j['thumbprint'] ?? ''}',
        subject: '${j['subject'] ?? ''}',
        issuer: '${j['issuer'] ?? ''}',
        ekus: e is List
            ? [for (final x in e) '$x']
            : e is String
                ? [
                    for (final x in e.split(','))
                      if (x.trim().isNotEmpty) x.trim()
                  ]
                : const []);
  }

  /// `Valid`, `NotSigned`, or another verdict: a signature that does not
  /// verify (`HashMismatch`, `NotTrusted`, ...).
  final String status;
  final String thumbprint;
  final String subject;
  final String issuer;
  final List<String> ekus;

  bool get valid => status == 'Valid';
  bool get unsigned => status == 'NotSigned';

  /// The marker every Azure Artifact Signing certificate carries.
  static const artifactSigningMarker = '1.3.6.1.4.1.311.97.1.0';

  /// Who signed it, as it stays from one certificate to the next.
  ///
  /// Azure Artifact Signing issues a certificate that lasts three days and is
  /// replaced every day, so its thumbprint names the day as much as the
  /// signer. What stays is the durable identity value of the certificate
  /// profile, an EKU under 1.3.6.1.4.1.311.97 that no other profile has, with
  /// the subject it was validated for: the same for every certificate the one
  /// profile issues, and different for another profile of the same publisher.
  /// It is taken as such only from a certificate Microsoft issued with the
  /// Artifact Signing marker. Any other certificate is named by its thumbprint.
  String get signer {
    if (ekus.contains(artifactSigningMarker) &&
        issuer.contains('O=Microsoft Corporation')) {
      final durable = [
        for (final e in ekus)
          if (e.startsWith('1.3.6.1.4.1.311.97.') && e != artifactSigningMarker)
            e
      ]..sort();
      if (durable.isNotEmpty)
        return 'artifact-signing|$subject|${durable.join(',')}';
    }
    return 'thumbprint|${thumbprint.toUpperCase()}';
  }
}

/// Why Windows refuses to run [binary] for the app [app], or null when it may.
///
/// The binary's hash, compiled into the app, is checked first and always
/// (CommandKeyMath.requireTheBinaryIsOurs); this is the signature check after
/// it (ADR-061 section 7):
/// - an app with a valid signature runs only a binary validly signed by the
///   same signer, the same durable identity for Azure Artifact Signing;
/// - an app with no signature at all runs the binary on its hash alone. On
///   Windows the hash lives in the app's compiled Dart code, which Authenticode
///   does not cover even in a signed app, so the signer adds nothing the hash
///   does not already give there, and an unsigned build can still sign key
///   events;
/// - an app whose signature does not verify runs nothing: it has been changed
///   since it was signed.
String? windowsSignerRefusal(
    {required WindowsSignature app, required WindowsSignature binary}) {
  if (app.unsigned) return null;
  if (!app.valid) {
    return 'this app\'s own signature does not verify (${app.status})';
  }
  if (!binary.valid) {
    return 'its Authenticode signature is not valid (${binary.status})';
  }
  if (app.signer != binary.signer) {
    return 'it is not signed by the signer that signed this app';
  }
  return null;
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
