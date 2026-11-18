import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'app_checks.dart';
import 'installed_app.dart';

/// The key a front end of a utility app signs with (ADR-072 section 2 step 3): a
/// P-256 key whose name in the protocol is its RFC 7638 thumbprint. Every request
/// after sign-in is signed with it, so a copied session or grant alone lets nobody in.
///
/// Four kinds, one interface:
///  - [HardwareFrontEndKey]: an installed front end's key, made and held in the
///    device's secure hardware, which can prove that ([prove]).
///  - [InstalledFrontEndKey]: what an installed front end uses: the hardware's key
///    where the app's owner accepts that hardware, and otherwise, where the owner
///    does not require a hardware key, a key held in software, which the Identity
///    Agent keeps at the lower grade (ADR-072 Amendment 17).
///  - [SoftwareFrontEndKey]: held in memory, for tests and for a front end that
///    is a browser's (which the Identity Agent takes only as a browser's).
///  - the browser's own key, which a page holds: its SDK is login-web, not this.
abstract class FrontEndKey {
  const FrontEndKey();

  /// The public point's coordinates, unpadded base64url, 32 bytes each. A hardware
  /// key's change when [prove] makes it a new key for an ask (see there).
  String get x;
  String get y;

  /// Whether this key's private half can never be read out of the platform.
  bool get isNonExtractable;

  /// What kind of front end this key can start a sign-in for.
  FrontEndKind get kind;

  /// Whether what [sign] gives is an App Attest assertion (Apple), which the back
  /// end and the Identity Agent check as one, not a 64-byte plain signature.
  bool get signsAssertions => false;

  /// The public key as the sign-in start asks for it.
  Map<String, String> get jwk => {'kty': 'EC', 'crv': 'P-256', 'x': x, 'y': y};

  String get thumbprint => browserKeyThumbprint(x, y);

  /// ECDSA P-256 with SHA-256 over [message] as WebCrypto gives it: r then s, 32
  /// bytes each, unpadded base64url.
  Future<String> sign(String message);

  /// The hardware's evidence for this key, made for [ask] at [assetId]; null for
  /// a key that has none to give. A hardware key is made FOR the ask (Android's
  /// key attestation fixes its challenge when the key is generated), so proving
  /// replaces the key: read [jwk] and [thumbprint] after, never before.
  ///
  /// A TPM's evidence needs a credential only the Identity Agent can make: its
  /// hardware calls [exchange] with its keys and opens what comes back.
  Future<InstalledKeyProof?> prove(InstalledAsk ask,
          {CredentialExchange? exchange}) async =>
      null;

  /// Whether [signature] is this key's signature over [message].
  bool verify(String message, String signature) {
    final raw = b64uDecode(signature);
    if (raw == null || raw.length != 64) return false;
    final curve = ECCurve_secp256r1();
    final q =
        curve.curve.createPoint(_big(b64uDecode(x)!), _big(b64uDecode(y)!));
    final v = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(false, PublicKeyParameter<ECPublicKey>(ECPublicKey(q, curve)));
    return v.verifySignature(Uint8List.fromList(utf8.encode(message)),
        ECSignature(_big(raw.sublist(0, 32)), _big(raw.sublist(32))));
  }
}

BigInt _big(List<int> b) {
  var n = BigInt.zero;
  for (final v in b) {
    n = (n << 8) | BigInt.from(v);
  }
  return n;
}

Uint8List _fixed32(BigInt v) {
  final out = Uint8List(32);
  var n = v;
  for (var i = 31; i >= 0; i--) {
    out[i] = (n & BigInt.from(0xff)).toInt();
    n >>= 8;
  }
  return out;
}

/// A [FrontEndKey] held in memory.
class SoftwareFrontEndKey extends FrontEndKey {
  final ECPrivateKey _private;
  @override
  final String x, y;
  SoftwareFrontEndKey._(this._private, this.x, this.y);
  static final _curve = ECCurve_secp256r1();

  /// A fresh key from the platform's secure random source.
  factory SoftwareFrontEndKey.generate() {
    final rnd = Random.secure();
    final seed = Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));
    final fortuna = FortunaRandom()..seed(KeyParameter(seed));
    final gen = ECKeyGenerator()
      ..init(ParametersWithRandom(ECKeyGeneratorParameters(_curve), fortuna));
    return SoftwareFrontEndKey._fromPrivate(gen.generateKeyPair().privateKey);
  }

  /// The key with private scalar [d] (32 bytes), for tests.
  factory SoftwareFrontEndKey.fromScalar(List<int> d) =>
      SoftwareFrontEndKey._fromPrivate(ECPrivateKey(_big(d), _curve));

  factory SoftwareFrontEndKey._fromPrivate(ECPrivateKey k) {
    final q = (_curve.G * k.d)!;
    return SoftwareFrontEndKey._(k, b64uEncode(_fixed32(q.x!.toBigInteger()!)),
        b64uEncode(_fixed32(q.y!.toBigInteger()!)));
  }

  @override
  bool get isNonExtractable => false;

  @override
  FrontEndKind get kind => FrontEndKind.browser;

  /// Deterministic (RFC 6979).
  @override
  Future<String> sign(String message) async {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(true, PrivateKeyParameter<ECPrivateKey>(_private));
    final sig =
        signer.generateSignature(Uint8List.fromList(utf8.encode(message)))
            as ECSignature;
    return b64uEncode([..._fixed32(sig.r), ..._fixed32(sig.s)]);
  }
}

/// What a device's secure hardware does for a key it holds, which each platform
/// supplies (login-flutter: Android Keystore, Apple Secure Enclave with App
/// Attest, a Windows TPM). The key never leaves it: it only signs and attests.
abstract class HardwareKeyPlatform {
  /// The platform that vouches for the key: [InstalledPlatform].
  String get platform;

  /// Whether the proof of each call is an App Attest assertion (Apple), not a
  /// plain ECDSA signature: an App Attest key signs only assertions.
  bool get callProofIsAssertion => false;

  /// The uncompressed P-256 public point (65 bytes, 0x04 first) of the key
  /// [label] names, or null when there is none yet (a key is made for an ask).
  Future<Uint8List?> publicPoint(String label);

  /// The proof of one call, over [message] (the proof text): ECDSA P-256 over its
  /// SHA-256, ASN.1 DER, as Android and a TPM give it, or, where
  /// [callProofIsAssertion], the App Attest assertion over its SHA-256.
  Future<Uint8List> signCall(String label, Uint8List message);

  /// Makes a NEW key under [label] in hardware for [challenge] (replacing any
  /// held) and gives its public point and the hardware's evidence that it is the
  /// hardware's own, made for that challenge.
  ///
  /// A platform whose evidence needs a credential from the Identity Agent (a TPM)
  /// gets it by calling [exchange]; one that does not ignores it.
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge,
      {CredentialExchange? exchange});

  /// The key [label] names signing [statementDigest] (the SHA-256 of the sign-in
  /// statement): ASN.1 DER ECDSA for Android and a TPM, an App Attest assertion
  /// for Apple.
  Future<Uint8List> signStatement(String label, Uint8List statementDigest);
}

/// An installed front end's key, in its device's secure hardware.
class HardwareFrontEndKey extends FrontEndKey {
  final HardwareKeyPlatform hardware;
  final String label;

  /// What the installed app calls the device it runs on, sent with the proof
  /// for the person's consent (shown there as the app's word, not checked).
  final String? deviceName;
  String? _x, _y;
  HardwareFrontEndKey._(
      this.hardware, this.label, this._x, this._y, this.deviceName);

  @override
  String get x => _x ?? (throw StateError(_noKey));
  @override
  String get y => _y ?? (throw StateError(_noKey));
  static const _noKey =
      'this front end has no key yet: it is made when a sign-in is started';

  static (String, String) _coordinates(Uint8List p) {
    if (p.length != 65 || p[0] != 4) {
      throw const TrustRefused(
          'the device\'s hardware did not give an uncompressed P-256 key');
    }
    return (b64uEncode(p.sublist(1, 33)), b64uEncode(p.sublist(33)));
  }

  /// The key [label] names, made on first use. A refusal from the hardware (no
  /// secure hardware, a key that is not P-256) is the platform's to throw.
  /// [deviceName], if given, is what the app calls its device.
  static Future<HardwareFrontEndKey> open(
      HardwareKeyPlatform hardware, String label,
      {String? deviceName}) async {
    final p = await hardware.publicPoint(label);
    if (p == null) {
      return HardwareFrontEndKey._(hardware, label, null, null, deviceName);
    }
    final (x, y) = _coordinates(p);
    return HardwareFrontEndKey._(hardware, label, x, y, deviceName);
  }

  @override
  bool get isNonExtractable => true;

  @override
  bool get signsAssertions => hardware.callProofIsAssertion;

  @override
  FrontEndKind get kind => FrontEndKind.installedApp;

  @override
  Future<String> sign(String message) async {
    final proof = await hardware.signCall(
        label, Uint8List.fromList(utf8.encode(message)));
    return b64uEncode(hardware.callProofIsAssertion ? proof : derToRaw(proof));
  }

  @override
  Future<InstalledKeyProof?> prove(InstalledAsk ask,
      {CredentialExchange? exchange}) async {
    final challenge = b64uDecode(ask.challenge);
    if (challenge == null) {
      throw const TrustRefused('the ask\'s challenge is not readable');
    }
    final made = await hardware.attestNewKey(label, challenge, exchange: exchange);
    final (x, y) = _coordinates(made.point);
    _x = x;
    _y = y;
    final digest =
        installedAppStatementDigest(ask.assetId, challenge, thumbprint);
    return InstalledKeyProof(
        platform: hardware.platform,
        evidence: made.evidence,
        ask: ask.ask,
        keySignature: await hardware.signStatement(label, digest),
        deviceName: deviceName);
  }
}

/// The r then s, 32 bytes each, of an ASN.1 DER ECDSA signature.
Uint8List derToRaw(Uint8List der) {
  int at = 0;
  int len() {
    var l = der[at++];
    if (l < 0x80) return l;
    final n = l & 0x7f;
    l = 0;
    for (var i = 0; i < n; i++) {
      l = (l << 8) | der[at++];
    }
    return l;
  }

  Uint8List int_() {
    if (der[at++] != 0x02) throw const FormatException('not a DER integer');
    final l = len();
    var v = der.sublist(at, at + l);
    at += l;
    while (v.length > 32 && v[0] == 0) {
      v = v.sublist(1);
    }
    if (v.length > 32) throw const FormatException('integer too large');
    return Uint8List(32)..setRange(32 - v.length, 32, v);
  }

  try {
    if (der.isEmpty || der[at++] != 0x30) {
      throw const FormatException('not a DER signature');
    }
    len();
    final r = int_();
    final s = int_();
    if (at != der.length) throw const FormatException('trailing bytes');
    return Uint8List.fromList([...r, ...s]);
  } on RangeError {
    throw const FormatException('truncated DER signature');
  }
}

/// Where an [InstalledFrontEndKey] keeps which key it holds, and a key held in
/// software itself, across restarts: login-flutter keeps it in the platform's
/// secure storage. It holds a secret, so it is never a plain file.
abstract class KeyStore {
  Future<String?> read();
  Future<void> write(String value);
  Future<void> clear();
}

/// A [KeyStore] in memory, for tests and for a front end that signs in each run.
class MemoryKeyStore implements KeyStore {
  String? _value;
  @override
  Future<String?> read() async => _value;
  @override
  Future<void> write(String value) async => _value = value;
  @override
  Future<void> clear() async => _value = null;
}

/// An installed front end's key (ADR-072 section 2 step 3, Amendment 17).
///
/// A sign-in starts with an ask from the app's back end, which says which
/// platforms the Identity Agent takes a key on for this app, as its owner set them
/// ([InstalledAsk.accepts]). This key is then made in the device's secure hardware
/// where that hardware is one the owner accepts, and otherwise, where the owner
/// does not require a hardware key, in software. The Identity Agent decides, not
/// this: a key in software is refused for an app whose owner requires a hardware
/// key, whatever a front end sends, and accepted elsewhere at the lower grade.
class InstalledFrontEndKey extends FrontEndKey {
  /// The device's secure hardware, or null where this device has none an app's key
  /// can be proved in.
  final HardwareKeyPlatform? hardware;
  final String label;
  final KeyStore keyStore;

  /// What the installed app calls the device it runs on, sent with a hardware
  /// key's proof for the person's consent (ADR-072 Amendment 14), where it is
  /// shown as the app's word, not checked. A key in software proves no device,
  /// so the Identity Agent names none for it.
  final String? deviceName;
  HardwareFrontEndKey? _hardwareKey;
  SoftwareFrontEndKey? _softwareKey;

  InstalledFrontEndKey._(
      this.hardware, this.label, this.keyStore, this.deviceName);

  static const _keptHardware = 'hardware';
  static const _keptSoftware = 'software:';

  /// The key this front end holds, as [keyStore] kept it; none yet where it has
  /// not signed in. A key is made when a sign-in is started ([prove]).
  static Future<InstalledFrontEndKey> open(
      {HardwareKeyPlatform? hardware,
      required String label,
      required KeyStore keyStore,
      String? deviceName}) async {
    final k = InstalledFrontEndKey._(hardware, label, keyStore, deviceName);
    final kept = await keyStore.read();
    if (kept == _keptHardware && hardware != null) {
      // A key the hardware no longer holds is no key: the next sign-in makes one.
      if (await hardware.publicPoint(label) != null) {
        k._hardwareKey = await HardwareFrontEndKey.open(hardware, label,
            deviceName: deviceName);
      }
    } else if (kept != null && kept.startsWith(_keptSoftware)) {
      final d = b64uDecode(kept.substring(_keptSoftware.length));
      if (d != null && d.length == 32) {
        k._softwareKey = SoftwareFrontEndKey.fromScalar(d);
      }
    }
    return k;
  }

  FrontEndKey get _key =>
      _hardwareKey ??
      _softwareKey ??
      (throw StateError(
          'this front end has no key yet: it is made when a sign-in is started'));

  /// [KeyGrade.hardware] or [KeyGrade.software] for the key held, or null before
  /// one is made.
  String? get grade => _hardwareKey != null
      ? KeyGrade.hardware
      : _softwareKey != null
          ? KeyGrade.software
          : null;

  @override
  String get x => _key.x;
  @override
  String get y => _key.y;

  @override
  bool get isNonExtractable => _hardwareKey != null;

  @override
  bool get signsAssertions => _hardwareKey?.signsAssertions ?? false;

  @override
  FrontEndKind get kind => FrontEndKind.installedApp;

  @override
  Future<String> sign(String message) => _key.sign(message);

  @override
  Future<InstalledKeyProof?> prove(InstalledAsk ask,
      {CredentialExchange? exchange}) async {
    final accepts = ask.accepts;
    final hw = hardware;
    final hardwareAccepted =
        hw != null && (accepts == null || accepts.contains(hw.platform));
    // A back end that does not say leaves the Identity Agent to decide, so a device
    // with no hardware tries software; one that says is believed.
    final softwareAccepted =
        accepts == null || accepts.contains(InstalledPlatform.software);
    if (hardwareAccepted) {
      // Only the hardware's own failure may lead to a key in software: a refusal or
      // failure from the app's back end during a TPM's credential exchange is passed on.
      var backEndFailed = false;
      final ex = exchange == null
          ? null
          : (TpmEnrolment e) async {
              try {
                return await exchange(e);
              } catch (_) {
                backEndFailed = true;
                rethrow;
              }
            };
      try {
        final k =
            await HardwareFrontEndKey.open(hw, label, deviceName: deviceName);
        final proof = await k.prove(ask, exchange: ex);
        _hardwareKey = k;
        _softwareKey = null;
        await keyStore.write(_keptHardware);
        return proof;
      } catch (_) {
        // The hardware could not make or prove the key. Where the owner explicitly
        // accepts a key in software, sign in with one; otherwise say why it failed.
        if (backEndFailed ||
            accepts == null ||
            !accepts.contains(InstalledPlatform.software)) {
          rethrow;
        }
      }
    }
    if (!softwareAccepted) {
      throw const TrustRefused(
          'This app\'s owner requires a sign-in key kept in a device\'s secure hardware, '
          'and this device has none the app accepts. Sign in from another device, or ask the app\'s owner.');
    }
    final challenge = b64uDecode(ask.challenge);
    if (challenge == null) {
      throw const TrustRefused('the ask\'s challenge is not readable');
    }
    // A new key for each sign-in, as the hardware makes one.
    final k = SoftwareFrontEndKey.generate();
    final statement = installedAppStatement(ask.assetId, challenge, k.thumbprint);
    final raw = b64uDecode(await k.sign(statement))!;
    await keyStore.write(_keptSoftware + b64uEncode(_fixed32(k._private.d!)));
    _softwareKey = k;
    _hardwareKey = null;
    return InstalledKeyProof(
        platform: InstalledPlatform.software,
        evidence: Uint8List.fromList(
            [4, ...b64uDecode(k.x)!, ...b64uDecode(k.y)!]),
        ask: ask.ask,
        keySignature: rawToDer(raw));
  }

  /// Forgets the key, as signing out does.
  Future<void> forget() async {
    _hardwareKey = null;
    _softwareKey = null;
    await keyStore.clear();
  }
}

/// ASN.1 DER of an ECDSA signature given as r then s, 32 bytes each: the form a
/// TPM and Android give, and the one the Identity Agent reads a key's signature
/// over the sign-in statement in.
Uint8List rawToDer(List<int> raw) {
  if (raw.length != 64) throw const FormatException('not r then s');
  Uint8List part(List<int> v) {
    var i = 0;
    while (i < v.length - 1 && v[i] == 0) {
      i++;
    }
    var b = v.sublist(i);
    if (b[0] & 0x80 != 0) b = [0, ...b];
    return Uint8List.fromList([0x02, b.length, ...b]);
  }

  final r = part(raw.sublist(0, 32)), s = part(raw.sublist(32));
  return Uint8List.fromList([0x30, r.length + s.length, ...r, ...s]);
}
