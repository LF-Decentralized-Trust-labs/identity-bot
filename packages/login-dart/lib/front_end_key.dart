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
/// Three kinds, one interface:
///  - [HardwareFrontEndKey]: an installed front end's key, made and held in the
///    device's secure hardware, which can prove that ([prove]). The only kind the
///    Identity Agent accepts for an installed app.
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
  Future<InstalledKeyProof?> prove(String assetId, InstalledAsk ask) async =>
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

  /// The uncompressed P-256 public point (65 bytes, 0x04 first) of the key
  /// [label] names, made in hardware on first use and kept across restarts.
  Future<Uint8List> publicPoint(String label);

  /// ECDSA P-256 over SHA-256 of [message] by the key, ASN.1 DER as the hardware
  /// gives it. This is what signs every call after sign-in.
  Future<Uint8List> signDer(String label, Uint8List message);

  /// Makes a NEW key under [label] in hardware for [challenge] (replacing any
  /// held) and gives its public point and the hardware's evidence that it is the
  /// hardware's own, made for that challenge.
  Future<({Uint8List point, Uint8List evidence})> attestNewKey(
      String label, Uint8List challenge);

  /// The key [label] names signing [statementDigest] (the SHA-256 of the sign-in
  /// statement): ASN.1 DER ECDSA for Android and a TPM, an App Attest assertion
  /// for Apple.
  Future<Uint8List> signStatement(String label, Uint8List statementDigest);
}

/// An installed front end's key, in its device's secure hardware.
class HardwareFrontEndKey extends FrontEndKey {
  final HardwareKeyPlatform hardware;
  final String label;
  String _x, _y;
  HardwareFrontEndKey._(this.hardware, this.label, this._x, this._y);

  @override
  String get x => _x;
  @override
  String get y => _y;

  static (String, String) _coordinates(Uint8List p) {
    if (p.length != 65 || p[0] != 4) {
      throw const TrustRefused(
          'the device\'s hardware did not give an uncompressed P-256 key');
    }
    return (b64uEncode(p.sublist(1, 33)), b64uEncode(p.sublist(33)));
  }

  /// The key [label] names, made on first use. A refusal from the hardware (no
  /// secure hardware, a key that is not P-256) is the platform's to throw.
  static Future<HardwareFrontEndKey> open(
      HardwareKeyPlatform hardware, String label) async {
    final (x, y) = _coordinates(await hardware.publicPoint(label));
    return HardwareFrontEndKey._(hardware, label, x, y);
  }

  @override
  bool get isNonExtractable => true;

  @override
  FrontEndKind get kind => FrontEndKind.installedApp;

  @override
  Future<String> sign(String message) async => b64uEncode(derToRaw(
      await hardware.signDer(label, Uint8List.fromList(utf8.encode(message)))));

  @override
  Future<InstalledKeyProof?> prove(String assetId, InstalledAsk ask) async {
    final challenge = b64uDecode(ask.challenge);
    if (challenge == null) {
      throw const TrustRefused('the ask\'s challenge is not readable');
    }
    final made = await hardware.attestNewKey(label, challenge);
    final (x, y) = _coordinates(made.point);
    _x = x;
    _y = y;
    final digest = installedAppStatementDigest(assetId, challenge, thumbprint);
    return InstalledKeyProof(
        platform: hardware.platform,
        evidence: made.evidence,
        ask: ask.ask,
        keySignature: await hardware.signStatement(label, digest));
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
