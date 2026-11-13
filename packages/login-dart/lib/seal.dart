import 'package:meta/meta.dart' show visibleForTesting;
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'package:http/http.dart' as http;

import 'app_checks.dart';

/// Sealed front-end traffic (ADR-072 section 2 step 5, Amendment 4): the Dart
/// port of identity-bot's `packages/login-web/src/seal.ts` and
/// `packages/login-go/seal.go`, held to the cases all three run
/// (`packages/login-web/test-vectors/seal.json`):
/// `test/every_sealed_case_is_the_one_the_go_and_the_typescript_run_test.dart`. For every installed platform alike.
///
/// Every call to the app's back end is one POST to [sealPath] whose body is
/// `{"v":1,"epk":…,"ct":…}`, and every answer one 200 whose body is
/// `{"v":1,"n":…,"ct":…}`. The call and the answer are inside `ct`. A fresh P-256
/// key per call is agreed with the back end's sealing key by ECDH; HKDF-SHA256,
/// salted by epk||sealing key (and, for the answer, `n`: 16 to 32 random bytes
/// the back end makes, so two answers to one call never share a key and nonce),
/// gives each direction its own AES-256-GCM key and nonce; the version, relay
/// identifier, direction and epk (and `n`) are the associated data. The
/// plaintext is its length (4 bytes), the content, then zeros to a bucket of
/// 1024 bytes, doubling.
const sealPath = '/sealed';
const sealVersion = 1;
const sealBucket = 1024;
const sealMax = 16 << 20;
const _label = 'APP-SEAL-V1';
const answerNMin = 16;
const answerNMax = 32;

/// Every refusal of a sealed message. It says nothing about why.
class SealRefused implements Exception {
  const SealRefused();
  String get message => 'the sealed message is not accepted';
  @override
  String toString() => message;
}

final _curve = ECCurve_secp256r1();

int _bucketFor(int n) {
  var b = sealBucket;
  while (b < n + 4) {
    b *= 2;
  }
  return b;
}

Uint8List _pad(List<int> content) {
  if (content.length > sealMax) throw const SealRefused();
  final out = Uint8List(_bucketFor(content.length));
  ByteData.sublistView(out).setUint32(0, content.length);
  out.setRange(4, 4 + content.length, content);
  return out;
}

/// [_unpad] for the tests: a padded message that declares more than a message may carry.
@visibleForTesting
Uint8List unpadForTest(Uint8List p) => _unpad(p);

Uint8List _unpad(Uint8List p) {
  if (p.length < 4) throw const SealRefused();
  final n = ByteData.sublistView(p).getUint32(0);
  if (n > p.length - 4 || n > sealMax || p.length != _bucketFor(n)) {
    throw const SealRefused();
  }
  for (var i = 4 + n; i < p.length; i++) {
    if (p[i] != 0) throw const SealRefused();
  }
  return Uint8List.sublistView(p, 4, 4 + n);
}

Uint8List _hkdf(Uint8List secret, Uint8List salt, String info, int bytes) {
  final k = HKDFKeyDerivator(SHA256Digest())
    ..init(HkdfParameters(secret, bytes, salt, Uint8List.fromList(utf8.encode(info))));
  final out = Uint8List(bytes);
  k.deriveKey(null, 0, out, 0);
  return out;
}

class _Dir {
  final Uint8List key, nonce, aad;
  _Dir(this.key, this.nonce, this.aad);
}

_Dir _direction(
    Uint8List secret, Uint8List epk, Uint8List spk, String rid, String dir,
    [Uint8List? n]) {
  final salt = Uint8List.fromList([...epk, ...spk, ...?n]);
  final nPart = n == null ? '' : '\n${b64uEncode(n)}';
  final aad = '$_label\n$rid\n$dir\n$sealVersion\n${b64uEncode(epk)}$nPart';
  return _Dir(
      _hkdf(secret, salt, '$_label $dir key\n$rid', 32),
      _hkdf(secret, salt, '$_label $dir nonce\n$rid', 12),
      Uint8List.fromList(utf8.encode(aad)));
}

Uint8List _sealWith(_Dir d, List<int> content) {
  final c = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(d.key), 128, d.nonce, d.aad));
  return c.process(_pad(content));
}

Uint8List _openWith(_Dir d, Uint8List ct) {
  final c = GCMBlockCipher(AESEngine())
    ..init(false, AEADParameters(KeyParameter(d.key), 128, d.nonce, d.aad));
  try {
    return _unpad(c.process(ct));
  } on InvalidCipherTextException {
    throw const SealRefused();
  } on ArgumentError {
    throw const SealRefused();
  }
}

/// What one sealed call leaves behind to open its answer.
class SealReply {
  final Uint8List _secret, _epk, _spk;
  final String _rid;
  SealReply._(this._secret, this._epk, this._spk, this._rid);

  /// Seals an answer's [content] (a back end's side, for tests). [n] is for the
  /// vectors; an answer makes its own 32 random bytes.
  String seal(List<int> content, {Uint8List? n}) {
    final nn = n ?? _secureRandom().nextBytes(answerNMax);
    if (nn.length < answerNMin || nn.length > answerNMax) {
      throw const SealRefused();
    }
    final d = _direction(_secret, _epk, _spk, _rid, 'answer', nn);
    return jsonEncode(
        {'v': sealVersion, 'n': b64uEncode(nn), 'ct': b64uEncode(_sealWith(d, content))});
  }

  /// Opens a sealed answer; a [SealRefused] if it is not this call's.
  Uint8List open(String outer) {
    Object? o;
    try {
      o = jsonDecode(outer);
    } catch (_) {
      throw const SealRefused();
    }
    if (o is! Map || (o.keys.toList()..sort()).join(',') != 'ct,n,v') {
      throw const SealRefused();
    }
    final ct = b64uDecode(o['ct']);
    final n = b64uDecode(o['n']);
    if (o['v'] != sealVersion ||
        ct == null ||
        n == null ||
        n.length < answerNMin ||
        n.length > answerNMax) {
      throw const SealRefused();
    }
    return _openWith(_direction(_secret, _epk, _spk, _rid, 'answer', n), ct);
  }
}

Uint8List _bigToBytes(BigInt v, int len) {
  final out = Uint8List(len);
  var x = v;
  for (var i = len - 1; i >= 0; i--) {
    out[i] = (x & BigInt.from(0xff)).toInt();
    x = x >> 8;
  }
  return out;
}

BigInt _bytesToBig(List<int> b) =>
    b.fold(BigInt.zero, (a, v) => (a << 8) | BigInt.from(v));

/// A public key from its 65 uncompressed bytes, which must be a point of the
/// curve: anything else is a [SealRefused].
ECPublicKey _publicKey(Uint8List point) {
  if (point.length != 65 || point[0] != 4) throw const SealRefused();
  final x = _bytesToBig(point.sublist(1, 33));
  final y = _bytesToBig(point.sublist(33));
  final c = _curve.curve;
  final p = (c as dynamic).q as BigInt;
  if (x >= p || y >= p) throw const SealRefused();
  // y^2 = x^3 + ax + b (mod p)
  final lhs = (y * y) % p;
  final rhs = (x * x * x + c.a!.toBigInteger()! * x + c.b!.toBigInteger()!) % p;
  if (lhs != rhs) throw const SealRefused();
  final q = c.createPoint(x, y);
  return ECPublicKey(q, ECDomainParameters('prime256v1'));
}

Uint8List _agree(BigInt d, Uint8List peer) {
  final a = ECDHBasicAgreement()
    ..init(ECPrivateKey(d, ECDomainParameters('prime256v1')));
  try {
    return _bigToBytes(a.calculateAgreement(_publicKey(peer)), 32);
  } on SealRefused {
    rethrow;
  } catch (_) {
    throw const SealRefused();
  }
}

Uint8List _publicOf(BigInt d) =>
    (_curve.G * d)!.getEncoded(false);

BigInt _freshScalar(SecureRandom rng) {
  while (true) {
    final d = _bytesToBig(rng.nextBytes(32));
    if (d > BigInt.zero && d < _curve.n) return d;
  }
}

SecureRandom _secureRandom() {
  final r = FortunaRandom();
  final dart = Random.secure();
  r.seed(KeyParameter(Uint8List.fromList(List.generate(32, (_) => dart.nextInt(256)))));
  return r;
}

/// Seals [content] (a call) for the back end whose sealing key is [spk] (65
/// bytes), as the relay identifier [rid]. [ephemeral] is for the vectors; a call
/// makes its own. Gives the body to POST to [sealPath] and the reply that opens
/// its answer.
({String outer, SealReply reply}) sealRequest(
    String rid, Uint8List spk, List<int> content,
    {BigInt? ephemeral}) {
  _publicKey(spk); // not a point on the curve: refused before anything is made
  final d = ephemeral ?? _freshScalar(_secureRandom());
  final epk = _publicOf(d);
  final secret = _agree(d, spk);
  final ct = _sealWith(_direction(secret, epk, spk, rid, 'request'), content);
  return (
    outer: jsonEncode({'v': sealVersion, 'epk': b64uEncode(epk), 'ct': b64uEncode(ct)}),
    reply: SealReply._(secret, epk, spk, rid),
  );
}

/// The back end's side, for tests and vectors: opens a sealed call with the
/// sealing key's private scalar [d]. A real back end is `login-go`'s
/// `SealKey.OpenRequest`.
({Uint8List content, SealReply reply}) openRequest(
    String rid, BigInt d, String outer) {
  Object? o;
  try {
    o = jsonDecode(outer);
  } catch (_) {
    throw const SealRefused();
  }
  if (o is! Map || (o.keys.toList()..sort()).join(',') != 'ct,epk,v') {
    throw const SealRefused();
  }
  final epk = b64uDecode(o['epk']);
  final ct = b64uDecode(o['ct']);
  if (o['v'] != sealVersion || epk == null || ct == null) {
    throw const SealRefused();
  }
  final spk = _publicOf(d);
  final secret = _agree(d, epk);
  final content = _openWith(_direction(secret, epk, spk, rid, 'request'), ct);
  return (content: content, reply: SealReply._(secret, epk, spk, rid));
}

/// What the relay identifier's key signs to vouch for a sealing key.
List<int> sealKeyStatementText(String rid, Uint8List pub, int sn) =>
    utf8.encode('APP-SEAL-KEY-V1\n$rid\n$sn\n${b64uEncode(pub)}');

/// The back end's sealing key the link carries, 65 bytes, with the relay
/// identifier's key log to remember, or a [TrustRefused] saying why not
/// (`checkSealKey` in `login-web/src/app.ts`). The statement is the identifier's
/// whole signed key log, the key, `sn` (the log's last sequence number) and the
/// signature of the key that log names NOW over the identifier, `sn` and the key.
/// The log is read as an answer's is, must carry on from the longest this app
/// already holds ([known]), and `sn` must be its last event: a key the
/// identifier has rotated away from vouches for nothing. [min] is the link's
/// latest event the owner's Identity Agent has seen (`readMinimum`): the log must
/// hold it, at that sequence number, so an app with no memory still takes no log
/// shorter than it.
({Uint8List key, String log}) checkSealKey(String rid, String encoded,
    {String? known, String? min}) {
  Never fail(String why) =>
      throw TrustRefused('the link\'s sealing key is refused: $why');
  final json = b64uDecode(encoded);
  if (json == null) fail('it is not readable');
  Object? st;
  try {
    st = jsonDecode(utf8.decode(json));
  } catch (_) {
    fail('it is not JSON');
  }
  if (st is! Map || (st.keys.map((k) => '$k').toList()..sort()).join(',') != 'key,log,sig,sn') {
    fail('it has fields it should not, or lacks some');
  }
  final key = b64uDecode(st['key']);
  final sig = b64uDecode(st['sig']);
  final text = st['log'];
  if (text is! String || key == null || sig == null) {
    fail('a part of it is not spelled one way');
  }
  if (key.length != 65 || key[0] != 4) {
    fail('the key is not an uncompressed P-256 point');
  }
  final got = readAnswerLog(rid, text, (why) => fail('its key log is refused: $why'));
  final sn = st['sn'];
  if (sn is! int || sn != got.events.length - 1) {
    fail('it is made at a sequence number other than its key log\'s last');
  }
  final floor = min == null ? null : readMinimum(min);
  if (min != null && floor == null) {
    fail('the link\'s latest key log event is not spelled one way');
  }
  if (floor != null &&
      (floor.sn >= got.events.length || got.events[floor.sn].said != floor.said)) {
    fail('its key log does not reach the latest event your Identity Agent has seen for the app\'s relay identifier: it may be an earlier log, from before a key was rotated away');
  }
  final keep = holdLog(rid, got, text, known, fail, floored: floor != null);
  if (!ed25519Verify(got.key, sealKeyStatementText(rid, key, sn), sig)) {
    fail('the relay identifier\'s current key did not sign this key');
  }
  return (key: key, log: keep);
}

/// The link's sealing key, checked against the log this app holds, which is then
/// the longer.
Uint8List checkedSealKey(AppLink link, AnswerLogs logs) {
  final r = checkSealKey(link.rid, link.seal,
      known: logs.get(link.rid), min: link.min);
  logs.set(link.rid, r.log);
  return r.key;
}

/// The headers the back end reads inside a sealed call. Any other is dropped
/// here, because the back end refuses a call that carries one.
const sealedHeaderNames = {
  'authorization',
  'content-type',
  'x-browser-proof-time',
  'x-browser-proof-nonce',
  'x-browser-proof',
  'x-browser-answer-nonce',
};

/// One answer from the back end, opened and shown to be the app's for this call.
typedef SealedAnswer = ({int status, String contentType, Uint8List body});

/// Makes a call that the relay between reads none of: one fixed POST whose body
/// is the call sealed for the back end. The answer is read only once opened and
/// shown to be the app's for this call ([checkAnswer]). A relay's own failure
/// is a [TrustRefused] that says so.
Future<SealedAnswer> sealedCall(
  http.Client client,
  AppLink link,
  Uint8List sealKey, {
  required String method,
  required String target,
  required Map<String, String> headers,
  required List<int> body,
  required String nonce,
  required AnswerLogs logs,
  required DateTime now,
}) async {
  final inner = utf8.encode(jsonEncode({
    'method': method,
    'target': target,
    'headers': {
      for (final e in headers.entries)
        if (sealedHeaderNames.contains(e.key.toLowerCase())) e.key.toLowerCase(): e.value,
      'x-browser-answer-nonce': nonce,
    },
    'body': utf8.decode(body),
    'ts': '${now.toUtc().toIso8601String().split('.').first}Z',
  }));
  final sealed = sealRequest(link.rid, sealKey, inner);
  final r = await client.post(Uri.parse('${link.api}$sealPath'),
      headers: {'content-type': 'application/json'}, body: sealed.outer);
  if (r.statusCode != 200) {
    throw TrustRefused(
        'the app\'s relay did not carry the call (${r.statusCode})');
  }
  Object? a;
  try {
    a = jsonDecode(utf8.decode(sealed.reply.open(utf8.decode(r.bodyBytes))));
  } on SealRefused {
    throw const TrustRefused('the answer is not the app\'s: it does not open');
  } catch (_) {
    throw const TrustRefused('the answer is not the app\'s: it is not readable');
  }
  final bytes = a is Map ? b64uDecode(a['body']) : null;
  if (a is! Map || a['status'] is! int || a['content_type'] is! String || bytes == null) {
    throw const TrustRefused('the answer is not the app\'s: it is not readable');
  }
  logs.set(
      link.rid,
      checkAnswer(
          rid: link.rid,
          nonce: nonce,
          status: a['status'] as int,
          contentType: a['content_type'] as String,
          body: bytes,
          log: a['log'] is String ? a['log'] as String : null,
          known: logs.get(link.rid),
          sig: a['sig'] is String ? a['sig'] as String : null));
  return (status: a['status'] as int, contentType: a['content_type'] as String, body: bytes);
}
