/// Verifies the signed, published list of launch measurements an owner will
/// accept a sealed machine for. The second implementation of one wire contract,
/// beside `identity-agent-core/measurementlist` (Go); the two must agree, so
/// both are tested against the same files in
/// `identity-agent-core/measurementlist/testdata` (this package's test reads
/// them), and the format is documented once, in the Go package.
///
/// Pure Dart on purpose (no Flutter, no storage): deciding what a list says is
/// separate from where it is fetched and where the highest accepted sequence is
/// kept.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// Why a list was refused. [code] is the Go package's error name, so a shared
/// test vector states one expectation for both.
class MeasurementListRefusal implements Exception {
  const MeasurementListRefusal(this.code, [this.detail = '']);
  final String code;
  final String detail;
  @override
  String toString() => detail.isEmpty ? code : '$code: $detail';
}

class MeasurementEntry {
  MeasurementEntry(this.image, this.measurement, this.validFrom, this.validUntil);
  final String image;
  final String measurement; // 96 lowercase hex
  final DateTime validFrom;
  final DateTime? validUntil;
  bool validAt(DateTime t) =>
      !t.isBefore(validFrom) && (validUntil == null || t.isBefore(validUntil!));
}

class VerifiedMeasurementList {
  VerifiedMeasurementList(this.sequence, this.digest, this.images, this.verifiedAt);
  final int sequence;

  /// Hex SHA-256 of the signed bytes, the same value the Go core records.
  final String digest;
  final Map<String, List<MeasurementEntry>> images;
  final DateTime verifiedAt;

  /// What the list accepts for [kind] at [at]. Empty means accept nothing,
  /// never "no restriction".
  List<String> measurementsAt(String kind, DateTime at) => [
        for (final e in images[kind] ?? const <MeasurementEntry>[])
          if (e.validAt(at)) e.measurement
      ];
}

const int maxListBytes = 1 << 20;
const String _signingPrefix = 'measurement-list-v1\n';

/// Public halves of keys whose private halves are printed in a standard. Same
/// set as `publishedTestKeys` in the Go package.
const Map<String, String> _publishedTestKeys = {
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a': 'RFC 8032 §7.1 Test 1',
};

final RegExp _rfc3339 =
    RegExp(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$');

bool _isHex(Object? s, int bytes) => s is String && RegExp('^[0-9a-f]{${bytes * 2}}\$').hasMatch(s);

/// Reads a pinned public key (lowercase hex). Refuses an empty key and a key
/// whose private half is public.
ed.PublicKey parsePinnedKeyHex(String hex) {
  if (hex.isEmpty) throw const MeasurementListRefusal('ErrNoKey', 'no publisher key is pinned in this build');
  if (!_isHex(hex, 32)) {
    throw const MeasurementListRefusal('ErrNoKey', 'the pinned publisher key is not 32 bytes of lowercase hex');
  }
  final which = _publishedTestKeys[hex];
  if (which != null) {
    throw MeasurementListRefusal('ErrNoKey', 'the pinned publisher key is $which, whose private key is public');
  }
  return ed.PublicKey(Uint8List.fromList([
    for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)
  ]));
}

/// Checks [raw] and returns the list only if every check passes. No partial
/// acceptance: any fault refuses the whole list.
///
/// [minSequence] is the highest sequence already accepted; [seenDigest] the
/// hash of the list accepted at it, or '' if unknown.
VerifiedMeasurementList verifyMeasurementList(
  Uint8List raw, {
  required String publisherKeyHex,
  required String publisherKeyId,
  required DateTime now,
  int minSequence = 0,
  String seenDigest = '',
}) {
  if (publisherKeyId.isEmpty) throw const MeasurementListRefusal('ErrNoKey', 'no publisher key id');
  final key = parsePinnedKeyHex(publisherKeyHex);
  if (raw.isEmpty || raw.length > maxListBytes) {
    throw MeasurementListRefusal('ErrMalformed', '${raw.length} bytes');
  }
  final Object? doc;
  try {
    doc = _StrictJson(utf8.decode(raw)).parse();
  } on FormatException catch (e) {
    throw MeasurementListRefusal('ErrMalformed', e.message);
  }
  if (doc is! Map<String, Object?>) throw const MeasurementListRefusal('ErrMalformed', 'not an object');
  const topFields = {
    'list_version', 'sequence', 'published_at', 'expires_at', 'signing_key_id', 'images', 'signature'
  };
  for (final k in doc.keys) {
    if (!topFields.contains(k)) throw MeasurementListRefusal('ErrMalformed', 'unknown field "$k"');
  }
  if (doc['list_version'] != 1) throw MeasurementListRefusal('ErrUnknownVersion', '${doc['list_version']}');
  if (doc['signing_key_id'] != publisherKeyId) {
    throw MeasurementListRefusal('ErrWrongKeyID', '"${doc['signing_key_id']}"');
  }
  final sigText = doc['signature'];
  final sig = sigText is String ? _decodeBase64Url(sigText, 64) : null;
  if (sig == null) throw const MeasurementListRefusal('ErrBadSignature', 'not 64 bytes in unpadded base64url');

  final unsigned = Map<String, Object?>.of(doc)..remove('signature');
  final msg = Uint8List.fromList(utf8.encode(_signingPrefix + _canonical(unsigned)));
  if (!ed.verify(key, msg, sig)) throw const MeasurementListRefusal('ErrBadSignature');

  // Signed, so the content is the publisher's. Still held to the rules.
  final sequence = doc['sequence'];
  if (sequence is! int || sequence < 1) throw MeasurementListRefusal('ErrMalformed', 'sequence $sequence');
  if (sequence < minSequence) {
    throw MeasurementListRefusal('ErrOldList', 'sequence $sequence, already accepted $minSequence');
  }
  final digest = sha256.convert(msg).toString();
  if (sequence == minSequence && seenDigest.isNotEmpty && digest != seenDigest) {
    throw MeasurementListRefusal('ErrConflictingList', 'sequence $sequence');
  }
  final published = _time(doc['published_at'], 'published_at', 'ErrMalformed');
  final expires = _time(doc['expires_at'], 'expires_at', 'ErrMalformed');
  if (!expires.isAfter(published)) {
    throw const MeasurementListRefusal('ErrMalformed', 'expires_at is not after published_at');
  }
  if (!now.isBefore(expires)) throw const MeasurementListRefusal('ErrExpired');
  if (published.isAfter(now)) throw const MeasurementListRefusal('ErrNotYetPublished');

  final images = doc['images'];
  if (images is! Map<String, Object?> || images.isEmpty) {
    throw const MeasurementListRefusal('ErrMalformed', 'no image kinds');
  }
  final out = <String, List<MeasurementEntry>>{};
  final seen = <String>{};
  images.forEach((kind, entries) {
    if (kind.isEmpty) throw const MeasurementListRefusal('ErrMalformed', 'an empty image kind');
    if (entries is! List || entries.isEmpty) {
      throw MeasurementListRefusal('ErrMalformed', 'image kind "$kind" has no measurements');
    }
    for (final e in entries) {
      final entry = _entry(e);
      // Listed twice, or under two kinds, would let one image stand as another.
      if (!seen.add(entry.measurement)) throw const MeasurementListRefusal('ErrDuplicateEntries');
      (out[kind] ??= []).add(entry);
    }
  });
  return VerifiedMeasurementList(sequence, digest, out, now);
}

MeasurementEntry _entry(Object? e) {
  if (e is! Map<String, Object?>) throw const MeasurementListRefusal('ErrBadEntry', 'not an object');
  const fields = {'image', 'measurement', 'computed_from', 'valid_from', 'valid_until'};
  for (final k in e.keys) {
    if (!fields.contains(k)) throw MeasurementListRefusal('ErrBadEntry', 'unknown field "$k"');
  }
  final m = e['measurement'];
  if (!_isHex(m, 48)) throw const MeasurementListRefusal('ErrBadMeasurement');
  final c = e['computed_from'];
  if (c is! Map<String, Object?>) throw const MeasurementListRefusal('ErrBadEntry', 'computed_from');
  const cFields = {
    'ovmf_sha256', 'vcpus', 'cpu_model', 'guest_features', 'cmdline_sha256',
    'kernel_sha256', 'initrd_sha256', 'root_hash'
  };
  for (final k in c.keys) {
    if (!cFields.contains(k)) throw MeasurementListRefusal('ErrBadEntry', 'unknown field "$k"');
  }
  bad(String what) => MeasurementListRefusal('ErrBadEntry', what);
  if (e['image'] is! String || (e['image'] as String).isEmpty) throw bad('no image name');
  if (!_isHex(c['ovmf_sha256'], 32)) throw bad('ovmf_sha256');
  if (c['vcpus'] is! int || (c['vcpus'] as int) < 1) throw bad('vcpus');
  if (c['cpu_model'] is! String || (c['cpu_model'] as String).isEmpty) throw bad('cpu_model');
  if (!_isHex(c['cmdline_sha256'], 32)) throw bad('cmdline_sha256');
  for (final k in const ['kernel_sha256', 'initrd_sha256']) {
    if (c.containsKey(k) && c[k] != '' && !_isHex(c[k], 32)) throw bad(k);
  }
  final from = _time(e['valid_from'], 'valid_from', 'ErrBadEntry');
  DateTime? until;
  if (e['valid_until'] != null) {
    until = _time(e['valid_until'], 'valid_until', 'ErrBadEntry');
    if (!until.isAfter(from)) throw bad('valid_until');
  }
  return MeasurementEntry(e['image'] as String, m as String, from, until);
}

DateTime _time(Object? v, String field, String code) {
  if (v is! String || !_rfc3339.hasMatch(v)) throw MeasurementListRefusal(code, field);
  try {
    return DateTime.parse(v).toUtc();
  } on FormatException {
    throw MeasurementListRefusal(code, field);
  }
}

/// Strict unpadded base64url of exactly [size] bytes, with zero spare bits.
Uint8List? _decodeBase64Url(String s, int size) {
  if (s.length != (size * 4 + 2) ~/ 3) return null;
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(s)) return null;
  try {
    final bytes = base64Url.decode(base64Url.normalize(s));
    if (bytes.length != size) return null;
    // Re-encoding must give the same text, which rejects non-zero spare bits.
    if (base64Url.encode(bytes).replaceAll('=', '') != s) return null;
    return Uint8List.fromList(bytes);
  } on FormatException {
    return null;
  }
}

/// RFC 8785 canonical form of a value made of objects, arrays, strings,
/// integers, booleans and null (all a list holds; a fraction is refused by the
/// parser).
String _canonical(Object? v) {
  if (v == null) return 'null';
  if (v is bool || v is int) return '$v';
  if (v is String) return _canonicalString(v);
  if (v is List) return '[${v.map(_canonical).join(',')}]';
  if (v is Map<String, Object?>) {
    // Dart compares strings by UTF-16 code unit, which is RFC 8785's order.
    final keys = v.keys.toList()..sort();
    return '{${keys.map((k) => '${_canonicalString(k)}:${_canonical(v[k])}').join(',')}}';
  }
  throw MeasurementListRefusal('ErrMalformed', 'unsupported ${v.runtimeType}');
}

String _canonicalString(String s) {
  final b = StringBuffer('"');
  for (final u in s.codeUnits) {
    switch (u) {
      case 0x22: b.write(r'\"');
      case 0x5c: b.write(r'\\');
      case 0x08: b.write(r'\b');
      case 0x0c: b.write(r'\f');
      case 0x0a: b.write(r'\n');
      case 0x0d: b.write(r'\r');
      case 0x09: b.write(r'\t');
      default:
        if (u < 0x20) {
          b.write('\\u${u.toRadixString(16).padLeft(4, '0')}');
        } else {
          b.writeCharCode(u);
        }
    }
  }
  return (b..write('"')).toString();
}

/// JSON parser that refuses what a signature check must not be fooled by: a
/// repeated key (two parsers would pick different ones), a fraction or
/// exponent, trailing text.
class _StrictJson {
  _StrictJson(this.s);
  final String s;
  int i = 0;

  Object? parse() {
    final v = _value();
    _ws();
    if (i != s.length) throw FormatException('trailing text at $i');
    return v;
  }

  void _ws() {
    while (i < s.length && ' \t\n\r'.contains(s[i])) {
      i++;
    }
  }

  Never _bad(String why) => throw FormatException('$why at $i');

  Object? _value() {
    _ws();
    if (i >= s.length) _bad('unexpected end');
    final c = s[i];
    if (c == '{') return _object();
    if (c == '[') return _array();
    if (c == '"') return _string();
    if (s.startsWith('true', i)) { i += 4; return true; }
    if (s.startsWith('false', i)) { i += 5; return false; }
    if (s.startsWith('null', i)) { i += 4; return null; }
    final m = RegExp(r'-?(0|[1-9]\d*)').matchAsPrefix(s, i);
    if (m == null) _bad('unexpected character');
    i = m.end;
    if (i < s.length && '.eE'.contains(s[i])) _bad('only whole numbers are allowed');
    final n = int.tryParse(m.group(0)!);
    if (n == null || n.abs() > 9007199254740991) _bad('number out of range');
    return n;
  }

  Map<String, Object?> _object() {
    i++;
    final out = <String, Object?>{};
    _ws();
    if (i < s.length && s[i] == '}') { i++; return out; }
    while (true) {
      _ws();
      if (i >= s.length || s[i] != '"') _bad('expected a key');
      final k = _string();
      if (out.containsKey(k)) _bad('repeated key "$k"');
      _ws();
      if (i >= s.length || s[i] != ':') _bad('expected :');
      i++;
      out[k] = _value();
      _ws();
      if (i < s.length && s[i] == ',') { i++; continue; }
      if (i < s.length && s[i] == '}') { i++; return out; }
      _bad('expected , or }');
    }
  }

  List<Object?> _array() {
    i++;
    final out = <Object?>[];
    _ws();
    if (i < s.length && s[i] == ']') { i++; return out; }
    while (true) {
      out.add(_value());
      _ws();
      if (i < s.length && s[i] == ',') { i++; continue; }
      if (i < s.length && s[i] == ']') { i++; return out; }
      _bad('expected , or ]');
    }
  }

  String _string() {
    i++;
    final b = StringBuffer();
    while (true) {
      if (i >= s.length) _bad('unterminated string');
      final c = s[i++];
      if (c == '"') return b.toString();
      if (c.codeUnitAt(0) < 0x20) _bad('control character in string');
      if (c != r'\') { b.write(c); continue; }
      if (i >= s.length) _bad('unterminated escape');
      final e = s[i++];
      switch (e) {
        case '"': b.write('"');
        case r'\': b.write(r'\');
        case '/': b.write('/');
        case 'b': b.write('\b');
        case 'f': b.write('\f');
        case 'n': b.write('\n');
        case 'r': b.write('\r');
        case 't': b.write('\t');
        case 'u':
          final h = i + 4 <= s.length ? s.substring(i, i + 4) : '';
          if (!RegExp(r'^[0-9a-fA-F]{4}$').hasMatch(h)) _bad('bad \\u escape');
          b.writeCharCode(int.parse(h, radix: 16));
          i += 4;
        default:
          _bad('bad escape');
      }
    }
  }
}
