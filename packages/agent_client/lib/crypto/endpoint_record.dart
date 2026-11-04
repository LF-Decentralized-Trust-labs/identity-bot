import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// An identifier's signed statement of the one origin it can be reached at, and
/// the check an app makes of one it was handed.
///
/// A computer told that an organisation moved must not believe whoever says so:
/// a plain reverse proxy can put any address in front of the old one. The proof
/// is the organisation's own signature over the new origin, checked against the
/// key its verified key log names NOW, never against a key the record brings.
///
/// The form, and the vectors every implementation is tested against, are the
/// Go package `endpointrecord` (identity-agent-core/endpointrecord/
/// endpoint-record-vectors.json). A record is five strings: type, aid, origin,
/// issued and signature. The signature is Ed25519 over the other four as a JSON
/// object, keys sorted, no whitespace (ADR-049's form), written CESR qb64
/// (code 0B). This file decides valid or invalid and nothing else: which witness
/// to ask, and which key the log names, are the caller's.
const endpointRecordType = 'endpoint-record/1';

/// How far ahead of the checker's clock a record may be issued.
const endpointRecordMaxFuture = Duration(minutes: 10);

/// The answer to checking a record.
class EndpointRecordCheck {
  const EndpointRecordCheck._(this.valid, this.reason, this.origin, this.issued);

  /// Whether the record is the identifier's own statement.
  final bool valid;

  /// Why not, when it is not.
  final String reason;

  /// The origin the record names, when it is valid. Empty for a withdrawal.
  final String origin;

  /// When the record was issued, when it is valid. A record replaces another
  /// for the same identifier only when this is later.
  final DateTime? issued;

  /// Valid, and says the identifier is reachable nowhere. A caller that needs an
  /// address must refuse it.
  bool get isWithdrawal => valid && origin.isEmpty;

  static EndpointRecordCheck _no(String why) =>
      EndpointRecordCheck._(false, why, '', null);
}

final _label = RegExp(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$');
final _numeric = RegExp(r'^(0[xX][0-9a-fA-F]*|[0-9]+)$');
final _port = RegExp(r'^[1-9][0-9]{0,4}$');
final _issuedForm = RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$');
final _b64url = RegExp(r'^[A-Za-z0-9_-]+$');

/// Null when [o] is an origin in its one spelling, or the reason it is not.
///
/// scheme http or https in lower case; a lower-case DNS name, an IPv4 address,
/// or an IPv6 address in brackets written compressed and in lower case; the
/// port always written, 1 to 65535 with no leading zero; nothing after it.
String? originProblem(String o) {
  final at = o.indexOf('://');
  if (at < 0) return 'no scheme';
  final scheme = o.substring(0, at);
  if (scheme != 'http' && scheme != 'https') return 'the scheme is http or https';
  final rest = o.substring(at + 3);
  String port;
  if (rest.startsWith('[')) {
    final end = rest.indexOf(']');
    if (end < 0 || !rest.substring(end + 1).startsWith(':')) {
      return 'an IPv6 host is [address]:port';
    }
    final inner = rest.substring(1, end);
    port = rest.substring(end + 2);
    if (!_isCompressedLowerIPv6(inner)) return 'the IPv6 address is not in its one spelling';
  } else {
    final colon = rest.lastIndexOf(':');
    if (colon < 0) return 'no port; write it, even the default';
    final host = rest.substring(0, colon);
    port = rest.substring(colon + 1);
    if (host.isEmpty || host.length > 253) return 'the host is empty or too long';
    for (final l in host.split('.')) {
      if (l.length > 63 || !_label.hasMatch(l)) return 'the host is not a DNS name in lower case';
    }
    // A host whose last label is a number, or reads as one (0x7f), is an IPv4
    // address to a resolver ("127.1", "2130706433" and "0x7f.1" are all
    // 127.0.0.1), so it is accepted only as four decimal numbers without a
    // leading zero.
    if (_numeric.hasMatch(host.split('.').last) && !_isDottedQuad(host)) {
      return 'the host is a number that is not four decimal numbers';
    }
  }
  if (!_port.hasMatch(port) || int.parse(port) > 65535) {
    return 'the port is 1 to 65535 with no leading zero, and nothing may follow it';
  }
  return null;
}

bool _isDottedQuad(String h) {
  final parts = h.split('.');
  if (parts.length != 4) return false;
  for (final p in parts) {
    if (!RegExp(r'^(0|[1-9][0-9]{0,2})$').hasMatch(p) || int.parse(p) > 255) return false;
  }
  return true;
}

/// IPv6 in the one spelling: what RFC 5952 writes. Parsed to eight groups, then
/// written back and compared, so a second spelling of one address fails.
bool _isCompressedLowerIPv6(String s) {
  if (s.isEmpty || s.contains('%') || s.contains('.')) return false;
  if (s != s.toLowerCase()) return false;
  final halves = s.split('::');
  if (halves.length > 2) return false;
  List<int>? groups(String part) {
    if (part.isEmpty) return <int>[];
    final out = <int>[];
    for (final g in part.split(':')) {
      if (!RegExp(r'^[0-9a-f]{1,4}$').hasMatch(g)) return null;
      out.add(int.parse(g, radix: 16));
    }
    return out;
  }

  final head = groups(halves[0]);
  final tail = halves.length == 2 ? groups(halves[1]) : <int>[];
  if (head == null || tail == null) return false;
  List<int> all;
  if (halves.length == 2) {
    final missing = 8 - head.length - tail.length;
    if (missing < 1) return false;
    all = [...head, ...List.filled(missing, 0), ...tail];
  } else {
    if (head.length != 8) return false;
    all = head;
  }
  // Write it back the way RFC 5952 does: the longest run of two or more zero
  // groups (the first, on a tie) becomes '::'.
  var bestStart = -1, bestLen = 0;
  for (var i = 0; i < 8;) {
    if (all[i] != 0) {
      i++;
      continue;
    }
    var j = i;
    while (j < 8 && all[j] == 0) {
      j++;
    }
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  String hex(Iterable<int> gs) => gs.map((g) => g.toRadixString(16)).join(':');
  final written = bestLen >= 2
      ? '${hex(all.take(bestStart))}::${hex(all.skip(bestStart + bestLen))}'
      : hex(all);
  return written == s;
}

/// The origin of an address as the form writes it (scheme and host in lower
/// case, the port always written), or null when it is not an http or https
/// address with a host. Path, query and fragment are not part of an origin.
String? canonicalOriginOf(String address) {
  final u = Uri.tryParse(address);
  if (u == null || !u.hasAuthority || u.host.isEmpty || u.userInfo.isNotEmpty) {
    return null;
  }
  final scheme = u.scheme.toLowerCase();
  if (scheme != 'http' && scheme != 'https') return null;
  // Dart reads "0443" as 443 (and drops a default port from hasPort), and the
  // form does not, so the port as WRITTEN must be the port it means.
  final afterScheme = address.substring(address.indexOf('://') + 3);
  final authority = afterScheme.split(RegExp(r'[/?#]')).first;
  final close = authority.lastIndexOf(']');
  final colon = authority.lastIndexOf(':');
  if (colon > close && authority.substring(colon + 1) != u.port.toString()) {
    return null;
  }
  final host = u.host.contains(':') ? '[${u.host.toLowerCase()}]' : u.host.toLowerCase();
  final origin = '$scheme://$host:${u.port}';
  return originProblem(origin) == null ? origin : null;
}

Uint8List? _strictB64url(String s) {
  if (!_b64url.hasMatch(s)) return null;
  final Uint8List raw;
  try {
    raw = base64Url.decode(base64Url.normalize(s));
  } on FormatException {
    return null;
  }
  // The one spelling: re-encoding must give the string back, so spare bits set
  // in the last character are refused.
  if (base64Url.encode(raw).replaceAll('=', '') != s) return null;
  return raw;
}

Uint8List? _keyRaw(String qb64) {
  if (qb64.length != 44 || (qb64[0] != 'D' && qb64[0] != 'B')) return null;
  final raw = _strictB64url('A${qb64.substring(1)}');
  if (raw == null || raw[0] != 0) return null;
  return Uint8List.fromList(raw.sublist(1));
}

Uint8List? _sigRaw(String qb64) {
  if (qb64.length != 88 || !qb64.startsWith('0B')) return null;
  final raw = _strictB64url('AA${qb64.substring(2)}');
  if (raw == null || raw[0] != 0 || raw[1] != 0) return null;
  return Uint8List.fromList(raw.sublist(2));
}

bool _printable(String s) => s.codeUnits.every((c) => c >= 0x20 && c <= 0x7e);

String _jsonString(String s) =>
    '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

/// The bytes a record's signature is over, or null when it is not five strings
/// of printable ASCII.
String? endpointRecordSignedBytes(Map<String, dynamic> record) {
  final keys = record.keys.where((k) => k != 'signature').toList()..sort();
  final parts = <String>[];
  for (final k in keys) {
    final v = record[k];
    if (v is! String || !_printable(k) || !_printable(v)) return null;
    parts.add('${_jsonString(k)}:${_jsonString(v)}');
  }
  return '{${parts.join(',')}}';
}

/// Whether [record] is its identifier's own statement.
///
/// [currentKey] is the key the identifier's VERIFIED key log names now, as CESR
/// qb64 (`D...`): the caller's, from a log it has checked, never from the record
/// or from whoever served it. A record signed by a key the log has since
/// rotated away from is invalid; its signer publishes again.
///
/// [now] is the checker's clock, for the bound on a record issued ahead of it.
EndpointRecordCheck verifyEndpointRecord(
  Map<String, dynamic> record,
  String currentKey, {
  DateTime? now,
}) {
  const fields = ['type', 'aid', 'origin', 'issued', 'signature'];
  if (record.length != fields.length ||
      !fields.every((f) => record[f] is String)) {
    return EndpointRecordCheck._no(
        'a record has exactly the string fields type, aid, origin, issued and signature');
  }
  if (record['type'] != endpointRecordType) {
    return EndpointRecordCheck._no('the record is not an $endpointRecordType');
  }
  final aid = record['aid'] as String;
  if (aid.isEmpty || aid.length > 128) {
    return EndpointRecordCheck._no('the record names no identifier');
  }
  final origin = record['origin'] as String;
  if (origin.isNotEmpty) {
    final why = originProblem(origin);
    if (why != null) return EndpointRecordCheck._no('origin: $why');
  }
  final issuedText = record['issued'] as String;
  if (!_issuedForm.hasMatch(issuedText)) {
    return EndpointRecordCheck._no('issued is not YYYY-MM-DDTHH:MM:SSZ');
  }
  final issued = DateTime.tryParse(issuedText);
  if (issued == null || _formatIssued(issued) != issuedText) {
    return EndpointRecordCheck._no('issued is not a time');
  }
  final clock = (now ?? DateTime.now()).toUtc();
  if (issued.isAfter(clock.add(endpointRecordMaxFuture))) {
    return EndpointRecordCheck._no('the record is issued in the future');
  }
  final sig = _sigRaw(record['signature'] as String);
  if (sig == null) {
    return EndpointRecordCheck._no('the signature is not a CESR Ed25519 signature');
  }
  final key = _keyRaw(currentKey);
  if (key == null) {
    return EndpointRecordCheck._no('the key is not a CESR Ed25519 key');
  }
  final signed = endpointRecordSignedBytes(record);
  if (signed == null) {
    return EndpointRecordCheck._no('a field is not printable ASCII');
  }
  final ok = ed.verify(
      ed.PublicKey(key), Uint8List.fromList(utf8.encode(signed)), sig);
  if (!ok) {
    return EndpointRecordCheck._no(
        'the record is not signed by the identifier\'s current key');
  }
  return EndpointRecordCheck._(true, '', origin, issued);
}

String _formatIssued(DateTime t) {
  final u = t.toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${u.year.toString().padLeft(4, '0')}-${two(u.month)}-${two(u.day)}'
      'T${two(u.hour)}:${two(u.minute)}:${two(u.second)}Z';
}

/// Whether [a] replaces [b]: the same identifier, and [a] issued strictly
/// after [b]. Both must already be valid; equal is not newer.
bool endpointRecordReplaces(Map<String, dynamic> a, Map<String, dynamic> b) {
  if (a['aid'] != b['aid']) return false;
  final ta = _issuedOf(a), tb = _issuedOf(b);
  return ta != null && tb != null && ta.isAfter(tb);
}

DateTime? _issuedOf(Map<String, dynamic> r) {
  final s = r['issued'];
  if (s is! String || !_issuedForm.hasMatch(s)) return null;
  final t = DateTime.tryParse(s);
  return t == null || _formatIssued(t) != s ? null : t;
}
