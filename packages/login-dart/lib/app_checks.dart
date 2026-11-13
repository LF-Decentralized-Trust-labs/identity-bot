import 'dart:convert';
import 'dart:typed_data';

import 'package:blake3_dart/blake3_dart.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/export.dart' show SHA256Digest;

/// What the app's back end must prove before anything it says is believed.
///
/// The one Dart port of identity-bot's `@identity-agent/login-web/app`
/// (`packages/login-web/src/app.ts`: `readAppLink`, `checkAppKeyLog`,
/// `checkAppChallenge`, `checkAppAnswer`, `proofText`, `serverSkew`), for every
/// installed platform alike (iOS, Android, macOS, Windows). Held to
/// `packages/login-web/test-vectors/app-checks.json`, which the TypeScript runs
/// too: `test/the_app_is_believed_only_as_the_sdk_believes_it_test.dart`. A
/// browser does not use this: its page is the SDK itself.
class TrustRefused implements Exception {
  final String message;
  const TrustRefused(this.message);
  @override
  String toString() => message;
}

Never _fail(String prefix, String why) => throw TrustRefused('$prefix$why');

// ---- encodings -------------------------------------------------------------

final _b64url = RegExp(r'^[A-Za-z0-9_-]*$');

/// Unpadded base64url in its one spelling, or null.
Uint8List? b64uDecode(Object? s) {
  if (s is! String || !_b64url.hasMatch(s) || s.length % 4 == 1) return null;
  Uint8List out;
  try {
    out = base64Url.decode(base64Url.normalize(s));
  } catch (_) {
    return null;
  }
  return b64uEncode(out) == s ? out : null;
}

String b64uEncode(List<int> b) => base64Url.encode(b).replaceAll('=', '');

/// CESR fixed-size material under one code, as the core spells it.
Uint8List? _matter(Object? qb64, String code, int len) {
  final ps = (3 - (len % 3)) % 3;
  if (qb64 is! String || !qb64.startsWith(code) || code.length % 4 != ps) {
    return null;
  }
  final raw = b64uDecode('${'A' * ps}${qb64.substring(code.length)}');
  if (raw == null || raw.length != ps + len) return null;
  for (var i = 0; i < ps; i++) {
    if (raw[i] != 0) return null;
  }
  return Uint8List.sublistView(raw, ps);
}

Uint8List? decodeVerkey(Object? q) => _matter(q, 'D', 32);
Uint8List? decodeSig(Object? q) => _matter(q, '0B', 64);

String matterEncode(String code, Uint8List raw) {
  final ps = (3 - (raw.length % 3)) % 3;
  final padded = Uint8List(ps + raw.length)..setRange(ps, ps + raw.length, raw);
  return code + b64uEncode(padded).substring(code.length % 4);
}

bool ed25519Verify(Uint8List key, List<int> data, Uint8List sig) {
  try {
    return ed.verify(ed.PublicKey(key), Uint8List.fromList(data), sig);
  } catch (_) {
    return false; // anything it cannot check is refused, never accepted
  }
}

// ---- an identifier is the digest of its own inception -----------------------

/// Fails unless [aid] is the digest of the inception [text] with `d` and `i`
/// blanked, which is what makes an identifier self-addressing: nobody else's
/// event is it.
void deriveIdentifier(String text, String aid, void Function(String) fail) {
  final blank = '#' * aid.length;
  var dummy = text;
  for (final f in ['d', 'i']) {
    final needle = '"$f":"$aid"';
    if (dummy.split(needle).length != 2) {
      fail('its event names $f other than once');
    }
    dummy = dummy.replaceFirst(needle, '"$f":"$blank"');
  }
  final bytes = Uint8List.fromList(utf8.encode(dummy));
  if (matterEncode('E', blake3(bytes)) != aid) {
    fail('its inception does not derive the identifier');
  }
}

// ---- the link --------------------------------------------------------------

/// What the app's link says: `PAGE#aid=…&kel=…&rid=…&api=…&seal=…&min=…` (the
/// app's identifier, its key log, its relay identifier, its back end's address,
/// the sealing key its calls are sealed to, which the relay identifier vouches
/// for: `checkSealKey`, and [min], the latest event of the relay identifier's key
/// log the owner's Identity Agent has seen, `<sequence number>.<SAID>`, which the
/// log shown must hold). A fragment is never sent to any server.
class AppLink {
  final String aid, kel, rid, api, seal, min;
  const AppLink(this.aid, this.kel, this.rid, this.api, this.seal, this.min);

  /// Reads [link]; a link with no fragment, or one naming no back end the way
  /// the page requires, is a [TrustRefused].
  factory AppLink.parse(String link) {
    final hash =
        link.contains('#') ? link.substring(link.indexOf('#') + 1) : '';
    Map<String, String> p = {};
    try {
      p = Uri.splitQueryString(hash);
    } catch (_) {}
    final api = p['api'] ?? '';
    final rid = p['rid'] ?? '';
    if (p['aid'] == null || p['kel'] == null) {
      throw const TrustRefused(
          'This is not the app\'s sign-in link: the link names no app and key log (the part after #).');
    }
    if (rid.isEmpty) {
      throw const TrustRefused(
          'the link names no relay identifier to check the app\'s answers against');
    }
    final seal = p['seal'] ?? '';
    if (seal.isEmpty) {
      throw const TrustRefused(
          'the link names no sealing key to seal calls to the app with');
    }
    final min = p['min'] ?? '';
    if (readMinimum(min) == null) {
      throw const TrustRefused(
          'the link names no latest key log event the app\'s relay identifier must have reached');
    }
    if (!RegExp(r'^https://').hasMatch(api) &&
        !RegExp(r'^http://(127\.0\.0\.1|localhost)[:/]').hasMatch(api)) {
      throw const TrustRefused('the link names no back end to sign in at');
    }
    return AppLink(
        p['aid']!, p['kel']!, rid, api.replaceAll(RegExp(r'/+$'), ''), seal, min);
  }
}

// ---- the app's key log -----------------------------------------------------

/// The key the link's key log puts in force for [aid], or a [TrustRefused] saying why not.
Uint8List checkKeyLog(String aid, String encoded) {
  Never fail(String why) => _fail('the link\'s key log is refused: ', why);
  if (aid.isEmpty || encoded.isEmpty) fail('the link names no app key log');
  final json = b64uDecode(encoded);
  if (json == null) fail('it is not readable');
  Object? kl;
  try {
    kl = jsonDecode(utf8.decode(json));
  } catch (_) {
    fail('it is not JSON');
  }
  if (kl is! Map) fail('it has fields it should not, or lacks some');
  final names = (kl.keys.map((k) => '$k').toList()..sort()).join(',');
  if (names != 'cesr_signatures,raw_events_b64') {
    fail('it has fields it should not, or lacks some');
  }
  final events = kl['raw_events_b64'], sigs = kl['cesr_signatures'];
  if (events is! List ||
      sigs is! List ||
      events.length != 1 ||
      sigs.length != 1) {
    fail('this page reads an unrotated key log of one event only');
  }
  Uint8List raw;
  try {
    raw = base64.decode(events[0] as String);
  } catch (_) {
    fail('its event is not readable');
  }
  String text;
  Object? ev;
  try {
    text = utf8.decode(raw);
    ev = jsonDecode(text);
  } catch (_) {
    fail('its event is not JSON');
  }
  if (ev is! Map) fail('its event is not JSON');
  if (ev['t'] != 'icp' && ev['t'] != 'dip') {
    fail('it does not open with an inception');
  }
  if (ev['d'] != aid || ev['i'] != aid) {
    fail('its inception is not the app\'s identifier');
  }
  deriveIdentifier(text, aid, fail);
  final k = ev['k'];
  if (ev['kt'] != '1' || k is! List || k.length != 1) {
    fail('only a single-key identity is read');
  }
  final key = decodeVerkey(k[0]);
  final sig = decodeSig(sigs[0]);
  if (key == null || sig == null) {
    fail('its key or signature is not spelled one way');
  }
  if (!ed25519Verify(key, raw, sig)) {
    fail('its inception is not signed by the key it declares');
  }
  return key;
}

// ---- the challenge ---------------------------------------------------------

/// The challenge the signed text says, or a [TrustRefused]: signed by the app's
/// key, for the app, naming this device's own key, not lapsed. [body] is the
/// exact text the signature covers; it is read only after the signature has
/// been checked.
Map<String, dynamic> checkChallenge({
  required String aid,
  required Uint8List key,
  required Object? body,
  required Object? sig,
  required Object? pointer,
  required String ownThumbprint,
  required DateTime now,
  String frontEnd = 'browser',
}) {
  Never fail(String why) => _fail('the sign-in is refused: ', why);
  final raw = decodeSig(sig);
  if (body is! String || raw == null) {
    fail('the challenge carries no signature it can read');
  }
  if (!ed25519Verify(key, utf8.encode(body), raw)) {
    fail('the challenge is not signed by the app');
  }
  Object? c;
  try {
    c = jsonDecode(body);
  } catch (_) {
    fail('the signed text is not a challenge');
  }
  if (c is! Map<String, dynamic>) {
    fail('the signed text is not a login challenge');
  }
  if (c['v'] != 'ASK1' || c['t'] != 1) {
    fail('the signed text is not a login challenge');
  }
  if (c['site_aid'] != aid) fail('the challenge is signed for another app');
  if (c['browser_key'] != ownThumbprint) {
    fail('the challenge does not name this page\'s own key');
  }
  // The kind is in the signed body when the Identity Agent names one (ADR-072
  // Amendment 2): a challenge naming another kind than ours is not ours.
  if (c['front_end'] != null && c['front_end'] != frontEnd) {
    fail('the challenge is for another kind of front end');
  }
  final expiry = DateTime.tryParse('${c['expiry']}');
  if (expiry == null || !expiry.isAfter(now)) fail('the challenge has lapsed');
  final token = c['session_token'];
  if (token is! String || token.isEmpty) fail('the challenge names no sign-in');
  final u = pointer is String ? Uri.tryParse(pointer) : null;
  if (u == null || !u.hasScheme) fail('the code to open is not an address');
  if (u.scheme != 'https' || !u.path.endsWith('/i/$token')) {
    fail('the code to open is not this challenge\'s');
  }
  return c;
}

// ---- the app's answers -----------------------------------------------------

const answerLogHeader = 'x-keri-app-answer-log';
const answerSigHeader = 'x-keri-app-answer-sig';

String _sha256hex(List<int> b) => SHA256Digest()
    .process(Uint8List.fromList(b))
    .map((v) => v.toRadixString(16).padLeft(2, '0'))
    .join();

/// What the app signed an answer over (appserve.answerBytes).
String answerText(String rid, String nonce, int status, String contentType,
        List<int> body) =>
    [
      'APP-ANSWER-V1',
      rid,
      'browser',
      nonce,
      '$status',
      contentType,
      _sha256hex(body)
    ].join('\n');

// ---- the relay identifier's key log ----------------------------------------

/// The most a relay takes of a key log (relayproto.MaxKELBytes, MaxKELEvents).
const _maxLogBytes = 64 << 10;
const _maxLogEvents = 256;

/// One event of a key log, as [logExtends] compares them.
class LogEvent {
  final int sn;
  final String ilk, said;
  const LogEvent(this.sn, this.ilk, this.said);
  @override
  bool operator ==(Object other) =>
      other is LogEvent && other.sn == sn && other.ilk == ilk && other.said == said;
  @override
  int get hashCode => Object.hash(sn, ilk, said);
}

/// What a relay identifier's key log says: the key it names now, and its events.
class CheckedLog {
  final Uint8List key;
  final List<LogEvent> events;
  const CheckedLog(this.key, this.events);
}

final _eventHead = RegExp(r'^\{"v":"KERI10JSON([0-9a-f]{6})_"');

/// Reads the signed key log an answer carries (a CESR stream: each event's JSON
/// followed by exactly one controller signature group), as login-web's
/// `checkAnswerKeyLog` does, and gives the key it names now. A [TrustRefused]
/// unless the log is the identifier [rid]'s own from its inception: every
/// event's SAID derives, each rotation carries on from the one before (sequence
/// number, prior SAID), is made with exactly the key the event before committed
/// to, and every event is signed by the key it names. Only an inception and
/// rotations, one key at a time: anything else is refused rather than skipped.
CheckedLog readAnswerLog(
    String rid, String? encoded, void Function(String) fail) {
  final bytes = b64uDecode(encoded ?? '');
  if (bytes == null || bytes.isEmpty) fail('it is not signed');
  if (bytes!.length > _maxLogBytes) {
    fail('its key log is larger than a relay takes');
  }
  if (bytes.any((b) => b >= 0x80)) fail('its key log is not text');
  final text = String.fromCharCodes(bytes);
  final parts = <({String event, String sig})>[];
  var pos = 0;
  while (pos < text.length) {
    final end = pos + 40 < text.length ? pos + 40 : text.length;
    final head = _eventHead.firstMatch(text.substring(pos, end));
    if (head == null) {
      fail('its key log has something that is not an event where one must begin');
    }
    final len = int.parse(head!.group(1)!, radix: 16);
    if (pos + len > text.length || !text.substring(pos, pos + len).endsWith('}')) {
      fail('an event of its key log is not as long as it says');
    }
    final event = text.substring(pos, pos + len);
    pos += len;
    // Exactly one controller signature (one key, so one place), as the relay makes them.
    if (!text.startsWith('-AAB', pos) || pos + 92 > text.length) {
      fail('an event of its key log is not followed by exactly one signature');
    }
    parts.add((event: event, sig: text.substring(pos + 4, pos + 92)));
    pos += 92;
    if (parts.length > _maxLogEvents) {
      fail('its key log has more events than a relay takes');
    }
  }
  if (parts.isEmpty) fail('it is not signed');

  final events = <LogEvent>[];
  Uint8List? key;
  String? prevSaid, prevNext;
  for (var i = 0; i < parts.length; i++) {
    final event = parts[i].event;
    Object? ev;
    try {
      ev = jsonDecode(event);
    } catch (_) {
      fail('an event of its key log is unreadable');
    }
    if (ev is! Map) fail('an event of its key log is unreadable');
    final m = ev as Map;
    final d = m['d'];
    if (d is! String || d.isEmpty) fail('an event of its key log has no SAID');
    if (i == 0) {
      if (m['t'] != 'icp' || m['i'] != rid || d != rid || _truthy(m['di'])) {
        fail('its inception is not the identifier the link names');
      }
      if (m['s'] != '0') fail('its inception is not sequence number 0');
      deriveIdentifier(event, rid, fail);
    } else {
      if (m['t'] != 'rot' || m['i'] != rid) {
        fail('an event after the inception is not a rotation of the identifier the link names');
      }
      if (m['s'] != i.toRadixString(16)) fail('a rotation is out of sequence');
      if (m['p'] != prevSaid) {
        fail('a rotation does not carry on from the event before it');
      }
      final needle = '"d":"$d"';
      if (event.split(needle).length != 2) {
        fail('a rotation names its SAID other than once');
      }
      final dummy = event.replaceFirst(needle, '"d":"${'#' * d.length}"');
      if (matterEncode('E', blake3(Uint8List.fromList(utf8.encode(dummy)))) != d) {
        fail('a rotation\'s SAID is not the digest of the rotation');
      }
    }
    final k = m['k'], n = m['n'];
    if (m['kt'] != '1' ||
        k is! List ||
        k.length != 1 ||
        m['nt'] != '1' ||
        n is! List ||
        n.length != 1 ||
        n[0] is! String) {
      fail('only a single-key identity that commits to its next key is read');
    }
    final verkey = decodeVerkey(k[0]);
    if (verkey == null) fail('its key is not spelled one way');
    // A rotation is made with exactly the key the event before committed to.
    if (prevNext != null &&
        matterEncode('E', blake3(Uint8List.fromList(utf8.encode(k[0] as String)))) !=
            prevNext) {
      fail('a rotation is made with a key the event before did not commit to');
    }
    final sig = _matter(parts[i].sig, 'AA', 64);
    if (sig == null) fail('an event\'s signature is not spelled one way');
    if (!ed25519Verify(verkey!, utf8.encode(event), sig!)) {
      fail('an event of its key log is not signed by the key it names');
    }
    key = verkey;
    prevSaid = d;
    prevNext = n[0] as String;
    events.add(LogEvent(i, m['t'] as String, d));
  }
  return CheckedLog(key!, events);
}

/// Whether [log] holds every event [base] holds, in the same order, and perhaps
/// more after them: the one rule for taking a newer log in place of one held.
bool logExtends(List<LogEvent> log, List<LogEvent> base) {
  if (log.length < base.length) return false;
  for (var i = 0; i < base.length; i++) {
    if (log[i] != base[i]) return false;
  }
  return true;
}

/// `<sequence number>.<SAID>` (login-web's `readMinimum`), or null when [min] is not
/// that: the latest event of the relay identifier's key log the link says must
/// have been reached.
({int sn, String said})? readMinimum(Object? min) {
  final m = min is String
      ? RegExp(r'^(0|[1-9][0-9]{0,2})\.([A-Za-z0-9_-]{20,100})$').firstMatch(min)
      : null;
  return m == null ? null : (sn: int.parse(m.group(1)!), said: m.group(2)!);
}

/// Where [AnswerLogs] keeps what it has been shown between runs of the app.
abstract interface class LogStore {
  String? read(String rid);
  void write(String rid, String log);
}

/// What this app has been shown of each relay identifier's key log: the longest,
/// per identifier. Without it a key the log has since left would be believed
/// again by showing its own shorter log. Kept in a [LogStore] where one is given,
/// so that closing the app does not forget it; held in memory for the run
/// regardless, and in memory alone where there is no store (a test).
class AnswerLogs {
  final LogStore? store;
  final Map<String, String> _held = {};
  AnswerLogs([this.store]);

  String? get(String rid) {
    final held = _held[rid];
    if (held != null) return held;
    try {
      return store?.read(rid);
    } catch (_) {
      return null; // a store that cannot be read: the link's minimum is what holds
    }
  }

  void set(String rid, String log) {
    _held[rid] = log;
    try {
      store?.write(rid, log);
    } catch (_) {
      // The copy in memory still holds for this run.
    }
  }
}

/// The one memory the app's checks share unless given another. `main` replaces it
/// with one kept on the device (`PreferencesLogStore`) before the app runs.
AnswerLogs answerLogs = AnswerLogs();

/// The log to remember once [got] (read from [text]) has been shown: the longer
/// of it and [known], the longest already held for [rid]. Refuses, through
/// [fail], a log that does not carry on from the one held, which is how a key
/// the log has since left is kept from being believed again. The one rule for an
/// answer and a sealing key alike (login-web's `holdLog`).
String holdLog(String rid, CheckedLog got, String text, String? known,
    void Function(String) fail,
    {bool floored = false}) {
  if (known == null || known.isEmpty) return text;
  CheckedLog held;
  try {
    held = readAnswerLog(rid, known, (why) => throw TrustRefused(why));
  } on TrustRefused {
    // What was kept is unreadable. Where the link gave a minimum ([floored]) the
    // log shown is held to that and replaces it; with none, refusing is the only way
    // not to take the first log offered as if this app had never seen one.
    if (floored) return text;
    fail('what this app kept of the app\'s key log cannot be read, and the link gives nothing to hold the log to');
    return text; // not reached: [fail] throws
  }
  if (!logExtends(got.events, held.events)) {
    fail('its key log is behind or apart from the one this page already knows for the app: the key that signed it may have been rotated away');
  }
  return held.events.length == got.events.length ? known : text;
}

/// Throws unless this answer is the app's: signed with the CURRENT key of the
/// relay identifier [rid] the link named, as its key log ([log], the
/// `x-keri-app-answer-log` header) names it, a log that carries on from the
/// longest one already held ([known]); for the call made with [nonce], carrying
/// exactly this status, content type and body. Gives the log to remember: the
/// longer of the two.
String checkAnswer({
  required String rid,
  required String nonce,
  required int status,
  required String contentType,
  required List<int> body,
  required String? log,
  String? known,
  required String? sig,
}) {
  Never fail(String why) => _fail('the answer is not the app\'s: ', why);
  if (rid.isEmpty) {
    fail('the link names no relay identifier to check it against');
  }
  final sigRaw = b64uDecode(sig ?? '');
  if (sigRaw == null || sigRaw.isEmpty) fail('it is not signed');
  final got = readAnswerLog(rid, log, fail);
  final keep = holdLog(rid, got, log!, known, fail);
  final signed = utf8.encode(answerText(rid, nonce, status, contentType, body));
  if (!ed25519Verify(got.key, signed, sigRaw)) {
    fail('its signature does not hold for this call');
  }
  return keep;
}

bool _truthy(Object? v) => v != null && v != false && v != 0 && v != '';

/// The app's clock less this device's, from the time the app's signed answer
/// gave; a [TrustRefused] if it gave none.
Duration serverSkew(Object? serverTime, DateTime now) {
  final ok = serverTime is String &&
      RegExp(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$').hasMatch(serverTime);
  final t = ok ? DateTime.tryParse(serverTime) : null;
  if (t == null) throw const TrustRefused('the app gave no time to go by');
  return t.difference(now);
}

// ---- a key's short code, as the approving device shows it --------------------

/// `authorisation.KeyFingerprint` in identity-bot: 16 Crockford base32 characters
/// of Blake3 over `"key-fingerprint/v2\n" + key`, in four groups of four, so the
/// code the person sees here is the code their Identity Agent shows.
String keyFingerprint(String key) {
  key = key.trim();
  if (key.isEmpty) return '';
  final sum =
      blake3(Uint8List.fromList(utf8.encode('key-fingerprint/v2\n$key')));
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  final out = StringBuffer();
  var acc = 0, bits = 0, n = 0;
  for (final by in sum.sublist(0, 10)) {
    acc = ((acc << 8) | by) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      if (n > 0 && n % 4 == 0) out.write('-');
      out.write(alphabet[(acc >> bits) & 31]);
      n++;
    }
  }
  return out.toString();
}

// ---- proofs ------------------------------------------------------------------

/// The unpadded base64url SHA-256 of [bytes].
String sha256B64u(List<int> bytes) =>
    b64uEncode(SHA256Digest().process(Uint8List.fromList(bytes)));

/// What a session names itself by in a proof: the SHA-256 of its token.
String sessionBinding(String token) => sha256B64u(utf8.encode(token));

/// The string signed for a request to the app's own back end (`proofText` in
/// the SDK, `appserve.Proof` in the add-ons, label IABK1, no host). While
/// signing in the binding is the sign-in's id.
String backEndProofString(String method, String target, String ts,
        String nonce, String binding, List<int> body) =>
    ['IABK1', method, target, ts, nonce, binding, sha256B64u(body)].join('\n');

/// RFC 7638 thumbprint of a P-256 public key given as its coordinates.
String browserKeyThumbprint(String x, String y) => sha256B64u(
    utf8.encode('{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}'));
