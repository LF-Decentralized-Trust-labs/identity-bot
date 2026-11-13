import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'app_checks.dart';

/// A relay identifier's key log as its witnesses hold it, ADR-072 Amendment 5:
/// the Dart port of login-web's `witnessed.ts`, held to the same cases
/// (`packages/login-web/test-vectors/seal.json`, `witnessed`).
///
/// Nothing a witness says is believed. Each answer (to GET /witness/kel/{rid})
/// is read as a key log ([readAnswerLog]), the receipts of all the answers are
/// pooled, and for each event the distinct witnesses designated at that event
/// whose signature over its bytes verifies are counted against the threshold
/// (`bt`) in force. A log is taken as far as every event has its threshold, and
/// no further. The witness list is carried forward as the core's
/// `WitnessesAfter` does (an inception names it, a rotation cuts `br` then adds
/// `ba`); a receipt's index is the witness's place in it; a witness counts once.
class WitnessedLog {
  /// The log as a page reads it (a CESR stream, base64url), cut after the last
  /// event that has its threshold of receipts.
  final String log;

  /// How many events it holds.
  final int events;
  final CheckedLog checked;
  const WitnessedLog(this.log, this.events, this.checked);
}

const _alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

Never _refuse(String why) =>
    throw TrustRefused("the witnesses' key log is refused: $why");

/// Standard base64 in its one spelling, or null.
Uint8List? _strictBase64(Object? s) {
  if (s is! String || !RegExp(r'^[A-Za-z0-9+/]*={0,2}$').hasMatch(s)) {
    return null;
  }
  if (s.length % 4 != 0) return null;
  try {
    final out = base64.decode(s);
    return base64.encode(out) == s ? out : null;
  } catch (_) {
    return null;
  }
}

List<String>? _strings(Object? v) =>
    v is List && v.every((x) => x is String) ? v.cast<String>() : null;

bool _isWitness(String w) => decodeMatter(w, 'B', 32) != null;

/// The witnesses in force after [ev] (the core's `WitnessesAfter`, held to
/// keri-go's rules for what an event may name), or null when [ev] does not say
/// or says what a log may not: a list naming a witness twice or one that is not
/// a witness identifier, a rotation that cuts a witness that is not in the
/// list, one that adds a witness already in it, or one that both cuts and adds
/// the same. A log with such an event is not read, as the core does not read it.
List<String>? _witnessesAfter(List<String> current, Map<String, dynamic> ev) {
  bool distinct(List<String> l) =>
      l.toSet().length == l.length && l.every(_isWitness);
  if (ev['t'] == 'icp') {
    final named = _strings(ev['b']);
    return named != null && distinct(named) ? named : null;
  }
  if (ev['t'] != 'rot') return current;
  final cut = _strings(ev['br']);
  final add = _strings(ev['ba']);
  if (cut == null || add == null || !distinct(cut) || !distinct(add)) {
    return null;
  }
  if (cut.any((w) => !current.contains(w))) return null;
  final out = current.where((w) => !cut.contains(w)).toList();
  if (add.any((w) => out.contains(w) || cut.contains(w))) return null;
  return [...out, ...add];
}

enum _Lists { ok, unreadable, cutAll }

/// Whether a log that is read says what a log may say of its witnesses:
/// unreadable (an event that breaks the rules above: the answer is not read),
/// or cutAll (a rotation that leaves an identifier that had witnesses with
/// none, which the owner's own signature shows).
_Lists _witnessListsOf(List<String> texts) {
  var designated = <String>[];
  for (final t in texts) {
    final ev = _json(t);
    if (ev == null) return _Lists.unreadable;
    final after = _witnessesAfter(designated, ev);
    if (after == null) return _Lists.unreadable;
    if (designated.isNotEmpty && after.isEmpty) return _Lists.cutAll;
    designated = after;
  }
  return _Lists.ok;
}

/// The witnesses prove the identifier is not what its link says, or that its
/// owner has made it unwitnessed: a link made for it is refused, not taken on
/// its minimum.
class WitnessesRefuse extends TrustRefused {
  const WitnessesRefuse(String why)
      : super("the witnesses' key log is refused: $why");
}

final _toadSpelling = RegExp(r'^(0|[1-9a-f][0-9a-f]{0,3})$');

int? _toadOf(Map<String, dynamic> ev) {
  final bt = ev['bt'];
  return bt is String && _toadSpelling.hasMatch(bt)
      ? int.parse(bt, radix: 16)
      : null;
}

Map<String, dynamic>? _json(String text) {
  try {
    final v = jsonDecode(text);
    return v is Map<String, dynamic> ? v : null;
  } catch (_) {
    return null;
  }
}

/// How many leading events of [texts] have their threshold of receipts, which
/// are [receipts] by event SAID, as (witness, signature). Fails closed: an
/// event whose witnesses or threshold cannot be read ends the count.
({int through, int named, int toad}) _receiptedThrough(List<String> texts,
    List<String> saids, Map<String, List<(String, String)>> receipts) {
  var designated = <String>[];
  var toad = 0;
  for (var i = 0; i < texts.length; i++) {
    final ev = _json(texts[i]);
    if (ev == null) return (through: i, named: designated.length, toad: toad);
    final after = _witnessesAfter(designated, ev);
    final bt = _toadOf(ev);
    if (after == null || bt == null) {
      return (through: i, named: designated.length, toad: toad);
    }
    designated = after;
    toad = bt;
    final keys = <String>{};
    for (final (witness, sig)
        in receipts[saids[i]] ?? const <(String, String)>[]) {
      final at = designated.indexOf(witness);
      final key = decodeMatter(witness, 'B', 32);
      if (at < 0 || key == null || sig.length != 88 || sig[0] != 'A')
        continue; // only an indexed receipt counts, as login-web's isIndexedReceipt
      if (_alphabet.indexOf(sig[1]) != at) continue;
      final raw = decodeMatter(sig, sig.substring(0, 2), 64);
      if (raw == null || !ed25519Verify(key, utf8.encode(texts[i]), raw)) {
        continue;
      }
      keys.add(witness);
    }
    if (keys.length < toad) {
      return (through: i, named: designated.length, toad: toad);
    }
  }
  return (through: texts.length, named: designated.length, toad: toad);
}

class _Read {
  final List<String> texts, sigs;
  final CheckedLog checked;
  _Read(this.texts, this.sigs, this.checked);
}

/// Reads the [answers] of the witnesses a relay identifier names into the log
/// they together vouch for: the longest log whose every event has its threshold
/// of receipts from the witnesses designated. A [TrustRefused] when there is
/// none, or when two logs that both reach a place disagree on an event before
/// it. An answer that is not a log of [rid]'s, or cannot be read, counts for
/// nothing and is no error for the others.
WitnessedLog readWitnessedLog(String rid, List<Object?> answers) {
  final receipts = <String, List<(String, String)>>{};
  final read = <_Read>[];
  for (final a in answers) {
    if (a is! Map || a['aid'] != rid) continue;
    final kel = a['kel'];
    if (kel is! List || kel.isEmpty || kel.length > 256) continue;
    final texts = <String>[], sigs = <String>[];
    var ok = true;
    for (final e in kel) {
      final raw = e is Map ? _strictBase64(e['raw_bytes_b64']) : null;
      final sig = e is Map ? e['cesr_signature'] : null;
      if (raw == null || sig is! String || sig.length != 88) {
        ok = false;
        break;
      }
      try {
        texts.add(utf8.decode(raw));
      } catch (_) {
        ok = false;
        break;
      }
      sigs.add(sig);
    }
    if (!ok) continue;
    final lists = _witnessListsOf(texts);
    if (lists == _Lists.unreadable) continue;
    CheckedLog checked;
    try {
      checked = readAnswerLog(
          rid,
          b64uEncode(utf8.encode([
            for (var i = 0; i < texts.length; i++) '${texts[i]}-AAB${sigs[i]}'
          ].join())),
          (why) => throw TrustRefused(why));
    } on TrustRefused {
      continue;
    }
    // Only a log its controller signed shows what its owner did.
    if (lists == _Lists.cutAll) {
      throw const WitnessesRefuse('a rotation of it cut every witness it had');
    }
    read.add(_Read(texts, sigs, checked));
    for (var i = 0; i < kel.length; i++) {
      final list = (kel[i] as Map)['witness_receipts'];
      if (list is! List) continue;
      for (final r in list) {
        if (r is Map &&
            r['witness'] is String &&
            r['cesr_signature'] is String) {
          (receipts[checked.events[i].said] ??= [])
              .add((r['witness'] as String, r['cesr_signature'] as String));
        }
      }
    }
  }
  if (read.isEmpty) {
    _refuse('no witness gave a key log of this identifier that can be read');
  }
  // A log is a witnessed one when the witnesses in force at its last event are
  // named and asked for a receipt. The events before witnesses were named (an
  // identifier made without them and given them by a rotation) need none.
  final witnessed = <_Read>[];
  final through = <int>[];
  for (final r in read) {
    final t = _receiptedThrough(
        r.texts, [for (final e in r.checked.events) e.said], receipts);
    if (t.named > 0 && t.toad > 0) {
      witnessed.add(r);
      through.add(t.through);
    }
  }
  if (witnessed.isEmpty) _refuse('no witness gave a log that names witnesses');
  read
    ..clear()
    ..addAll(witnessed);
  for (var x = 0; x < read.length; x++) {
    for (var y = 0; y < read.length; y++) {
      final reach = through[x] < through[y] ? through[x] : through[y];
      for (var i = 0; i < reach; i++) {
        if (read[x].checked.events[i].said != read[y].checked.events[i].said) {
          throw const WitnessesRefuse(
              'two logs, each receipted, disagree on an event');
        }
      }
    }
  }
  var best = 0;
  for (var i = 1; i < read.length; i++) {
    if (through[i] > through[best]) best = i;
  }
  if (through[best] == 0) {
    _refuse('no event of it has its threshold of witness receipts');
  }
  final n = through[best];
  final stream = [
    for (var i = 0; i < n; i++)
      '${read[best].texts[i]}-AAB${read[best].sigs[i]}'
  ].join();
  final log = b64uEncode(utf8.encode(stream));
  final checked = readAnswerLog(rid, log, (why) => throw TrustRefused(why));
  return WitnessedLog(log, n, checked);
}

/// How the log a link carried stands to the log the witnesses vouch for.
enum LinkVerdict {
  /// The link's log holds every event they vouch for (and perhaps more, which
  /// they have not been told yet).
  agrees,

  /// They vouch for events after the link's last: the key the link vouched a
  /// sealing key for is not current.
  moved_on,

  /// The two have different events at one place.
  apart,

  /// The witnesses gave no log a page can take.
  none,

  /// What the witnesses hold proves the identifier unfit for a link: two
  /// histories each receipted by a threshold, or a rotation that cut every
  /// witness. Not [none]: a page does not fall back to the link's minimum.
  refused,
}

/// Judges [linkLog] (already read from the link, base64url) against the
/// [answers] of the identifier's witnesses, as login-web's `judgeLinkLog`.
/// [log] is the witnessed log to remember when there is one: it is what keeps a
/// link made before a rotation refused afterwards.
({LinkVerdict verdict, String? log}) judgeLinkLog(
    String rid, String linkLog, List<Object?> answers) {
  final WitnessedLog w;
  try {
    w = readWitnessedLog(rid, answers);
  } on WitnessesRefuse {
    return (verdict: LinkVerdict.refused, log: null);
  } on TrustRefused {
    return (verdict: LinkVerdict.none, log: null);
  }
  final mine = readAnswerLog(rid, linkLog, (why) => throw TrustRefused(why));
  if (logExtends(mine.events, w.checked.events)) {
    return (verdict: LinkVerdict.agrees, log: w.log);
  }
  if (logExtends(w.checked.events, mine.events)) {
    return (verdict: LinkVerdict.moved_on, log: w.log);
  }
  return (verdict: LinkVerdict.apart, log: w.log);
}

/// The most a page takes of one witness's answer.
const _maxWitnessAnswer = 512 << 10;
const _witnessTimeout = Duration(seconds: 8);

/// Asks each witness address (`<address>/witness/kel/<rid>`) for the log,
/// presenting [inception] (the identifier's first event as published) in
/// X-Inception-Event, which is all that lets a page read it. Every address is
/// asked at once; one that cannot be reached, answers anything but 200 with
/// JSON, or answers too much, gives nothing.
Future<List<Object?>> askWitnesses(String rid, String inception,
    List<String> addresses, http.Client client) async {
  final proof = b64uEncode(utf8.encode(inception));
  final got = await Future.wait(addresses.map((address) async {
    try {
      final r = await client.get(
          Uri.parse('$address/witness/kel/${Uri.encodeComponent(rid)}'),
          headers: {'X-Inception-Event': proof}).timeout(_witnessTimeout);
      if (r.statusCode != 200 || r.bodyBytes.length > _maxWitnessAnswer) {
        return null;
      }
      return jsonDecode(utf8.decode(r.bodyBytes));
    } catch (_) {
      return null;
    }
  }));
  return [
    for (final a in got)
      if (a != null) a
  ];
}
