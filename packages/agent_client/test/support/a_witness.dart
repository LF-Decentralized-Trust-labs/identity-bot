import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:agent_client/services/key_math.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

/// A witness for a test, answering the routes an Identity Agent's witness
/// answers (`POST witness/event`, `GET witness/kel/{aid}/tip`,
/// `GET witness/kel/{aid}/event/{sn}`) with the same bodies. It judges each
/// event with the core's own engine before it keeps it, as a witness does, and
/// signs its receipts with its own key. The ways it can misbehave are set on
/// it.
class AWitness {
  AWitness._(this._server, this._km, this._key, this.aid);

  static Future<AWitness> start(KeyMath km) async {
    final key = ed.generateKey();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final w = AWitness._(server, km, key,
        qb64('B', Uint8List.fromList(ed.public(key.privateKey).bytes)));
    server.listen(w._answer);
    return w;
  }

  final HttpServer _server;
  final KeyMath _km;
  final ed.KeyPair _key;

  /// This witness's name: its key, non-transferable.
  final String aid;

  /// Where its routes are reached.
  Uri get base => Uri.parse('http://127.0.0.1:${_server.port}/api/');

  /// The log it holds for each identity.
  final Map<String, List<SignedCopy>> held = {};
  final Map<String, List<String>> _digests = {};

  /// The witness list in force after each event of the log it holds for each
  /// identity: the inception names it, a rotation cuts and adds.
  final Map<String, List<List<String>>> _lists = {};

  /// Answers nothing at all.
  bool offline = false;

  /// Signs its receipts with another key.
  bool forgesReceipts = false;

  /// Writes its receipts at the place after its own, as a copy of a genuine
  /// receipt with another index would be.
  bool misindexesReceipts = false;

  /// Answers in another witness's name.
  bool namesAnother = false;

  /// Answers who it is (a core confirms that before it proposes a witness) and
  /// nothing else, as a witness that has since stopped does not.
  bool mute = false;

  /// Signs its answer to where its log ends with another witness's key.
  bool tipSignedByAnother = false;

  /// Signs, as the end of the log it holds, a digest that is not the digest
  /// of the event its copy ends on: what a wrong address relaying a real
  /// witness's signed answer beside another copy amounts to.
  bool signsAnotherTip = false;

  /// The identities it has agreed to witness, or null for any. A real witness
  /// agrees through `witness/request` first, and refuses any other identity
  /// with `403 not_witnessing`.
  Set<String>? witnessesOnly;

  /// The witness list it takes to be in force, for a test that asks witnesses
  /// about a list the log it holds does not have. Null: the list its held log
  /// defines.
  List<String>? listInForce;

  /// How many events it was sent.
  int sent = 0;

  /// Puts [copy] at the end of [aid]'s log as this witness holds it, checked.
  Future<void> hold(String aid, SignedCopy copy) async {
    final ev = await _km.parseEvent(base64Decode(copy.rawB64));
    (held[aid] ??= []).add(copy);
    (_digests[aid] ??= []).add(ev.d);
    List<String> names(Object? v) =>
        v is List ? [for (final x in v) x as String] : const <String>[];
    final lists = _lists[aid] ??= [];
    var list = lists.isEmpty ? <String>[] : lists.last;
    if (ev.t == 'icp' || ev.t == 'dip') {
      list = names(ev['b']);
    } else if (ev.t == 'rot' || ev.t == 'drt') {
      final cuts = names(ev['br']);
      list = [
        for (final w in list)
          if (!cuts.contains(w)) w
      ];
      for (final w in names(ev['ba'])) {
        if (!list.contains(w)) list.add(w);
      }
    }
    lists.add(list);
  }

  /// Forgets every log it holds and behaves again, as a new witness would.
  void forgetAll() {
    held.clear();
    _digests.clear();
    _lists.clear();
    signsAnotherTip = false;
    offline = false;
    mute = false;
    tipSignedByAnother = false;
    forgesReceipts = false;
    namesAnother = false;
    witnessesOnly = null;
  }

  Future<void> close() => _server.close(force: true);

  Future<void> _answer(HttpRequest req) async {
    if (offline) {
      req.response.statusCode = 503;
      await req.response.close();
      return;
    }
    final path = req.uri.pathSegments;
    try {
      if (req.method == 'GET' && req.uri.path == '/api/health') {
        _json(req.response, 200, {'service_aid': aid});
      } else if (mute) {
        req.response.statusCode = 503;
      } else if (req.method == 'POST' && req.uri.path == '/api/witness/event') {
        sent++;
        final body = jsonDecode(await utf8.decodeStream(req)) as Map;
        await _event(
            req.response, body['aid'] as String, body['event_b64'] as String, [
          for (final s in (body['cesr_signatures'] as List? ?? const [])) '$s'
        ]);
      } else if (req.method == 'GET' &&
          path.length == 5 &&
          path[2] == 'kel' &&
          path[4] == 'tip') {
        final a = path[3];
        final nonce = req.uri.queryParameters['nonce'] ?? '';
        final log = _digests[a] ?? const [];
        final sn = log.length - 1;
        final said = sn < 0 ? '' : (signsAnotherTip ? 'E${'x' * 43}' : log[sn]);
        _json(req.response, 200, {
          'aid': a,
          'nonce': nonce,
          'sn': sn,
          'said': said,
          'witness_aid': aid,
          'signature': tipSignedByAnother
              ? qb64(
                  '0B',
                  Uint8List.fromList(ed.sign(
                      ed.generateKey().privateKey,
                      Uint8List.fromList(utf8.encode(
                          'witness-kel-tip/v1\n$a\n$nonce\n$sn\n$said')))))
              : _sign('witness-kel-tip/v1\n$a\n$nonce\n$sn\n$said'),
        });
      } else if (req.method == 'GET' &&
          path.length == 6 &&
          path[2] == 'kel' &&
          path[4] == 'event') {
        final log = held[path[3]] ?? const [];
        final sn = int.parse(path[5]);
        if (sn >= log.length) {
          _json(req.response, 404, {'error': 'not held'});
        } else {
          _json(req.response, 200, {
            'raw_bytes_b64': log[sn].rawB64,
            'cesr_signature': log[sn].sigs.first,
            'cesr_signatures': log[sn].sigs,
          });
        }
      } else {
        _json(req.response, 404, {'error': 'no such route'});
      }
    } catch (e) {
      _json(req.response, 400, {'error': 'rejected', 'details': '$e'});
    }
    await req.response.close();
  }

  /// One event at a time: a core and an app send the same event together, and
  /// a witness judges each against the log it holds when it comes to it.
  Future<void> _turn = Future.value();

  Future<void> _event(
      HttpResponse res, String forAid, String rawB64, List<String> sigs) {
    final done = _turn.then((_) => _judge(res, forAid, rawB64, sigs));
    _turn = done.catchError((_) {});
    return done;
  }

  Future<void> _judge(
      HttpResponse res, String forAid, String rawB64, List<String> sigs) async {
    final only = witnessesOnly;
    if (only != null && !only.contains(forAid)) {
      _json(res, 403, {'error': 'not_witnessing'});
      return;
    }
    final ev = await _km.parseEvent(base64Decode(rawB64));
    final log = held[forAid] ?? const <SignedCopy>[];
    final digests = _digests[forAid] ?? const <String>[];
    if (ev.s > log.length) {
      _json(res, 409, {'error': 'sequence_gap'});
      return;
    }
    if (ev.s < log.length && digests[ev.s] != ev.d) {
      // A recovery rotation replaces the interactions from its place on, as a
      // real witness admits one; anything else at a held place is refused.
      final replaces = ev.t == 'rot' &&
          [for (final c in log.sublist(ev.s)) await _ilk(c)]
              .every((t) => t == 'ixn');
      if (!replaces) {
        _json(res, 409, {'error': 'duplicate_sequence'});
        return;
      }
      final copy = SignedCopy(rawB64, sigs);
      await _km.verifyLog(forAid, [...log.sublist(0, ev.s), copy]);
      held[forAid] = [...log.sublist(0, ev.s)];
      _digests[forAid] = [...digests.sublist(0, ev.s)];
      _lists[forAid] = [..._lists[forAid]!.sublist(0, ev.s)];
      await hold(forAid, copy);
    } else if (ev.s < log.length) {
      // A repeat: answered with the receipt it already issued.
    } else {
      final copy = SignedCopy(rawB64, sigs);
      // Judged as the next event of the log it holds, by the engine.
      await _km.verifyLog(forAid, [...log, copy]);
      await hold(forAid, copy);
    }
    _json(res, 200, {
      'event_said': ev.d,
      'witness_aid': namesAnother ? qb64('B', Uint8List(32)) : aid,
      'sequence_number': ev.s,
      'cesr_signature': _receipt(
          forgesReceipts ? ed.generateKey().privateKey : _key.privateKey,
          base64Decode(rawB64),
          _place(forAid, ev.s)),
    });
  }

  /// Where this witness stands in the witness list in force at the event at
  /// [sn] of [forAid], from the log it holds. A receipt carries this place as
  /// its index, as keripy's Hab.witness writes it. Zero when it is not in the
  /// list.
  int _place(String forAid, int sn) {
    final stated = listInForce;
    if (misindexesReceipts) return min(63, _truePlace(forAid, sn) + 1);
    return _truePlace(forAid, sn);
  }

  int _truePlace(String forAid, int sn) {
    final stated = listInForce;
    if (stated != null) return max(0, stated.indexOf(aid));
    final lists = _lists[forAid] ?? const <List<String>>[];
    final at = sn < lists.length ? lists[sn].indexOf(aid) : -1;
    return at < 0 ? 0 : at;
  }

  Future<String> _ilk(SignedCopy c) async =>
      (await _km.parseEvent(base64Decode(c.rawB64))).t;

  /// A receipt as keripy's Hab.witness makes one: an indexed Ed25519 signature
  /// (code `A`, with [index] its witness's place in the list) over the
  /// serialised event.
  String _receipt(ed.PrivateKey key, Uint8List event, int index) {
    const digits =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    return qb64('A${digits[index]}', Uint8List.fromList(ed.sign(key, event)));
  }

  String _sign(String message) => qb64(
      '0B',
      Uint8List.fromList(
          ed.sign(_key.privateKey, Uint8List.fromList(utf8.encode(message)))));

  static void _json(HttpResponse res, int status, Object body) {
    res.statusCode = status;
    res.headers.contentType = ContentType.json;
    res.write(jsonEncode(body));
  }
}

/// [raw] in CESR's qb64 under the one- or two-character [code]: the code in
/// place of the base64 of the leading zero bytes that pad the raw value.
String qb64(String code, Uint8List raw) {
  final lead = (3 - raw.length % 3) % 3;
  final b64 = base64Url.encode([...List.filled(lead, 0), ...raw]);
  return code + b64.substring(code.length);
}
