import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'key_math.dart';

/// Where each witness is reached. A witness is named by its key, and every
/// answer counted from one is checked against that key, so an address that
/// leads somewhere else costs a receipt, never a false one.
abstract class WitnessDirectory {
  /// The base address of [witness], ending in `/`, that its `witness/...`
  /// routes resolve against (an Identity Agent's is its `/api/`), or null
  /// when this app does not know where it is.
  Uri? whereIs(String witness);
}

/// A [WitnessDirectory] of addresses this app was configured with or agreed to.
class KnownWitnesses implements WitnessDirectory {
  KnownWitnesses(this._at);
  final Map<String, Uri> _at;
  @override
  Uri? whereIs(String witness) => _at[witness];
}

/// The witnesses an event of an identity is witnessed by, and how many of
/// them must receipt it (`b` and `bt` in force after the event).
///
/// A witness is counted by its name, so only the canonical spelling of a
/// non-transferable Ed25519 witness (`B` and 43 characters, the one spelling
/// the core accepts, ADR-060) is counted, each once: a name in any other
/// spelling, or a second copy of one, could otherwise be counted twice.
class WitnessSet {
  WitnessSet(List<String> witnesses, this.toad)
      : witnesses = List.unmodifiable({
          for (final w in witnesses)
            if (_canonical.hasMatch(w)) w
        });
  final List<String> witnesses;
  final int toad;

  static final _canonical = RegExp(r'^B[A-Za-z0-9_-]{43}$');

  /// How many receipts establish an event: the threshold, and at least one
  /// wherever there are witnesses, however low the threshold was set.
  int get toEstablish =>
      witnesses.isEmpty ? 0 : min(max(toad, 1), witnesses.length);

  /// How many witnesses must show they do not hold an event before it can be
  /// taken to be in no one's copy of the log: enough that the rest could not
  /// meet [toEstablish] between them.
  int get toRuleOut => witnesses.length - toEstablish + 1;

  /// None: an identity with no witnesses has nothing to wait for.
  static final none = WitnessSet(const [], 0);

  /// The set after a rotation that cuts [cuts], adds [adds] and sets the
  /// threshold to [toad].
  WitnessSet rotated(
          {List<String> cuts = const [],
          List<String> adds = const [],
          required int toad}) =>
      WitnessSet([
        for (final w in witnesses)
          if (!cuts.contains(w)) w,
        ...adds
      ], toad);
}

/// The event a witness holds at a place, from a copy of the log that
/// verifies from the founding: its digest and type.
class Held {
  Held(this.digest, this.ilk);
  final String digest;
  final String ilk;

  /// Whether it is an establishment event, which nothing at its place
  /// supersedes.
  bool get establishment => ilk != 'ixn';
}

/// A copy of an identity's log a witness holds: the key state it verifies to,
/// and its events as signed, in order.
class HeldCopy {
  HeldCopy(this.state, this.events);
  final LogState state;
  final List<SignedCopy> events;
}

/// What an identity's witnesses said about one of its events, each answer
/// checked by this app.
class Witnessed {
  Witnessed(this.set, this.receipts, this.holdAnother, this.unreached);
  final WitnessSet set;

  /// Each witness whose receipt over the event's digest verified under its
  /// own key, with that receipt.
  final Map<String, String> receipts;

  /// Witnesses that hold a different event at the event's place.
  final Set<String> holdAnother;

  /// Witnesses that could not be reached, or gave no answer that checked.
  final Set<String> unreached;

  /// Whether enough witnesses receipted the event to establish it.
  bool get enough => receipts.length >= set.toEstablish;
}

/// What this app learns, by asking the witnesses itself, about the events of
/// its identity that this device signs (ADR-061 section 4, items 5 and 6).
///
/// A core that answers `201` and sends nothing on, or that says another event
/// holds a place when none does, would otherwise decide what the identity's
/// log is. So the app sends each event it signed to the witnesses itself (the
/// same signed bytes, which the witness checks before it receipts them), and
/// counts a receipt only when it verifies, under the key the witness is named
/// by, over the event's digest. What a witness holds at a place is believed
/// only as a copy of the log that verifies from the founding.
class TheWitnessesOfThisDevicesEvents {
  TheWitnessesOfThisDevicesEvents(this._client, this._km, this._where,
      {this.timeout = const Duration(seconds: 5)});

  final http.Client _client;
  final KeyMath _km;
  final WitnessDirectory _where;
  final Duration timeout;

  /// Where witness [w] is reached, or null.
  Uri? addressOf(String w) => _where.whereIs(w);

  /// Sends the event at [sn] of [aid] (its bytes [bytesB64], digest [digest]
  /// and signatures [sigs]) to every witness in [set] and checks each receipt.
  /// A witness that lacks earlier events is first sent them, from the copies
  /// the other witnesses hold. Sending the same event again is harmless: a
  /// witness answers a repeat with the receipt it already issued.
  Future<Witnessed> receipt(
      {required String aid,
      required int sn,
      required String digest,
      required String bytesB64,
      required List<String> sigs,
      required WitnessSet set}) async {
    final receipts = <String, String>{};
    final another = <String>{};
    final unreached = <String>{};
    await Future.wait([
      for (final w in set.witnesses)
        _receiptFrom(w, set, aid, sn, digest, bytesB64, sigs).then((r) {
          switch (r.$1) {
            case _Answer.receipted:
              receipts[w] = r.$2!;
            case _Answer.holdsAnother:
              another.add(w);
            case _Answer.unreached || _Answer.gap:
              unreached.add(w);
          }
        })
    ]);
    return Witnessed(set, receipts, another, unreached);
  }

  /// What each witness in [set] holds at [sn] of [aid], by witness: the
  /// event there, counted only where the witness's copy of the
  /// log up to that place verifies from the identity's founding; or null where
  /// the witness's signed answer for how far it holds the log stops before
  /// [sn]. A witness that cannot be reached, or whose answer does not check,
  /// is left out.
  Future<Map<String, Held?>> holdAt(
      {required String aid, required int sn, required WitnessSet set}) async {
    final out = <String, Held?>{};
    await Future.wait([
      for (final w in set.witnesses)
        () async {
          final base = _where.whereIs(w);
          if (base == null) return;
          final tip = await _tip(base, w, aid);
          if (tip == null) return;
          if (tip.sn < sn) {
            out[w] = null;
            return;
          }
          // The whole copy up to the tip the witness signed, so the event at
          // [sn] is the one in the history it vouches for.
          final st = (await _signedCopy(base, aid, tip))?.state;
          if (st == null) return;
          final at = st.events[sn];
          out[w] = Held(at.digest, at.ilk);
        }()
    ]);
    return out;
  }

  /// Whether witness [w] answers at its address in its own name: its signed
  /// answer to a fresh nonce checks under the key [w] is named by. Asked about
  /// [w] itself, which no log is held under, so a witness answers that it holds
  /// nothing; what is checked is who answers.
  Future<bool> answersInItsOwnName(String w) async {
    final base = _where.whereIs(w);
    return base != null && await _tip(base, w, w) != null;
  }

  /// The whole copy of [aid]'s log witness [w] holds, judged from the
  /// founding; null when it cannot be reached, holds nothing, or its copy does
  /// not verify. Where it ends is taken from its signed answer to a fresh
  /// nonce, so a copy cut short in transit is not mistaken for the whole.
  Future<HeldCopy?> copyHeldBy(String w, String aid) async {
    final base = _where.whereIs(w);
    if (base == null) return null;
    final tip = await _tip(base, w, aid);
    if (tip == null || tip.sn < 0) return null;
    return _signedCopy(base, aid, tip);
  }

  /// The copy at [base] up to [tip], judged from the founding, and ending in
  /// the event whose digest the witness signed: a copy served at a wrong
  /// address cannot pass for the witness's own.
  Future<HeldCopy?> _signedCopy(
      Uri base, String aid, ({int sn, String said}) tip) async {
    final held = await _verifiedCopy(base, aid, tip.sn);
    final st = held?.state;
    if (st == null || st.sn != tip.sn || st.digest != tip.said) return null;
    if (st.events.length != tip.sn + 1) return null;
    return held;
  }

  Future<(_Answer, String?)> _receiptFrom(String w, WitnessSet set, String aid,
      int sn, String digest, String bytesB64, List<String> sigs) async {
    final base = _where.whereIs(w);
    if (base == null) return (_Answer.unreached, null);
    var answer = await _send(base, w, aid, digest, bytesB64, sigs);
    if (answer.$1 == _Answer.gap) {
      await _fillUpTo(w, base, set, aid, sn);
      answer = await _send(base, w, aid, digest, bytesB64, sigs);
    }
    return answer.$1 == _Answer.gap ? (_Answer.unreached, null) : answer;
  }

  /// Sends one signed event to witness [w] and checks its answer.
  Future<(_Answer, String?)> _send(Uri base, String w, String aid,
      String digest, String bytesB64, List<String> sigs) async {
    final http.Response res;
    try {
      res = await _client
          .post(base.resolve('witness/event'),
              headers: const {'Content-Type': 'application/json'},
              body: jsonEncode(
                  {'aid': aid, 'event_b64': bytesB64, 'cesr_signatures': sigs}))
          .timeout(timeout);
    } catch (_) {
      return (_Answer.unreached, null);
    }
    final body = _json(res.body);
    if (res.statusCode == 409) {
      switch (body['error']) {
        case 'sequence_gap':
          return (_Answer.gap, null);
        case 'duplicate_sequence':
          // Said, not shown: [holdAt] is what checks it.
          return (_Answer.holdsAnother, null);
      }
      return (_Answer.unreached, null);
    }
    if (res.statusCode != 200) return (_Answer.unreached, null);
    final sig = body['cesr_signature'];
    if (body['witness_aid'] != w ||
        body['event_said'] != digest ||
        sig is! String ||
        !await _km.isReceipt(w, digest, sig, eventB64: bytesB64)) {
      return (_Answer.unreached, null);
    }
    return (_Answer.receipted, sig);
  }

  /// Passes an earlier event's copy on to the witness at [base]; whether it
  /// took it.
  Future<bool> _pass(Uri base, String aid, SignedCopy copy) async {
    try {
      final res = await _client
          .post(base.resolve('witness/event'),
              headers: const {'Content-Type': 'application/json'},
              body: jsonEncode({
                'aid': aid,
                'event_b64': copy.rawB64,
                'cesr_signatures': copy.sigs
              }))
          .timeout(timeout);
      return res.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// Sends witness [w] the events of [aid] it lacks before [sn], each from a
  /// copy another witness in [set] holds. The witness checks each one against
  /// the log it holds before it keeps it, so a copy from anywhere is safe to
  /// pass on.
  Future<void> _fillUpTo(
      String w, Uri base, WitnessSet set, String aid, int sn) async {
    final has = (await _tip(base, w, aid))?.sn;
    if (has == null) return;
    for (var k = has + 1; k < sn; k++) {
      SignedCopy? copy;
      for (final other in set.witnesses) {
        if (other == w) continue;
        final at = _where.whereIs(other);
        if (at == null) continue;
        copy = await _eventAt(at, aid, k);
        if (copy != null) break;
      }
      if (copy == null || !await _pass(base, aid, copy)) return;
    }
  }

  /// How far witness [w] holds [aid]'s log, and the digest of the event it
  /// ends on, from its signed answer to a fresh nonce: sequence number -1 when
  /// it holds nothing, null when it cannot be reached or its answer does not
  /// check.
  Future<({int sn, String said})?> _tip(Uri base, String w, String aid) async {
    final nonce = base64Url
        .encode(List<int>.generate(16, (_) => Random.secure().nextInt(256)))
        .replaceAll('=', '');
    try {
      final res = await _client
          .get(base.resolve('witness/kel/$aid/tip?nonce=$nonce'))
          .timeout(timeout);
      final a = _json(res.body);
      final sn = (a['sn'] as num?)?.toInt() ?? -1;
      final said = a['said'] as String? ?? '';
      final sig = a['signature'];
      if (res.statusCode != 200 ||
          (sn >= 0) == said.isEmpty ||
          a['aid'] != aid ||
          a['nonce'] != nonce ||
          a['witness_aid'] != w ||
          sig is! String ||
          !await _km.isReceipt(
              w, 'witness-kel-tip/v1\n$aid\n$nonce\n$sn\n$said', sig)) {
        return null;
      }
      return (sn: sn, said: said);
    } catch (_) {
      return null;
    }
  }

  /// The copy of [aid]'s log up to [sn] the witness at [base] holds, judged
  /// from the founding.
  Future<HeldCopy?> _verifiedCopy(Uri base, String aid, int sn) async {
    final copies = <SignedCopy>[];
    for (var k = 0; k <= sn; k++) {
      final c = await _eventAt(base, aid, k);
      if (c == null) return null;
      copies.add(c);
    }
    try {
      return HeldCopy(await _km.verifyLog(aid, copies), copies);
    } on KeyMathRefused {
      return null;
    }
  }

  Future<SignedCopy?> _eventAt(Uri base, String aid, int sn) async {
    try {
      final res = await _client
          .get(base.resolve('witness/kel/$aid/event/$sn'))
          .timeout(timeout);
      if (res.statusCode != 200) return null;
      final a = _json(res.body);
      final raw = a['raw_bytes_b64'];
      if (raw is! String || raw.isEmpty) return null;
      final sigs = [
        for (final s in (a['cesr_signatures'] as List? ?? const [])) '$s'
      ];
      if (sigs.isEmpty && a['cesr_signature'] is String) {
        sigs.add(a['cesr_signature'] as String);
      }
      return SignedCopy(raw, sigs);
    } catch (_) {
      return null;
    }
  }

  static Map<String, dynamic> _json(String body) {
    try {
      final d = jsonDecode(body);
      if (d is Map<String, dynamic>) return d;
    } catch (_) {}
    return const {};
  }
}

enum _Answer { receipted, holdsAnother, gap, unreached }
