import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'app_checks.dart';
import 'front_end_key.dart';
import 'installed_app.dart';
import 'seal.dart';

/// Where a front end keeps what a sign-in gave it: a browser's session or an
/// installed app's app-key grant, which lasts until it is ended, so an installed
/// app keeps it across restarts (login-flutter keeps it in the platform's secure
/// storage).
abstract class GrantStore {
  Future<String?> read();
  Future<void> write(String token);
  Future<void> clear();
}

/// A [GrantStore] in memory, for tests and for a front end that signs in each run.
class MemoryGrantStore implements GrantStore {
  String? _token;
  @override
  Future<String?> read() async => _token;
  @override
  Future<void> write(String token) async => _token = token;
  @override
  Future<void> clear() async => _token = null;
}

/// The app ended the session or grant (or never knew it): the person has to sign
/// in again.
class SessionEnded implements Exception {
  const SessionEnded();
  String get message =>
      'Your session with this app has ended, so you have been signed out. Sign in again to carry on.';
  @override
  String toString() => message;
}

/// A sign-in refused or failed, in words a person can act on.
class SignInFailed implements Exception {
  final String message;
  const SignInFailed(this.message);
  @override
  String toString() => message;
}

/// A sign-in the app's back end started for this front end's key.
class SignInStarted {
  /// What to open in the person's Identity Agent to approve it: shown only after
  /// the app's challenge for it has been checked.
  final String pointer;

  /// The app's own name for this sign-in: what each proof while signing in is
  /// bound to.
  final String signInId;
  final Duration skew;

  /// When the app's signed challenge lapses, by the app's clock.
  final DateTime expiry;

  /// The key's short code, for the person to compare on their Identity Agent.
  final String fingerprint;
  const SignInStarted(this.pointer, this.signInId, this.skew,
      {required this.expiry, required this.fingerprint});
}

/// One answer from the app, already shown to be the app's.
class AppAnswer {
  final int status;
  final Uint8List body;
  const AppAnswer(this.status, this.body);
  Map<String, dynamic> json() {
    try {
      final j = jsonDecode(utf8.decode(body));
      return j is Map<String, dynamic> ? j : {};
    } catch (_) {
      return {};
    }
  }
}

/// The one place an installed (or Flutter) front end of a utility app signs in to
/// its app's back end and makes every later call (ADR-072 section 2). It is the
/// Dart counterpart of login-web's `appFetch` and `appSession`: every call is
/// signed by the front end's [key] and sealed for the back end, the relay reads
/// none of it, and every answer is believed only if the app signed it for that
/// call. A front end has no copy of any of it.
///
/// Signing in is the Ask (ADR-021): [start] shows the person's Identity Agent
/// what to approve, [wait] asks until they have, and the back end then binds them
/// to the key, a session for a browser or an app-key grant for an installed app,
/// which is kept in [store] until it is ended.
class AppSession {
  final http.Client client;
  final AppLink link;
  final FrontEndKey key;

  final GrantStore store;
  final AnswerLogs logs;
  final DateTime Function() now;
  final Random _random;
  late final CheckedSealKey _sealKey = CheckedSealKey(link, logs, client);
  Duration _skew = Duration.zero;
  bool _synced = false;

  AppSession(this.client, this.link, this.key,
      {GrantStore? store,
      AnswerLogs? logs,
      DateTime Function()? now,
      Random? random})
      : store = store ?? MemoryGrantStore(),
        logs = logs ?? AnswerLogs(),
        now = now ?? DateTime.now,
        _random = random ?? Random.secure();

  String _nonce([int n = 12]) =>
      b64uEncode(List<int>.generate(n, (_) => _random.nextInt(256)));

  String _stamp(Duration skew) =>
      '${now().add(skew).toUtc().toIso8601String().split('.').first}Z';

  Future<AppAnswer> _send(String method, String path, String body,
      Future<Map<String, String>> Function(Duration skew) headers) async {
    final bytes = utf8.encode(body);
    final r = await sealedCallDated(client, link, _sealKey,
        logs: logs, now: now, skew: _skew, make: (skew) async {
      return (
        method: method,
        target: path,
        headers: {
          ...await headers(skew),
          if (method != 'GET') 'content-type': 'application/json',
        },
        body: bytes,
        nonce: _nonce(),
      );
    });
    _skew = r.skew;
    return AppAnswer(r.answer.status, r.answer.body);
  }

  T _guard<T>(T Function() f) {
    try {
      return f();
    } on TrustRefused catch (e) {
      throw SignInFailed(e.message);
    }
  }

  Map<String, dynamic> _ok(AppAnswer r, String what) {
    if (r.status == 200) return r.json();
    if (r.status == 502 || r.status == 503 || r.status == 504) {
      throw SignInFailed(
          '$what failed: the app could not reach your Identity Agent just now. Try again in a minute.');
    }
    final e = r.json()['error'];
    throw SignInFailed(e is String ? e : '$what failed (HTTP ${r.status}).');
  }

  /// Starts a sign-in for [key]. An installed front end first asks its back end
  /// for an ask and has its hardware make evidence for it; the back end carries
  /// that to the Identity Agent, which checks it. The challenge that comes back
  /// is shown only after it is checked to be the app's, naming this key and this
  /// kind of front end.
  Future<SignInStarted> start() async {
    final appKey = _guard(() => checkKeyLog(link.aid, link.kel));
    InstalledKeyProof? proof;
    if (key.kind == FrontEndKind.installedApp) {
      final asked = _ok(
          await _send('POST', installedAskPath, '{}', (_) async => {}),
          'Asking the app for evidence of this device\'s key');
      final ask = _guard(() => InstalledAsk.fromJson(asked));
      proof = await key.prove(ask, exchange: (enrolment) async {
        final j = _ok(
            await _send(
                'POST',
                installedCredentialPath,
                jsonEncode(enrolment.toJson(ask.ask)),
                (_) async => {}),
            'Asking the app for a credential for this device\'s TPM');
        return _guard(() => TpmCredential.fromJson(j));
      });
      if (proof == null) {
        throw const SignInFailed(
            'This device cannot prove its key to the app, so it cannot sign in as the app\'s installed front end.');
      }
    }
    final j = _ok(
        await _send(
            'POST',
            '/signin/session',
            frontEndStartBody(
                kind: key.kind,
                jwk: key.jwk,
                thumbprint: key.thumbprint,
                proof: proof),
            (_) async => {}),
        'Starting the sign-in');
    final skew = _guard(() => serverSkew(j['server_time'], now()));
    _skew = skew;
    final c = _guard(() => checkChallenge(
        aid: link.aid,
        key: appKey,
        body: j['canonical_body'],
        sig: j['sig'],
        pointer: j['relay_or_qr_url'],
        ownThumbprint: key.thumbprint,
        now: now().add(skew),
        frontEnd: key.kind.wire));
    final id = j['session_token'];
    if (id is! String || id.isEmpty) {
      throw const SignInFailed('The app did not say what to open to approve.');
    }
    return SignInStarted(j['relay_or_qr_url'] as String, id, skew,
        expiry: DateTime.parse('${c['expiry']}'),
        fingerprint: keyFingerprint(key.thumbprint));
  }

  /// One ask of `GET /signin/session/{id}`: false while the person has not
  /// decided; true once the grant is kept.
  Future<bool> finishOnce(SignInStarted s) async {
    final path = '/signin/session/${Uri.encodeComponent(s.signInId)}';
    final r = await _send('GET', path, '', (skew) async {
      final ts = _stamp(skew);
      final nonce = _nonce(16);
      return {
        'x-browser-proof-time': ts,
        'x-browser-proof-nonce': nonce,
        'x-browser-proof': await key.sign(
            backEndProofString('GET', path, ts, nonce, s.signInId, const [])),
      };
    });
    final j = _ok(r, 'Finishing the sign-in');
    switch (j['state']) {
      case 'declined':
        throw const SignInFailed(
            'The sign-in was not accepted. Either you declined it in your Identity Agent, or that Identity Agent is not on the app’s list of people who may sign in. '
            'Ask the app’s owner to add you under “My apps”, then try again.');
      case 'verified':
        final t = j['app_session_token'];
        if (t is! String || t.isEmpty) {
          throw const SignInFailed(
              'The app signed you in but gave no session.');
        }
        await store.write(t);
        return true;
    }
    return false;
  }

  /// Asks until decided, every [every]; gives up when the challenge lapses (by
  /// the app's clock) or after [until].
  Future<void> wait(SignInStarted s,
      {Duration every = const Duration(seconds: 2),
      Duration until = const Duration(minutes: 10)}) async {
    const ranOut = SignInFailed(
        'The sign-in ran out of time before it was approved. Press the button to start a new one.');
    final end = now().add(until);
    while (now().isBefore(end)) {
      await Future<void>.delayed(every);
      if (s.expiry.isBefore(now().add(_skew))) throw ranOut;
      if (await finishOnce(s)) return;
    }
    throw ranOut;
  }

  /// Whether this front end holds a session or grant (it may have ended at the app).
  Future<bool> get signedIn async => await store.read() != null;

  /// A call to the app's back end as the person signed in: carries the grant and
  /// a proof made with the key, and is believed only if the app's signed answer
  /// holds for it. A 401 forgets the grant and is a [SessionEnded].
  Future<AppAnswer> call(String method, String path, [String body = '']) async {
    method = method.toUpperCase();
    final token = await store.read();
    if (token == null) throw const SessionEnded();
    // A restart has lost the app's clock: ask for it first, so the proof is dated as the app counts.
    // (Signing out does not wait on it: a front end that cannot be told the clock still ends its grant.)
    if (!_synced && path != '/session/whoami' && path != '/session/signout') {
      await whoami();
    }
    final r =
        await _send(method, path, method == 'GET' ? '' : body, (skew) async {
      final ts = _stamp(skew);
      final nonce = _nonce(16);
      return {
        'authorization': 'Bearer $token',
        'x-browser-proof-time': ts,
        'x-browser-proof-nonce': nonce,
        'x-browser-proof': await key.sign(backEndProofString(
            method,
            path,
            ts,
            nonce,
            sessionBinding(token),
            utf8.encode(method == 'GET' ? '' : body))),
      };
    });
    if (r.status == 401) {
      await store.clear();
      throw const SessionEnded();
    }
    return r;
  }

  /// Who the app says is signed in (`GET /session/whoami`).
  Future<Map<String, dynamic>> whoami() async {
    final r = await call('GET', '/session/whoami');
    if (r.status != 200) {
      throw const SignInFailed(
          'The utility app would not say who is signed in.');
    }
    final w = r.json();
    _skew = _guard(() => serverSkew(w['server_time'], now()));
    _synced = true;
    return w;
  }

  /// Ends the session or grant at the app as far as the app can be reached, and
  /// forgets it here.
  Future<void> signOut() async {
    try {
      if (await store.read() != null)
        await call('POST', '/session/signout', '{}');
    } catch (_) {
      // The app could not be reached or had already ended it: either way this device forgets it.
    } finally {
      await store.clear();
    }
  }
}
