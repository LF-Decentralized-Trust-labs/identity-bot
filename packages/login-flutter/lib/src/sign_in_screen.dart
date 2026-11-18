import 'dart:developer' as developer;

import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData, PlatformException;
import 'package:http/http.dart' as http;
import 'package:login_dart/app_checks.dart';
import 'package:login_dart/app_session.dart';
import 'package:login_dart/front_end_key.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Signs a person in to a utility app from its installed front end: the button, the
/// code to compare, and the waiting state. What it does is `AppSession.start` and
/// `wait`; it shows nothing the SDK has not checked (the key log, the challenge for
/// this key and kind), and an installed front end's key is the hardware's.
class UtilityAppSignInScreen extends StatefulWidget {
  /// What the person calls the app, in the screen's words.
  final String appName;

  /// The app's own link, when this front end is its own app's and so is pinned by
  /// what it is (ADR-072 section 2); otherwise the person pastes or scans one.
  final String? pinnedLink;

  /// The link the person used last, put in the field to be changed or kept, so a
  /// person who signs out is not asked to paste it again. Ignored when [pinnedLink] is set.
  final String? initialLink;

  /// Called with the link once a sign-in has started on it, so the app can keep it for [initialLink].
  final void Function(String link)? onLinkUsed;
  final http.Client Function() makeClient;

  /// The key and the grant store for the link opened (an installed app:
  /// `openInstalledFrontEndKey`, which uses the hardware's key where the app's
  /// owner accepts it and a key in software where the owner allows that, and a
  /// `SecureGrantStore`).
  final Future<FrontEndKey> Function(AppLink link) keyFor;
  final GrantStore Function(AppLink link) storeFor;

  /// The person is signed in: the session to make calls with.
  final void Function(AppSession session) onSignedIn;
  final Duration every;

  /// Said above the sign-in: the session ended, or the person signed out.
  final String? notice;

  /// Reads the app's link from its QR code; null where this device has no camera.
  final Future<String?> Function(BuildContext context)? scan;
  final String? deviceName;

  const UtilityAppSignInScreen({
    super.key,
    required this.appName,
    required this.makeClient,
    required this.keyFor,
    required this.storeFor,
    required this.onSignedIn,
    this.pinnedLink,
    this.initialLink,
    this.onLinkUsed,
    this.every = const Duration(seconds: 2),
    this.notice,
    this.scan,
    this.deviceName,
  });

  @override
  State<UtilityAppSignInScreen> createState() => _State();
}

/// What a person is told when the device's secure hardware cannot make or prove the
/// key, by the platform code's error [code]. The code's own message is for developers
/// and goes to the log, never to the screen.
String hardwareProblem(PlatformException e, String appName) {
  switch (e.code) {
    case 'unsupported':
      return 'This device does not support the secure hardware ${_name(appName)} signs in with. '
          'Try a different device.';
    case 'no_key':
    case 'no_enrolment':
      return 'This device\'s sign-in key is not there any more. Press the button to sign in again.';
    case 'no_tpm':
      return 'This computer has no security chip (TPM) that ${_name(appName)} can sign in with, or it is switched off. '
          'Turn it on in the computer\'s settings, or sign in from a phone.';
    case 'no_ek_certificate':
      return 'This computer\'s security chip did not give the proof ${_name(appName)} needs. '
          'Sign in from a phone, or ask ${_name(appName)}\'s owner.';
    default:
      return 'This device\'s secure hardware could not make or prove the sign-in key. '
          'Press the button to try again; if it keeps happening, restart the device or ask ${_name(appName)}\'s owner.';
  }
}

/// The app's name as the screen says it; the same fallback as login-web's `signInProblem`.
String _name(String appName) =>
    appName.trim().isEmpty ? 'this utility app' : appName.trim();

class _State extends State<UtilityAppSignInScreen> {
  late final _link = TextEditingController(text: widget.pinnedLink ?? widget.initialLink ?? '');
  String? _pointer, _fingerprint, _error, _progress;
  bool _busy = false, _copied = false;

  String get _n => _name(widget.appName);

  Future<void> _scan() async {
    final text = await widget.scan!(context);
    if (text == null || !mounted) return;
    _link.text = text.trim();
    await _go();
  }

  /// Ends the attempt with [message]: nothing that says it is still waiting stays beside it.
  void _fail(String message) {
    if (!mounted) return;
    setState(() {
      _error = message;
      _pointer = null;
      _fingerprint = null;
      _progress = null;
      _copied = false;
    });
  }

  void _phase(SignInPhase p) {
    if (!mounted) return;
    setState(() => _progress = switch (p) {
          SignInPhase.proveKey => 'Checking this device\'s secure hardware…',
          SignInPhase.credential =>
            'Getting this device a credential from the app…',
          SignInPhase.start => 'Starting the sign-in…',
        });
  }

  Future<void> _go() async {
    final AppLink link;
    try {
      link = AppLink.parse(_link.text.trim());
    } on TrustRefused catch (e) {
      _fail(e.message);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _pointer = null;
      _fingerprint = null;
      _copied = false;
      _progress = 'Checking this device\'s secure hardware…';
    });
    final client = widget.makeClient();
    try {
      final session = AppSession(client, link, await widget.keyFor(link),
          store: widget.storeFor(link));
      final started = await session.start(onPhase: _phase);
      widget.onLinkUsed?.call(_link.text.trim());
      if (!mounted) return;
      setState(() {
        _pointer = started.pointer;
        _fingerprint = started.fingerprint;
        _progress = null;
      });
      await session.wait(started, every: widget.every);
      if (!mounted) return;
      widget.onSignedIn(session);
    } on SignInFailed catch (e) {
      _fail(e.message);
    } on TrustRefused catch (e) {
      _fail(e.message);
    } on UnsupportedError {
      _fail('This device has no secure hardware this app can sign in with.');
    } on PlatformException catch (e) {
      developer.log('hardware key: ${e.code}: ${e.message}',
          name: 'login_flutter');
      _fail(hardwareProblem(e, widget.appName));
    } catch (e) {
      developer.log('sign-in: $e', name: 'login_flutter');
      _fail('$_n could not be reached just now. Check the connection and try again.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _device() {
    if (widget.deviceName != null) return widget.deviceName!;
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return 'this Android device';
      case TargetPlatform.iOS:
        return 'this iPhone or iPad';
      case TargetPlatform.macOS:
        return 'this Mac';
      case TargetPlatform.windows:
        return 'this Windows computer';
      default:
        return 'this device';
    }
  }

  @override
  void didUpdateWidget(UtilityAppSignInScreen old) {
    super.didUpdateWidget(old);
    // The last link may be read from storage after the screen is up: fill the field with it
    // unless the person has already typed or pasted one.
    if (old.initialLink != widget.initialLink &&
        widget.pinnedLink == null &&
        _link.text.isEmpty) {
      _link.text = widget.initialLink ?? '';
    }
  }

  @override
  void dispose() {
    _link.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final n = _n;
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 460),
        child: ListView(
            shrinkWrap: true,
            padding: const EdgeInsets.all(24),
            children: [
              Text('Sign in to $n',
                  style: Theme.of(context).textTheme.headlineSmall),
              if (widget.notice != null)
                Padding(
                    padding: const EdgeInsets.only(top: 12),
                    child: Text(widget.notice!, key: const Key('notice'))),
              const SizedBox(height: 16),
              if (widget.pinnedLink == null) ...[
                Text(
                    'Your Identity Agent shows $n’s sign-in QR code and link under “My apps”.'),
                const SizedBox(height: 8),
                if (widget.scan != null) ...[
                  OutlinedButton.icon(
                      key: const Key('scan'),
                      onPressed: _busy ? null : _scan,
                      icon: const Icon(Icons.qr_code_scanner),
                      label: const Text('Scan its QR code')),
                  const SizedBox(height: 8),
                  const Text('or paste its link:'),
                ],
                TextField(
                    key: const Key('field-link'),
                    controller: _link,
                    decoration: InputDecoration(
                        labelText:
                            '$n sign-in link (the whole link, with the part after #)')),
                const SizedBox(height: 16),
              ],
              FilledButton(
                  key: const Key('sign-in'),
                  onPressed: _busy ? null : _go,
                  child: Text(_busy ? 'Connecting…' : 'Sign in with Identity Agent')),
              Semantics(
                liveRegion: true,
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  if (_progress != null)
                    Padding(
                        padding: const EdgeInsets.only(top: 16),
                        child: Row(children: [
                          const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(
                                  key: Key('progress'), strokeWidth: 2)),
                          const SizedBox(width: 12),
                          Expanded(
                              child:
                                  Text(_progress!, key: const Key('progress-text'))),
                        ])),
                  if (_pointer != null) ...[
                    const SizedBox(height: 16),
                    Text(
                        'Now approve this sign-in in your Identity Agent, on your phone. '
                        'It will ask whether to let ${_device()} into $n. '
                        'Check that the request shows this code, and approve only if it does; '
                        'if the code is different, decline.'),
                    const SizedBox(height: 8),
                    SelectableText(_fingerprint ?? '',
                        key: const Key('fingerprint'),
                        style: Theme.of(context).textTheme.titleLarge),
                    const SizedBox(height: 8),
                    const Text('In your Identity Agent, scan this code:'),
                    const SizedBox(height: 8),
                    Center(
                        child: Semantics(
                            container: true, // its own node, not merged into the live region's text
                            label:
                                'QR code to approve this sign-in in your Identity Agent',
                            image: true,
                            child: ExcludeSemantics(
                                child: QrImageView(data: _pointer!, size: 180)))),
                    Center(
                        child: TextButton(
                            key: const Key('copy-link'),
                            onPressed: () async {
                              await Clipboard.setData(ClipboardData(text: _pointer!));
                              if (mounted) setState(() => _copied = true);
                            },
                            child: Text(_copied ? 'Link copied' : 'Copy link instead'))),
                    const Text('Waiting for your approval…', key: Key('waiting')),
                  ],
                  if (_error != null)
                    Padding(
                        padding: const EdgeInsets.only(top: 12),
                        child: Text(_error!,
                            key: const Key('sign-in-error'),
                            style: TextStyle(
                                color: Theme.of(context).colorScheme.error))),
                ]),
              ),
            ]),
      ),
    );
  }
}
