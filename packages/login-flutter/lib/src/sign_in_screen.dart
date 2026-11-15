import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show PlatformException;
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
  final http.Client Function() makeClient;

  /// The utility app's asset identifier, which the hardware's evidence is made for.
  final String Function(AppLink link) assetId;

  /// The key and the grant store for the link opened (an installed app: a
  /// `HardwareFrontEndKey` and a `SecureGrantStore`).
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
    required this.assetId,
    required this.keyFor,
    required this.storeFor,
    required this.onSignedIn,
    this.pinnedLink,
    this.every = const Duration(seconds: 2),
    this.notice,
    this.scan,
    this.deviceName,
  });

  @override
  State<UtilityAppSignInScreen> createState() => _State();
}

class _State extends State<UtilityAppSignInScreen> {
  late final _link = TextEditingController(text: widget.pinnedLink ?? '');
  String? _pointer, _fingerprint, _error;
  bool _busy = false;

  Future<void> _scan() async {
    final text = await widget.scan!(context);
    if (text == null || !mounted) return;
    _link.text = text.trim();
    await _go();
  }

  Future<void> _go() async {
    final AppLink link;
    try {
      link = AppLink.parse(_link.text.trim());
    } on TrustRefused catch (e) {
      setState(() => _error = e.message);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _pointer = null;
    });
    final client = widget.makeClient();
    try {
      final session = AppSession(client, link, await widget.keyFor(link),
          assetId: widget.assetId(link), store: widget.storeFor(link));
      final started = await session.start();
      if (!mounted) return;
      setState(() {
        _pointer = started.pointer;
        _fingerprint = started.fingerprint;
      });
      await session.wait(started, every: widget.every);
      if (!mounted) return;
      widget.onSignedIn(session);
    } on SignInFailed catch (e) {
      if (mounted) setState(() => _error = e.message);
    } on TrustRefused catch (e) {
      if (mounted) setState(() => _error = e.message);
    } on PlatformException catch (e) {
      // The device's hardware said why it cannot make or prove the key: say that, not that the app is down.
      if (mounted) {
        setState(() => _error = e.message ??
            'This device\'s secure hardware could not make the key.');
      }
    } catch (e) {
      if (mounted) {
        setState(() => _error =
            '${widget.appName} could not be reached just now. Check the connection and try again.');
      }
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
  void dispose() {
    _link.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final n = widget.appName;
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
                  child: const Text('Sign in with my Identity Agent')),
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
                const Text(
                    'In your Identity Agent, scan this code or open this address:'),
                SelectableText(_pointer!, key: const Key('pointer')),
                const SizedBox(height: 8),
                Center(child: QrImageView(data: _pointer!, size: 180)),
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
    );
  }
}
