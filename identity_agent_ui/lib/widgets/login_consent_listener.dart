import 'dart:async';
import 'package:flutter/material.dart';
import '../services/event_service.dart';
import '../services/login_service.dart';
import '../theme/app_theme.dart';
import 'consent_modal.dart';

/// Listens for `login_pending` events and shows the B1 consent modal.
class LoginConsentListener extends StatefulWidget {
  final String? serverUrl;
  final Widget child;

  const LoginConsentListener({
    super.key,
    required this.child,
    this.serverUrl,
  });

  @override
  State<LoginConsentListener> createState() => _LoginConsentListenerState();
}

class _LoginConsentListenerState extends State<LoginConsentListener> {
  StreamSubscription<AgentEvent>? _sub;
  LoginService? _loginService;
  bool _showing = false;

  @override
  void initState() {
    super.initState();
    final baseUrl = widget.serverUrl;
    if (baseUrl != null && baseUrl.isNotEmpty) {
      _loginService = LoginService(baseUrl: baseUrl);
      _sub = EventService.instance(baseUrl).events.listen(_onEvent);
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    _loginService?.dispose();
    super.dispose();
  }

  Future<void> _onEvent(AgentEvent event) async {
    if (event.type != 'login_pending' || _showing || !mounted) return;
    final payload = event.payload;
    final sessionToken = payload['session_token'] as String? ?? '';
    final rpSessionUrl = payload['rp_session_url'] as String? ?? '';
    if (sessionToken.isEmpty || rpSessionUrl.isEmpty) return;

    final preview = LoginPreview.fromJson(payload);
    await _showConsent(preview, sessionToken, rpSessionUrl);
  }

  Future<void> showLoginConsent(LoginPreview preview) {
    return _showConsent(
      preview,
      preview.sessionToken,
      preview.rpSessionUrl,
    );
  }

  Future<void> _showConsent(
    LoginPreview preview,
    String sessionToken,
    String rpSessionUrl,
  ) async {
    if (_showing || !mounted) return;
    _showing = true;

    final details = preview.requestedDisclosures.map((field) {
      final label = field.replaceAll('_', ' ');
      return ConsentDetailItem(
        label: label,
        value: preview.disclosurePreview[field] ?? '—',
        isMonospace: field.contains('aid') || field.contains('email'),
      );
    }).toList();

    // A site can ask for credentials and a trust score as well as fields.
    // Listing only the fields understated what approving does.
    for (final cred in preview.requestedCredentials) {
      details.add(ConsentDetailItem(
        label: 'Credential ${cred.shortSaid}',
        value: cred.consentValue,
      ));
    }
    if (preview.requestedScore != null) {
      details.add(ConsentDetailItem(
        label: 'Trust score',
        value: preview.requestedScore!.consentValue,
      ));
    }

    final result = await ConsentModal.show(
      context: context,
      title: 'Sign in request',
      subtitle: preview.audience,
      name: preview.siteLabel,
      avatarLabel: preview.siteLabel.isNotEmpty
          ? preview.siteLabel[0].toUpperCase()
          : '?',
      details: details,
      confirmLabel: 'Approve',
      cancelLabel: 'Deny',
      accentColor: AppColors.accent,
      icon: Icons.login_rounded,
      warningMessage:
          'You are signing in to this site. Only what is listed above is shared.',
    );

    if (!mounted) {
      _showing = false;
      return;
    }

    final login = _loginService;
    if (login == null) {
      _showing = false;
      return;
    }

    try {
      if (result?.confirmed == true) {
        await login.approve(
          sessionToken: sessionToken,
          rpSessionUrl: rpSessionUrl,
        );
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Signed in successfully')),
          );
        }
      } else if (result?.confirmed == false) {
        await login.decline(
          sessionToken: sessionToken,
          rpSessionUrl: rpSessionUrl,
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Login failed: $e')),
        );
      }
    } finally {
      _showing = false;
    }
  }

  @override
  Widget build(BuildContext context) => widget.child;
}