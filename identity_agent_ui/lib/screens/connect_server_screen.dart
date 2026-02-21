import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import '../theme/app_theme.dart';

class ConnectServerScreen extends StatefulWidget {
  final void Function(String serverUrl) onConnected;
  final VoidCallback onBack;

  const ConnectServerScreen({
    super.key,
    required this.onConnected,
    required this.onBack,
  });

  @override
  State<ConnectServerScreen> createState() => _ConnectServerScreenState();
}

class _ConnectServerScreenState extends State<ConnectServerScreen> {
  final _urlController = TextEditingController();
  bool _connecting = false;
  String? _error;
  String? _serverInfo;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) {
      setState(() => _error = 'Please enter a server URL.');
      return;
    }

    String normalizedUrl = url;
    if (!normalizedUrl.startsWith('http://') &&
        !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://$normalizedUrl';
    }
    if (normalizedUrl.endsWith('/')) {
      normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 1);
    }

    setState(() {
      _connecting = true;
      _error = null;
      _serverInfo = null;
    });

    try {
      final response = await http
          .get(Uri.parse('$normalizedUrl/api/health'))
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final status = data['status'] ?? 'unknown';
        final agent = data['agent'] ?? 'unknown';
        final version = data['version'] ?? '';

        if (status == 'active') {
          setState(() {
            _serverInfo = '$agent v$version';
            _connecting = false;
          });

          await Future.delayed(const Duration(milliseconds: 500));
          widget.onConnected(normalizedUrl);
        } else {
          setState(() {
            _connecting = false;
            _error =
                'Server responded but status is "$status". Expected "active".';
          });
        }
      } else {
        setState(() {
          _connecting = false;
          _error =
              'Server returned status ${response.statusCode}. '
              'Make sure Identity Agent is running at this URL.';
        });
      }
    } catch (e) {
      setState(() {
        _connecting = false;
        _error =
            'Could not reach the server. Check the URL and make sure '
            'the server is running and accessible.\n\n'
            'Details: ${e.toString().length > 120 ? e.toString().substring(0, 120) : e.toString()}';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    width: 64,
                    height: 64,
                    decoration: BoxDecoration(
                      color: AppColors.accent.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: AppColors.accent.withOpacity(0.3),
                        width: 1.5,
                      ),
                    ),
                    child: const Icon(
                      Icons.link,
                      color: AppColors.accent,
                      size: 32,
                    ),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    'CONNECT TO SERVER',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 20,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 2.0,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Enter the URL of your Identity Agent server. '
                    'This is the address where your primary identity is running.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      height: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 32),
                  Container(
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      color: AppColors.surface,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: AppColors.border, width: 1),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'SERVER URL',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            letterSpacing: 1.5,
                            fontFamily: 'monospace',
                          ),
                        ),
                        const SizedBox(height: 10),
                        TextField(
                          controller: _urlController,
                          style: const TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 14,
                            fontFamily: 'monospace',
                          ),
                          decoration: InputDecoration(
                            hintText: 'https://your-server.example.com',
                            hintStyle: TextStyle(
                              color: AppColors.textMuted.withOpacity(0.5),
                              fontFamily: 'monospace',
                              fontSize: 13,
                            ),
                            filled: true,
                            fillColor: AppColors.primary,
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide:
                                  const BorderSide(color: AppColors.border),
                            ),
                            enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide:
                                  const BorderSide(color: AppColors.border),
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide:
                                  const BorderSide(color: AppColors.accent),
                            ),
                            prefixIcon: const Icon(
                              Icons.dns_outlined,
                              color: AppColors.textMuted,
                              size: 20,
                            ),
                          ),
                          keyboardType: TextInputType.url,
                          autocorrect: false,
                          enableSuggestions: false,
                          textInputAction: TextInputAction.go,
                          onSubmitted: (_) => _connect(),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'This can be a Cloudflare tunnel URL, ngrok URL, '
                          'or any address where your server is reachable.',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 10,
                            height: 1.4,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: AppColors.coreInactive.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: AppColors.coreInactive.withOpacity(0.3),
                          width: 1,
                        ),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Icon(Icons.error_outline,
                              color: AppColors.coreInactive, size: 18),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              _error!,
                              style: const TextStyle(
                                color: AppColors.coreInactive,
                                fontSize: 11,
                                height: 1.4,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                  if (_serverInfo != null) ...[
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: AppColors.accent.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: AppColors.accent.withOpacity(0.3),
                          width: 1,
                        ),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.check_circle_outline,
                              color: AppColors.accent, size: 18),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              'Connected to $_serverInfo',
                              style: const TextStyle(
                                color: AppColors.accent,
                                fontSize: 12,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                  const SizedBox(height: 24),
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      onPressed: _connecting ? null : _connect,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.accent,
                        foregroundColor: AppColors.primary,
                        padding: const EdgeInsets.symmetric(vertical: 16),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                        disabledBackgroundColor:
                            AppColors.accent.withOpacity(0.3),
                      ),
                      child: _connecting
                          ? const SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: AppColors.primary,
                              ),
                            )
                          : const Text(
                              'CONNECT',
                              style: TextStyle(
                                fontSize: 14,
                                fontWeight: FontWeight.w700,
                                letterSpacing: 1.5,
                                fontFamily: 'monospace',
                              ),
                            ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextButton(
                    onPressed: widget.onBack,
                    child: const Text(
                      'GO BACK',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 12,
                        fontWeight: FontWeight.w500,
                        letterSpacing: 1.0,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
