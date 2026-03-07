import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import '../../theme/mobile_theme.dart';

class MobileConnectServerScreen extends StatefulWidget {
  final void Function(String serverUrl) onConnected;
  final VoidCallback onBack;

  const MobileConnectServerScreen({
    super.key,
    required this.onConnected,
    required this.onBack,
  });

  @override
  State<MobileConnectServerScreen> createState() =>
      _MobileConnectServerScreenState();
}

class _MobileConnectServerScreenState extends State<MobileConnectServerScreen> {
  final _urlController = TextEditingController();
  bool _connecting = false;
  String? _error;
  String? _statusMessage;
  int _step = 0;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  String _normalizeUrl(String url) {
    String normalized = url.trim();
    if (!normalized.startsWith('http://') &&
        !normalized.startsWith('https://')) {
      normalized = 'https://$normalized';
    }
    if (normalized.endsWith('/')) {
      normalized = normalized.substring(0, normalized.length - 1);
    }
    return normalized;
  }

  Future<void> _connect() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) {
      setState(() => _error = 'Please enter a server URL.');
      return;
    }

    final normalizedUrl = _normalizeUrl(url);

    setState(() {
      _connecting = true;
      _error = null;
      _statusMessage = null;
      _step = 0;
    });

    try {
      setState(() {
        _step = 1;
        _statusMessage = 'Checking server health...';
      });

      final healthResponse = await http
          .get(Uri.parse('$normalizedUrl/api/health'))
          .timeout(const Duration(seconds: 10));

      if (healthResponse.statusCode != 200) {
        setState(() {
          _connecting = false;
          _error =
              'Server returned status ${healthResponse.statusCode}. '
              'Make sure Identity Agent is running at this URL.';
        });
        return;
      }

      final healthData = jsonDecode(healthResponse.body);
      final status = healthData['status'] ?? 'unknown';

      if (status != 'active') {
        setState(() {
          _connecting = false;
          _error =
              'Server responded but status is "$status". Expected "active".';
        });
        return;
      }

      final agent = healthData['agent'] ?? 'unknown';
      final version = healthData['version'] ?? '';

      setState(() {
        _step = 2;
        _statusMessage = 'Server found ($agent v$version). Fetching OOBI...';
      });

      final oobiResponse = await http
          .get(Uri.parse('$normalizedUrl/api/oobi'))
          .timeout(const Duration(seconds: 10));

      if (oobiResponse.statusCode != 200) {
        setState(() {
          _connecting = false;
          _error =
              'Server is running but no identity was found. '
              'The server needs an identity created before you can connect to it.';
        });
        return;
      }

      final oobiData = jsonDecode(oobiResponse.body);
      final oobiUrl = oobiData['oobi_url'] ?? '';
      final aid = oobiData['aid'] ?? '';

      if (oobiUrl.isEmpty || aid.isEmpty) {
        setState(() {
          _connecting = false;
          _error =
              'Server responded but did not return a valid OOBI URL. '
              'Make sure the server has an identity created.';
        });
        return;
      }

      setState(() {
        _step = 3;
        _statusMessage = 'OOBI found. Resolving identity ($aid)...';
      });

      final resolveResponse = await http
          .get(Uri.parse(oobiUrl))
          .timeout(const Duration(seconds: 15));

      if (resolveResponse.statusCode != 200) {
        setState(() {
          _connecting = false;
          _error =
              'Could not resolve the OOBI URL. The server\'s public identity '
              'endpoint may not be reachable from this device.';
        });
        return;
      }

      final resolvedData = jsonDecode(resolveResponse.body);
      final resolvedAid = resolvedData['aid'] ?? '';

      if (resolvedAid.isEmpty) {
        setState(() {
          _connecting = false;
          _error = 'OOBI resolution returned no identity data.';
        });
        return;
      }

      setState(() {
        _step = 4;
        _statusMessage = 'OOBI resolved. Identity verified.';
        _connecting = false;
      });

      await Future.delayed(const Duration(milliseconds: 800));
      widget.onConnected(normalizedUrl);
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
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
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
                        color: MobileColors.primary.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(
                          color: MobileColors.primary.withOpacity(0.3),
                          width: 1.5,
                        ),
                      ),
                      child: const Icon(
                        Icons.link,
                        color: MobileColors.primary,
                        size: 32,
                      ),
                    ),
                    const SizedBox(height: 24),
                    const Text(
                      'Connect to Server',
                      style: TextStyle(
                        color: MobileColors.textPrimary,
                        fontSize: 22,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Enter the URL of your Identity Agent server. '
                      'This will establish a cryptographic relationship '
                      'by resolving the server\'s OOBI.',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: MobileColors.textSecondary,
                        fontSize: 14,
                        height: 1.5,
                      ),
                    ),
                    const SizedBox(height: 32),
                    Container(
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: MobileColors.surface,
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(color: MobileColors.border, width: 1),
                        boxShadow: [
                          BoxShadow(
                            color: MobileColors.cardShadow,
                            blurRadius: 8,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Server URL',
                            style: TextStyle(
                              color: MobileColors.textMuted,
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 10),
                          TextField(
                            controller: _urlController,
                            style: const TextStyle(
                              color: MobileColors.textPrimary,
                              fontSize: 15,
                            ),
                            decoration: InputDecoration(
                              hintText: 'https://your-server.example.com',
                              hintStyle: TextStyle(
                                color: MobileColors.textMuted.withOpacity(0.6),
                                fontSize: 14,
                              ),
                              filled: true,
                              fillColor: MobileColors.surfaceSecondary,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(10),
                                borderSide: const BorderSide(
                                    color: MobileColors.border),
                              ),
                              enabledBorder: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(10),
                                borderSide: const BorderSide(
                                    color: MobileColors.border),
                              ),
                              focusedBorder: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(10),
                                borderSide: const BorderSide(
                                    color: MobileColors.primary, width: 2),
                              ),
                              prefixIcon: const Icon(
                                Icons.dns_outlined,
                                color: MobileColors.textMuted,
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
                              color: MobileColors.textMuted,
                              fontSize: 12,
                              height: 1.4,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (_connecting && _statusMessage != null) ...[
                      const SizedBox(height: 16),
                      _buildProgressCard(),
                    ],
                    if (_error != null) ...[
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(14),
                        decoration: BoxDecoration(
                          color: MobileColors.error.withOpacity(0.08),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: MobileColors.error.withOpacity(0.3),
                            width: 1,
                          ),
                        ),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Icon(Icons.error_outline,
                                color: MobileColors.error, size: 18),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                _error!,
                                style: const TextStyle(
                                  color: MobileColors.error,
                                  fontSize: 12,
                                  height: 1.4,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                    if (!_connecting && _step == 4) ...[
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(14),
                        decoration: BoxDecoration(
                          color: MobileColors.success.withOpacity(0.08),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: MobileColors.success.withOpacity(0.3),
                            width: 1,
                          ),
                        ),
                        child: const Row(
                          children: [
                            Icon(Icons.check_circle_outline,
                                color: MobileColors.success, size: 18),
                            SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                'OOBI resolved. Identity verified.',
                                style: TextStyle(
                                  color: MobileColors.success,
                                  fontSize: 13,
                                  fontWeight: FontWeight.w500,
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
                          backgroundColor: MobileColors.primary,
                          foregroundColor: MobileColors.textOnPrimary,
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                          disabledBackgroundColor:
                              MobileColors.primary.withOpacity(0.3),
                        ),
                        child: _connecting
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: MobileColors.textOnPrimary,
                                ),
                              )
                            : const Text(
                                'Connect',
                                style: TextStyle(
                                  fontSize: 15,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextButton(
                      onPressed: widget.onBack,
                      child: const Text(
                        'Go Back',
                        style: TextStyle(
                          color: MobileColors.textMuted,
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildProgressCard() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: MobileColors.border, width: 1),
        boxShadow: [
          BoxShadow(
            color: MobileColors.cardShadow,
            blurRadius: 6,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildStepRow(1, 'Verify server health', _step >= 1),
          const SizedBox(height: 8),
          _buildStepRow(2, 'Fetch OOBI URL', _step >= 2),
          const SizedBox(height: 8),
          _buildStepRow(3, 'Resolve OOBI identity', _step >= 3),
          const SizedBox(height: 8),
          _buildStepRow(4, 'Establish relationship', _step >= 4),
        ],
      ),
    );
  }

  Widget _buildStepRow(int stepNum, String label, bool reached) {
    final isCurrentStep = _step == stepNum && _connecting;
    final isComplete = _step > stepNum || (_step == stepNum && !_connecting);

    return Row(
      children: [
        SizedBox(
          width: 20,
          height: 20,
          child: isCurrentStep
              ? const CircularProgressIndicator(
                  strokeWidth: 2,
                  color: MobileColors.primary,
                )
              : Icon(
                  isComplete ? Icons.check_circle : Icons.circle_outlined,
                  color: isComplete
                      ? MobileColors.success
                      : MobileColors.textMuted.withOpacity(0.3),
                  size: 18,
                ),
        ),
        const SizedBox(width: 10),
        Text(
          label,
          style: TextStyle(
            color: reached ? MobileColors.textPrimary : MobileColors.textMuted,
            fontSize: 13,
            fontWeight: reached ? FontWeight.w600 : FontWeight.w400,
          ),
        ),
      ],
    );
  }
}
