import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../theme/app_theme.dart';

/// Connected Services — the credential intake for governed capabilities.
///
/// Stores one provider credential per service in the agent's encrypted vault
/// (POST /api/vault/credentials) with the egress match domains that let the
/// governance gateway inject it at egress. Capabilities never see the key;
/// neither does this screen after saving — the list endpoint returns service
/// names only.
class ConnectedServicesSection extends StatefulWidget {
  final String baseUrl;

  const ConnectedServicesSection({super.key, required this.baseUrl});

  @override
  State<ConnectedServicesSection> createState() =>
      _ConnectedServicesSectionState();
}

/// Known providers prefill the service name and egress match domains so users
/// never have to think about them. "Custom" exposes both fields.
class _ServicePreset {
  final String label;
  final String service;
  final String domains;
  const _ServicePreset(this.label, this.service, this.domains);
}

const _presets = [
  _ServicePreset('Cloudflare', 'cloudflare', 'api.cloudflare.com'),
  _ServicePreset('OpenRouter', 'openrouter', 'openrouter.ai, *.openrouter.ai'),
  _ServicePreset('Custom…', '', ''),
];

class _ConnectedServicesSectionState extends State<ConnectedServicesSection> {
  final _client = http.Client();
  final _serviceController = TextEditingController();
  final _keyController = TextEditingController();
  final _domainsController = TextEditingController();

  _ServicePreset _preset = _presets.first;
  List<String> _services = [];
  bool _loading = true;
  bool _saving = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _applyPreset(_presets.first);
    _refresh();
  }

  @override
  void dispose() {
    _client.close();
    _serviceController.dispose();
    _keyController.dispose();
    _domainsController.dispose();
    super.dispose();
  }

  void _applyPreset(_ServicePreset p) {
    _preset = p;
    _serviceController.text = p.service;
    _domainsController.text = p.domains;
  }

  Future<void> _refresh() async {
    try {
      final resp = await _client
          .get(Uri.parse('${widget.baseUrl}/api/vault/credentials'))
          .timeout(const Duration(seconds: 8));
      if (resp.statusCode == 200) {
        final body = jsonDecode(resp.body) as Map<String, dynamic>;
        final services =
            (body['services'] as List<dynamic>? ?? []).cast<String>();
        if (mounted) {
          setState(() {
            _services = services;
            _loading = false;
            _error = null;
          });
        }
        return;
      }
      throw Exception('HTTP ${resp.statusCode}');
    } catch (e) {
      if (mounted) {
        setState(() {
          _loading = false;
          _error = 'Could not load connected services: $e';
        });
      }
    }
  }

  Future<void> _save() async {
    final service = _serviceController.text.trim().toLowerCase();
    final key = _keyController.text.trim();
    final domains = _domainsController.text
        .split(RegExp(r'[,\s]+'))
        .where((d) => d.isNotEmpty)
        .toList();
    if (service.isEmpty || key.isEmpty || domains.isEmpty) {
      setState(() =>
          _error = 'Service, API key, and at least one match domain are required.');
      return;
    }
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      final resp = await _client
          .post(
            Uri.parse('${widget.baseUrl}/api/vault/credentials'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({
              'service': service,
              'api_key': key,
              'match_domains': domains,
            }),
          )
          .timeout(const Duration(seconds: 8));
      if (resp.statusCode != 200) {
        String message = 'HTTP ${resp.statusCode}';
        try {
          message = (jsonDecode(resp.body) as Map<String, dynamic>)['error']
                  as String? ??
              message;
        } catch (_) {}
        throw Exception(message);
      }
      _keyController.clear();
      await _refresh();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('$service connected — key stored in the encrypted vault',
              style: const TextStyle(fontFamily: 'monospace')),
          behavior: SnackBarBehavior.floating,
        ));
      }
    } catch (e) {
      if (mounted) setState(() => _error = 'Save failed: $e');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _delete(String service) async {
    try {
      await _client
          .delete(
              Uri.parse('${widget.baseUrl}/api/vault/credentials/$service'))
          .timeout(const Duration(seconds: 8));
      await _refresh();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('$service disconnected',
              style: const TextStyle(fontFamily: 'monospace')),
          behavior: SnackBarBehavior.floating,
        ));
      }
    } catch (e) {
      if (mounted) setState(() => _error = 'Delete failed: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border, width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Provider credentials are stored once per service in the encrypted vault and '
            'injected only at egress by the governance gateway. Capabilities and callers '
            'never see them.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontFamily: 'monospace',
              height: 1.4,
            ),
          ),
          const SizedBox(height: 14),
          if (_loading)
            const Center(
                child: Padding(
              padding: EdgeInsets.all(8),
              child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: AppColors.accent)),
            ))
          else ...[
            for (final s in _services) _serviceRow(s),
            if (_services.isEmpty)
              const Text(
                'NO SERVICES CONNECTED',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontFamily: 'monospace',
                  letterSpacing: 1.2,
                ),
              ),
          ],
          const SizedBox(height: 16),
          const Divider(color: AppColors.border, height: 1),
          const SizedBox(height: 14),
          const Text(
            'CONNECT A SERVICE',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 10),
          DropdownButtonFormField<_ServicePreset>(
            value: _preset,
            dropdownColor: AppColors.surface,
            decoration: _inputDecoration('Provider'),
            style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontFamily: 'monospace'),
            items: [
              for (final p in _presets)
                DropdownMenuItem(value: p, child: Text(p.label)),
            ],
            onChanged: (p) {
              if (p != null) setState(() => _applyPreset(p));
            },
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _serviceController,
            enabled: _preset.service.isEmpty,
            style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontFamily: 'monospace'),
            decoration: _inputDecoration('Service name (e.g. github)'),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _keyController,
            obscureText: true,
            style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontFamily: 'monospace'),
            decoration: _inputDecoration('API key / token'),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _domainsController,
            enabled: _preset.service.isEmpty,
            style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontFamily: 'monospace'),
            decoration: _inputDecoration(
                'Match domains (comma-separated, e.g. api.example.com)'),
          ),
          const SizedBox(height: 12),
          if (_error != null) ...[
            Text(
              _error!,
              style: const TextStyle(
                  color: AppColors.error, fontSize: 11, fontFamily: 'monospace'),
            ),
            const SizedBox(height: 10),
          ],
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: _saving ? null : _save,
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: AppColors.background,
                padding: const EdgeInsets.symmetric(vertical: 12),
              ),
              child: Text(
                _saving ? 'CONNECTING…' : 'CONNECT SERVICE',
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.2,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _serviceRow(String service) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Text(
            service.toUpperCase(),
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.2,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(width: 10),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
            decoration: BoxDecoration(
              color: AppColors.accent.withOpacity(0.15),
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: AppColors.accent.withOpacity(0.4), width: 1),
            ),
            child: const Text(
              'CONNECTED',
              style: TextStyle(
                color: AppColors.accent,
                fontSize: 9,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.2,
                fontFamily: 'monospace',
              ),
            ),
          ),
          const Spacer(),
          GestureDetector(
            onTap: () => _delete(service),
            child: const Icon(Icons.delete_outline,
                size: 16, color: AppColors.textMuted),
          ),
        ],
      ),
    );
  }

  InputDecoration _inputDecoration(String hint) {
    return InputDecoration(
      hintText: hint,
      hintStyle: const TextStyle(
          color: AppColors.textMuted, fontSize: 12, fontFamily: 'monospace'),
      filled: true,
      fillColor: AppColors.background,
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.border, width: 1),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.accent, width: 1),
      ),
      disabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.border, width: 1),
      ),
    );
  }
}
