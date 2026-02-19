import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/app_theme.dart';
import '../services/core_service.dart';
import '../services/keri_service.dart';

class SettingsScreen extends StatefulWidget {
  final KeriService keriService;

  const SettingsScreen({super.key, required this.keriService});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final CoreService _coreService = CoreService();
  final TextEditingController _ngrokTokenController = TextEditingController();
  final TextEditingController _cfTokenController = TextEditingController();

  String _selectedProvider = 'none';
  bool _loading = true;
  bool _saving = false;
  bool _restarting = false;
  String? _error;
  Map<String, dynamic>? _tunnelStatus;
  bool _cloudflaredAvailable = false;
  bool _hasNgrokToken = false;
  bool _hasCfToken = false;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final settings = await _coreService.getTunnelSettings();
      setState(() {
        _selectedProvider = (settings['provider'] ?? 'none').toString();
        _tunnelStatus = settings['status'] as Map<String, dynamic>?;
        _cloudflaredAvailable = settings['cloudflared_available'] == true;
        _hasNgrokToken = settings['has_ngrok_token'] == true;
        _hasCfToken = settings['has_cloudflare_token'] == true;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _loading = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _saveSettings() async {
    setState(() {
      _saving = true;
      _error = null;
    });

    try {
      await _coreService.saveTunnelSettings(
        provider: _selectedProvider,
        ngrokAuthToken: _ngrokTokenController.text.isNotEmpty ? _ngrokTokenController.text : null,
        cloudflareTunnelToken: _cfTokenController.text.isNotEmpty ? _cfTokenController.text : null,
      );

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('Settings saved', style: TextStyle(fontFamily: 'monospace')),
          backgroundColor: AppColors.accent.withOpacity(0.9),
          behavior: SnackBarBehavior.floating,
        ),
      );

      await _loadSettings();
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _saving = false);
    }
  }

  Future<void> _restartTunnel() async {
    setState(() {
      _restarting = true;
      _error = null;
    });

    try {
      final result = await _coreService.restartTunnel();
      setState(() {
        _tunnelStatus = result;
        _restarting = false;
      });
      await _loadSettings();

      if (mounted) {
        final active = result['active'] == true;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              active ? 'Tunnel active: ${result['url'] ?? ''}' : 'Tunnel stopped',
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            backgroundColor: active ? AppColors.accent.withOpacity(0.9) : AppColors.warning.withOpacity(0.9),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } catch (e) {
      setState(() {
        _restarting = false;
        _error = e.toString();
      });
    }
  }

  @override
  void dispose() {
    _ngrokTokenController.dispose();
    _cfTokenController.dispose();
    _coreService.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: _loading
          ? const Center(child: CircularProgressIndicator(color: AppColors.accent))
          : SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const SizedBox(height: 8),
                  const Text(
                    'SETTINGS',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 22,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 2,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'TUNNEL & CONNECTIVITY',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      letterSpacing: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 24),
                  _buildTunnelStatusCard(),
                  const SizedBox(height: 16),
                  _buildProviderSelector(),
                  const SizedBox(height: 16),
                  if (_selectedProvider == 'ngrok') _buildNgrokConfig(),
                  if (_selectedProvider == 'cloudflare') _buildCloudflareConfig(),
                  const SizedBox(height: 16),
                  if (_error != null) _buildErrorCard(),
                  if (_error != null) const SizedBox(height: 16),
                  _buildActionButtons(),
                  const SizedBox(height: 24),
                  _buildInfoSection(),
                ],
              ),
            ),
    );
  }

  Widget _buildTunnelStatusCard() {
    final active = _tunnelStatus?['active'] == true;
    final url = _tunnelStatus?['url']?.toString() ?? '';
    final mode = _tunnelStatus?['mode']?.toString() ?? '';
    final provider = _tunnelStatus?['provider']?.toString() ?? _selectedProvider;
    final error = _tunnelStatus?['error']?.toString() ?? '';

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: active ? AppColors.accent.withOpacity(0.4) : AppColors.border,
          width: 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: active ? AppColors.coreActive : (error.isNotEmpty ? AppColors.error : AppColors.textMuted),
                  boxShadow: active
                      ? [BoxShadow(color: AppColors.coreActive.withOpacity(0.5), blurRadius: 6)]
                      : null,
                ),
              ),
              const SizedBox(width: 10),
              Text(
                active ? 'TUNNEL ACTIVE' : 'TUNNEL INACTIVE',
                style: TextStyle(
                  color: active ? AppColors.accent : AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const Spacer(),
              Text(
                provider.toUpperCase(),
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  letterSpacing: 1.2,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
          if (url.isNotEmpty) ...[
            const SizedBox(height: 12),
            GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: url));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('URL copied', style: TextStyle(fontFamily: 'monospace')),
                    duration: Duration(seconds: 1),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: AppColors.primary,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        url,
                        style: const TextStyle(
                          color: AppColors.accent,
                          fontSize: 11,
                          fontFamily: 'monospace',
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    const SizedBox(width: 8),
                    const Icon(Icons.copy, size: 14, color: AppColors.textMuted),
                  ],
                ),
              ),
            ),
          ],
          if (mode.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              'Mode: $mode',
              style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 10,
                fontFamily: 'monospace',
              ),
            ),
          ],
          if (error.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              error,
              style: const TextStyle(
                color: AppColors.error,
                fontSize: 10,
                fontFamily: 'monospace',
              ),
              maxLines: 3,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildProviderSelector() {
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
            'TUNNEL PROVIDER',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 12),
          _buildProviderOption(
            'cloudflare',
            'CLOUDFLARE',
            'Free quick tunnels or authenticated. Desktop only (requires cloudflared binary).',
            Icons.cloud_outlined,
            enabled: _cloudflaredAvailable,
            badge: _cloudflaredAvailable ? 'AVAILABLE' : 'NOT FOUND',
          ),
          const SizedBox(height: 8),
          _buildProviderOption(
            'ngrok',
            'NGROK',
            'In-memory tunnel. Works on desktop & mobile. Requires auth token.',
            Icons.swap_vert,
            enabled: true,
            badge: _hasNgrokToken ? 'TOKEN SET' : null,
          ),
          const SizedBox(height: 8),
          _buildProviderOption(
            'none',
            'NONE',
            'No tunnel. OOBI URLs use request-derived host or PUBLIC_URL env var.',
            Icons.block,
            enabled: true,
          ),
        ],
      ),
    );
  }

  Widget _buildProviderOption(String value, String label, String description, IconData icon, {bool enabled = true, String? badge}) {
    final selected = _selectedProvider == value;

    return GestureDetector(
      onTap: enabled ? () => setState(() => _selectedProvider = value) : null,
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: selected ? AppColors.accent.withOpacity(0.08) : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: selected ? AppColors.accent.withOpacity(0.5) : AppColors.border.withOpacity(0.5),
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(
              icon,
              size: 20,
              color: enabled ? (selected ? AppColors.accent : AppColors.textSecondary) : AppColors.textMuted.withOpacity(0.5),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        label,
                        style: TextStyle(
                          color: enabled ? (selected ? AppColors.accent : AppColors.textPrimary) : AppColors.textMuted,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          letterSpacing: 1.2,
                          fontFamily: 'monospace',
                        ),
                      ),
                      if (badge != null) ...[
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: enabled ? AppColors.accent.withOpacity(0.15) : AppColors.error.withOpacity(0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            badge,
                            style: TextStyle(
                              color: enabled ? AppColors.accent : AppColors.error,
                              fontSize: 8,
                              fontWeight: FontWeight.w600,
                              letterSpacing: 0.5,
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    description,
                    style: TextStyle(
                      color: enabled ? AppColors.textMuted : AppColors.textMuted.withOpacity(0.5),
                      fontSize: 10,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            Radio<String>(
              value: value,
              groupValue: _selectedProvider,
              onChanged: enabled ? (v) => setState(() => _selectedProvider = v!) : null,
              activeColor: AppColors.accent,
              fillColor: WidgetStateProperty.resolveWith((states) {
                if (!enabled) return AppColors.textMuted.withOpacity(0.3);
                if (states.contains(WidgetState.selected)) return AppColors.accent;
                return AppColors.textMuted;
              }),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildNgrokConfig() {
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
            'NGROK AUTH TOKEN',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 4),
          Text(
            _hasNgrokToken ? 'A token is already configured. Enter a new one to replace it.' : 'Get your token at dashboard.ngrok.com',
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _ngrokTokenController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 12, fontFamily: 'monospace'),
            decoration: InputDecoration(
              hintText: _hasNgrokToken ? '(token configured)' : 'Paste ngrok auth token...',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
              filled: true,
              fillColor: AppColors.primary,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.border),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.border),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.accent),
              ),
              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            ),
            obscureText: true,
          ),
        ],
      ),
    );
  }

  Widget _buildCloudflareConfig() {
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
            'CLOUDFLARE TUNNEL TOKEN',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'Optional. Leave empty for free Quick Tunnel (no account needed).',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _cfTokenController,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 12, fontFamily: 'monospace'),
            decoration: InputDecoration(
              hintText: _hasCfToken ? '(token configured)' : 'Paste tunnel token (optional)...',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 12),
              filled: true,
              fillColor: AppColors.primary,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.border),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.border),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: AppColors.accent),
              ),
              contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            ),
            obscureText: true,
          ),
          if (!_cloudflaredAvailable) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppColors.warning.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.warning.withOpacity(0.3)),
              ),
              child: const Row(
                children: [
                  Icon(Icons.warning_amber, size: 16, color: AppColors.warning),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'cloudflared binary not found. Install it or use ngrok instead.',
                      style: TextStyle(
                        color: AppColors.warning,
                        fontSize: 10,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildErrorCard() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.error.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.error.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline, size: 16, color: AppColors.error),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              _error ?? '',
              style: const TextStyle(
                color: AppColors.error,
                fontSize: 10,
                fontFamily: 'monospace',
              ),
              maxLines: 4,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButtons() {
    return Row(
      children: [
        Expanded(
          child: ElevatedButton(
            onPressed: _saving ? null : _saveSettings,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              disabledBackgroundColor: AppColors.accent.withOpacity(0.3),
            ),
            child: _saving
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary))
                : const Text(
                    'SAVE',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: OutlinedButton(
            onPressed: _restarting ? null : _restartTunnel,
            style: OutlinedButton.styleFrom(
              foregroundColor: AppColors.accent,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              side: BorderSide(color: _restarting ? AppColors.border : AppColors.accent.withOpacity(0.5)),
            ),
            child: _restarting
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.accent))
                : const Text(
                    'RESTART TUNNEL',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 1.0,
                      fontFamily: 'monospace',
                    ),
                  ),
          ),
        ),
      ],
    );
  }

  Widget _buildInfoSection() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface.withOpacity(0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border.withOpacity(0.5), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: const [
          Text(
            'ABOUT TUNNELING',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          SizedBox(height: 8),
          Text(
            'Tunnels create a public HTTPS URL so your OOBI endpoints are reachable from anywhere. This lets other agents discover and verify your identity.\n\n'
            'Cloudflare: Free quick tunnels or authenticated tunnels via cloudflared binary (desktop only).\n\n'
            'ngrok: Pure in-memory tunnel via Go library. Works on desktop and mobile. Requires a free ngrok account.\n\n'
            'None: No tunnel. OOBI URLs use the PUBLIC_URL env var or the request host header.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              height: 1.5,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }
}
