import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/app_theme.dart';
import '../widgets/connected_services_section.dart';
import '../services/core_service.dart';
import 'package:agent_client/services/keri_service.dart';
import '../services/preferences_service.dart';
import '../main.dart';

class SettingsScreen extends StatefulWidget {
  final KeriService keriService;
  final AgentMode? mode;
  final EntityType? entityType;
  final String? serverUrl;

  const SettingsScreen({
    super.key,
    required this.keriService,
    this.mode,
    this.entityType,
    this.serverUrl,
  });

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    return null;
  }
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
  String _endpointUrl = '';
  String _endpointSource = '';
  

  final TextEditingController _openRouterKeyController = TextEditingController();
  bool _openRouterKeySet = false;
  bool _savingLLMKey = false;
  bool _showOpenRouterKey = false;

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
      Map<String, dynamic>? endpointData;
      try {
        endpointData = await _coreService.getEndpoint();
      } catch (_) {}
      setState(() {
        _selectedProvider = (settings['provider'] ?? 'none').toString();
        _tunnelStatus = settings['status'] as Map<String, dynamic>?;
        _cloudflaredAvailable = settings['cloudflared_available'] == true;
        _hasNgrokToken = settings['has_ngrok_token'] == true;
        _hasCfToken = settings['has_cloudflare_token'] == true;
        if (endpointData != null) {
          _endpointUrl = endpointData['url']?.toString() ?? '';
          _endpointSource = endpointData['source']?.toString() ?? '';
        }
        _loading = false;
      });
      _loadLLMSettings();
    } catch (e) {
      setState(() {
        _loading = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _loadLLMSettings() async {
    try {
      final data = await _coreService.getLLMSettings();
      final serviceStatus = data['service_status'] as Map<String, dynamic>? ?? {};
      if (mounted) {
        setState(() {
          _openRouterKeySet = serviceStatus['openrouter'] == true;
        });
      }
    } catch (_) {}
  }

  Future<void> _saveLLMKey() async {
    final key = _openRouterKeyController.text.trim();
    if (key.isEmpty) return;
    setState(() => _savingLLMKey = true);
    try {
      await _coreService.saveLLMKey('openrouter', key);
      _openRouterKeyController.clear();
      if (mounted) {
        setState(() {
          _openRouterKeySet = true;
          _savingLLMKey = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('OpenRouter key saved', style: TextStyle(fontFamily: 'monospace')),
          backgroundColor: Color(0xFF00ffc8),
          behavior: SnackBarBehavior.floating,
        ));
      }
    } catch (e) {
      if (mounted) {
        setState(() => _savingLLMKey = false);
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Failed: $e', style: const TextStyle(fontFamily: 'monospace')),
          backgroundColor: AppColors.error,
          behavior: SnackBarBehavior.floating,
        ));
      }
    }
  }

  Future<void> _deleteLLMKey(String service) async {
    try {
      await _coreService.deleteLLMKey(service);
      if (mounted) {
        setState(() => _openRouterKeySet = false);
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Key removed', style: TextStyle(fontFamily: 'monospace')),
          behavior: SnackBarBehavior.floating,
        ));
      }
    } catch (_) {}
  }

  Future<void> _saveSettings() async {
    setState(() {
      _saving = true;
      _error = null;
    });

    try {
      final result = await _coreService.saveTunnelSettings(
        provider: _selectedProvider,
        ngrokAuthToken: _ngrokTokenController.text.isNotEmpty ? _ngrokTokenController.text : null,
        cloudflareTunnelToken: _cfTokenController.text.isNotEmpty ? _cfTokenController.text : null,
      );

      await _loadSettings();

      if (mounted) {
        final tunnel = result['tunnel'];
        final tunnelActive = tunnel is Map && tunnel['active'] == true;
        final endpointUrl = result['endpoint_url']?.toString() ?? '';
        final tunnelError = tunnel is Map ? (tunnel['error'] ?? '') : '';

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              tunnelActive
                  ? 'Saved — tunnel active: $endpointUrl'
                  : tunnelError.toString().isNotEmpty
                      ? 'Saved — tunnel error: $tunnelError'
                      : _selectedProvider == 'none'
                          ? 'Settings saved — no tunnel configured'
                          : 'Settings saved — tunnel not connected',
              style: const TextStyle(fontFamily: 'monospace'),
            ),
            backgroundColor: tunnelActive
                ? AppColors.accent.withOpacity(0.9)
                : AppColors.warning.withOpacity(0.9),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
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
    _openRouterKeyController.dispose();
    _coreService.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: _loading
          ? const Center(child: CircularProgressIndicator(color: AppColors.accent))
          : SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 720),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (!AppLayout.isMobile(context)) ...[
                    Builder(builder: (context) => Text('Settings', style: Theme.of(context).textTheme.headlineMedium)),
                    const SizedBox(height: 4),
                    const Text(
                      'Configure connectivity and preferences.',
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 14),
                    ),
                    const SizedBox(height: 24),
                  ],
                  _buildAgentInfoCard(),
                  const SizedBox(height: 24),
                  const Text(
                    'Tunnel & Connectivity',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
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
                  const Text(
                    'AI Keys',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
                  _buildLLMKeysSection(),
                  const SizedBox(height: 24),
                  const Text(
                    'Connected Services',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 12),
                  ConnectedServicesSection(baseUrl: _coreService.baseUrl),
                  const SizedBox(height: 24),
                  _buildInfoSection(),
                  const SizedBox(height: 24),
                  _buildResetSection(),
                ],
              ),
              ),
            ),
    );
  }

  Widget _buildAgentInfoCard() {
    final modeName = widget.mode != null
        ? PreferencesService.modeDisplayName(widget.mode!)
        : 'Unknown';
    final entityName = widget.entityType != null
        ? PreferencesService.entityTypeDisplayName(widget.entityType!)
        : null;
    final envName = widget.keriService.environment.name.toUpperCase();

    return Container(
      width: double.infinity,
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
            'AGENT CONFIGURATION',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 14),
          _buildInfoRow('MODE', modeName),
          if (entityName != null) ...[
            const SizedBox(height: 8),
            _buildInfoRow('IDENTITY TYPE', entityName),
          ],
          const SizedBox(height: 8),
          _buildInfoRow('ENGINE', envName),
          if (widget.serverUrl != null && widget.serverUrl!.isNotEmpty) ...[
            const SizedBox(height: 8),
            _buildInfoRow('SERVER', widget.serverUrl!),
          ],
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 110,
          child: Text(
            label,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.0,
              fontFamily: 'monospace',
            ),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
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
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: AppColors.border),
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
          if (_endpointUrl.isNotEmpty) ...[
            const SizedBox(height: 12),
            const Text(
              'ACTIVE ENDPOINT',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 9,
                fontWeight: FontWeight.w600,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 4),
            GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: _endpointUrl));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Endpoint URL copied', style: TextStyle(fontFamily: 'monospace')),
                    duration: Duration(seconds: 1),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: AppColors.border),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        _endpointUrl,
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
            if (_endpointSource.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(
                'source: $_endpointSource',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 9,
                  fontFamily: 'monospace',
                ),
              ),
            ],
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
            badgeIsError: !_cloudflaredAvailable,
          ),
          const SizedBox(height: 8),
          _buildProviderOption(
            'ngrok',
            'NGROK',
            'In-memory tunnel. Works on desktop & mobile. Requires auth token.',
            Icons.swap_vert,
            enabled: true,
            badge: _hasNgrokToken ? 'AVAILABLE' : 'NO TOKEN',
            badgeIsError: !_hasNgrokToken,
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

  Widget _buildProviderOption(String value, String label, String description, IconData icon, {bool enabled = true, String? badge, bool badgeIsError = false}) {
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
                            color: (!enabled || badgeIsError) ? AppColors.warning.withOpacity(0.15) : AppColors.accent.withOpacity(0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            badge,
                            style: TextStyle(
                              color: (!enabled || badgeIsError) ? AppColors.warning : AppColors.accent,
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
                    'RECONNECT',
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

  bool _resetting = false;

  Widget _buildResetSection() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.error.withOpacity(0.05),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.error.withOpacity(0.3), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'DEVELOPER TOOLS',
            style: TextStyle(
              color: AppColors.error,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Reset all data and return to the beginning of the setup process. This will delete your identity, contacts, settings, and all stored events.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              height: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _resetting ? null : _handleReset,
              icon: _resetting
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white,
                      ),
                    )
                  : const Icon(Icons.restart_alt, size: 16),
              label: Text(
                _resetting ? 'RESETTING...' : 'RESET IDENTITY',
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.0,
                  fontFamily: 'monospace',
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.error,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _handleReset() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text(
          'Reset Identity?',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontFamily: 'monospace',
          ),
        ),
        content: const Text(
          'This will permanently delete your identity, contacts, key event log, and all settings. You will need to go through the setup process again.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontFamily: 'monospace',
            fontSize: 12,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text(
              'CANCEL',
              style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace'),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text(
              'RESET',
              style: TextStyle(color: AppColors.error, fontFamily: 'monospace'),
            ),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    setState(() => _resetting = true);
    try {
      await _coreService.resetAll();
      await PreferencesService.clearAll();
      if (mounted) {
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (_) => const IdentityAgentApp()),
          (route) => false,
        );
      }
    } catch (e) {
      setState(() {
        _resetting = false;
        _error = 'Reset failed: $e';
      });
    }
  }

  Widget _buildLLMKeysSection() {
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
          Row(
            children: [
              const Text(
                'OPENROUTER',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(width: 10),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: _openRouterKeySet
                      ? AppColors.accent.withOpacity(0.15)
                      : AppColors.textMuted.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(
                    color: _openRouterKeySet
                        ? AppColors.accent.withOpacity(0.4)
                        : AppColors.border,
                    width: 1,
                  ),
                ),
                child: Text(
                  _openRouterKeySet ? 'KEY SET' : 'NO KEY',
                  style: TextStyle(
                    color: _openRouterKeySet ? AppColors.accent : AppColors.textMuted,
                    fontSize: 9,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.2,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
              if (_openRouterKeySet) ...[
                const Spacer(),
                GestureDetector(
                  onTap: () => _deleteLLMKey('openrouter'),
                  child: const Icon(Icons.delete_outline, size: 16, color: AppColors.textMuted),
                ),
              ],
            ],
          ),
          const SizedBox(height: 6),
          const Text(
            'API key is stored in the Identity Agent and injected into sandbox apps. Never sent to containers.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontFamily: 'monospace',
              height: 1.4,
            ),
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _openRouterKeyController,
                  obscureText: !_showOpenRouterKey,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                  decoration: InputDecoration(
                    hintText: _openRouterKeySet ? 'Enter new key to replace...' : 'sk-or-v1-...',
                    hintStyle: TextStyle(
                      color: AppColors.textMuted.withOpacity(0.5),
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                    filled: true,
                    fillColor: AppColors.primary,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: BorderSide(color: AppColors.border),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: BorderSide(color: AppColors.border),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: BorderSide(color: AppColors.accent, width: 1.5),
                    ),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    suffixIcon: IconButton(
                      icon: Icon(
                        _showOpenRouterKey ? Icons.visibility_off : Icons.visibility,
                        size: 16,
                        color: AppColors.textMuted,
                      ),
                      onPressed: () => setState(() => _showOpenRouterKey = !_showOpenRouterKey),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              SizedBox(
                height: 44,
                child: ElevatedButton(
                  onPressed: _savingLLMKey ? null : _saveLLMKey,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.accent,
                    foregroundColor: AppColors.primary,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                  ),
                  child: _savingLLMKey
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                        )
                      : const Text(
                          'SAVE',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1.2,
                            fontFamily: 'monospace',
                          ),
                        ),
                ),
              ),
            ],
          ),
        ],
      ),
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
            'A development tunnel gives this Identity Agent a public HTTPS URL from a tunnel vendor, so its OOBI endpoints are reachable from anywhere. It is not private, and is for development. A stable public or private address comes from a relay, which this app does not configure yet.\n\n'
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
