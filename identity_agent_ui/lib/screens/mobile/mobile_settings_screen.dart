import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../services/preferences_service.dart';
import '../../config/agent_config.dart';
import '../../main.dart';
import 'mobile_auth_management_screen.dart';

class MobileSettingsScreen extends StatefulWidget {
  final String? serverUrl;

  const MobileSettingsScreen({super.key, this.serverUrl});

  @override
  State<MobileSettingsScreen> createState() => _MobileSettingsScreenState();
}

class _MobileSettingsScreenState extends State<MobileSettingsScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  final TextEditingController _ngrokTokenController = TextEditingController();
  final TextEditingController _cfTokenController = TextEditingController();
  final TextEditingController _grapeIdDomainController =
      TextEditingController(text: 'grapeid.org');
  final TextEditingController _grapeIdExtController = TextEditingController();

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

  bool _isCheckingGrapeId = false;
  bool? _isGrapeIdAvailable;
  String? _grapeIdCheckError;
  bool? _grapeIdHubAvailable;
  bool _grapeIdNameLocked = false;
  String _grapeIdLockedName = '';
  bool _isReleasingName = false;
  bool _resetting = false;

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

        if (settings['tunnel_domain'] != null &&
            settings['tunnel_domain'].toString().isNotEmpty) {
          _grapeIdDomainController.text = settings['tunnel_domain'].toString();
        }
        if (settings['tunnel_extension'] != null) {
          _grapeIdExtController.text = settings['tunnel_extension'].toString();
        }
        final ext = (settings['tunnel_extension'] ?? '').toString().trim();
        final provider = (settings['provider'] ?? 'none').toString();
        if (provider == 'grapeid' && ext.isNotEmpty) {
          _grapeIdNameLocked = true;
          _grapeIdLockedName = ext;
        } else {
          _grapeIdNameLocked = false;
          _grapeIdLockedName = '';
        }
        if (endpointData != null) {
          _endpointUrl = endpointData['url']?.toString() ?? '';
          _endpointSource = endpointData['source']?.toString() ?? '';
        }
        _loading = false;
      });
      _checkGrapeIdHub();
    } catch (e) {
      setState(() {
        _loading = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _checkGrapeIdHub() async {
    final domain = _grapeIdDomainController.text.trim().isNotEmpty
        ? _grapeIdDomainController.text.trim()
        : 'grapeid.org';
    final result = await _coreService.checkGrapeIdHealth(domain);
    if (mounted) {
      setState(() {
        _grapeIdHubAvailable = result.reachable;
      });
    }
  }

  Future<void> _saveSettings() async {
    setState(() {
      _saving = true;
      _error = null;
    });

    try {
      final result = await _coreService.saveTunnelSettings(
        provider: _selectedProvider,
        ngrokAuthToken: _ngrokTokenController.text.isNotEmpty
            ? _ngrokTokenController.text
            : null,
        cloudflareTunnelToken:
            _cfTokenController.text.isNotEmpty ? _cfTokenController.text : null,
        tunnelDomain: _grapeIdDomainController.text.trim().isNotEmpty
            ? _grapeIdDomainController.text.trim()
            : null,
        tunnelExtension: _grapeIdExtController.text.trim().isNotEmpty
            ? _grapeIdExtController.text.trim()
            : null,
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
            ),
            backgroundColor:
                tunnelActive ? MobileColors.success : MobileColors.warning,
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
              active
                  ? 'Tunnel active: ${result['url'] ?? ''}'
                  : 'Tunnel stopped',
            ),
            backgroundColor:
                active ? MobileColors.success : MobileColors.warning,
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

  Future<void> _checkGrapeIdAvailability() async {
    final domain = _grapeIdDomainController.text.trim();
    final ext = _grapeIdExtController.text.trim();

    if (ext.isEmpty) {
      setState(() {
        _isGrapeIdAvailable = null;
        _grapeIdCheckError = null;
      });
      return;
    }

    setState(() {
      _isCheckingGrapeId = true;
      _grapeIdCheckError = null;
    });

    try {
      final result = await _coreService.checkGrapeIdName(domain, ext);
      setState(() {
        _isCheckingGrapeId = false;
        _isGrapeIdAvailable = result.available;
        _grapeIdCheckError = result.hubError ? result.message : null;
      });
    } catch (e) {
      setState(() {
        _isCheckingGrapeId = false;
        _isGrapeIdAvailable = null;
        _grapeIdCheckError = 'Provider not responsive';
      });
    }
  }

  Future<void> _releaseTunnelName() async {
    setState(() => _isReleasingName = true);
    try {
      await _coreService.releaseTunnelName();
      setState(() {
        _grapeIdNameLocked = false;
        _grapeIdLockedName = '';
        _grapeIdExtController.clear();
        _isGrapeIdAvailable = null;
        _grapeIdCheckError = null;
      });
      await _loadSettings();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Name released successfully'),
            backgroundColor: MobileColors.success,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to release name: $e'),
            backgroundColor: MobileColors.error,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isReleasingName = false);
    }
  }

  Future<void> _changeTunnelName() async {
    setState(() => _isReleasingName = true);
    try {
      await _coreService.releaseTunnelName();
      setState(() {
        _grapeIdNameLocked = false;
        _grapeIdLockedName = '';
        _grapeIdExtController.clear();
        _isGrapeIdAvailable = null;
        _grapeIdCheckError = null;
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to release current name: $e'),
            backgroundColor: MobileColors.error,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _isReleasingName = false);
    }
  }

  Future<void> _handleReset() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text(
          'Reset Identity?',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontWeight: FontWeight.w700,
          ),
        ),
        content: const Text(
          'This will permanently delete your identity, contacts, key event log, and all settings. You will need to go through the setup process again.',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 14,
            height: 1.5,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text(
              'Cancel',
              style: TextStyle(color: MobileColors.textMuted),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text(
              'Reset',
              style: TextStyle(
                color: MobileColors.error,
                fontWeight: FontWeight.w600,
              ),
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

  void _confirmReleaseName() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text(
          'Release Name?',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontWeight: FontWeight.w700,
          ),
        ),
        content: Text(
          'This will release "$_grapeIdLockedName" on the hub and disconnect the tunnel. The name will become available for others to claim.',
          style: const TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 14,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text(
              'Cancel',
              style: TextStyle(color: MobileColors.textMuted),
            ),
          ),
          TextButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              _releaseTunnelName();
            },
            child: const Text(
              'Release',
              style: TextStyle(
                color: MobileColors.warning,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _ngrokTokenController.dispose();
    _cfTokenController.dispose();
    _grapeIdDomainController.dispose();
    _grapeIdExtController.dispose();
    _coreService.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          backgroundColor: MobileColors.surface,
          elevation: 0,
          leading: IconButton(
            icon:
                const Icon(Icons.arrow_back, color: MobileColors.textPrimary),
            onPressed: () => Navigator.of(context).pop(),
          ),
          title: const Text(
            'Settings',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
          centerTitle: true,
          bottom: PreferredSize(
            preferredSize: const Size.fromHeight(1),
            child: Container(
              color: MobileColors.border,
              height: 1,
            ),
          ),
        ),
        body: _loading
            ? const Center(
                child: CircularProgressIndicator(color: MobileColors.primary))
            : RefreshIndicator(
                onRefresh: _loadSettings,
                color: MobileColors.primary,
                child: SingleChildScrollView(
                  physics: const AlwaysScrollableScrollPhysics(),
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildAuthSection(),
                      const SizedBox(height: 16),
                      _buildTunnelStatusCard(),
                      const SizedBox(height: 16),
                      _buildProviderSelector(),
                      const SizedBox(height: 16),
                      if (_selectedProvider == 'grapeid') _buildGrapeIdConfig(),
                      if (_selectedProvider == 'ngrok') _buildNgrokConfig(),
                      if (_selectedProvider == 'cloudflare')
                        _buildCloudflareConfig(),
                      if (_error != null) ...[
                        const SizedBox(height: 16),
                        _buildErrorCard(),
                      ],
                      const SizedBox(height: 20),
                      _buildActionButtons(),
                      const SizedBox(height: 24),
                      _buildInfoSection(),
                      const SizedBox(height: 24),
                      _buildResetSection(),
                      const SizedBox(height: 32),
                    ],
                  ),
                ),
              ),
      ),
    );
  }

  Widget _buildTunnelStatusCard() {
    final active = _tunnelStatus?['active'] == true;
    final url = _tunnelStatus?['url']?.toString() ?? '';
    final provider =
        _tunnelStatus?['provider']?.toString() ?? _selectedProvider;
    final error = _tunnelStatus?['error']?.toString() ?? '';

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: active
              ? MobileColors.success.withOpacity(0.4)
              : MobileColors.border,
          width: 1,
        ),
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
          Row(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: active
                      ? MobileColors.success
                      : (error.isNotEmpty
                          ? MobileColors.error
                          : MobileColors.textMuted),
                  boxShadow: active
                      ? [
                          BoxShadow(
                              color: MobileColors.success.withOpacity(0.5),
                              blurRadius: 6)
                        ]
                      : null,
                ),
              ),
              const SizedBox(width: 10),
              Text(
                active ? 'Tunnel Active' : 'Tunnel Inactive',
                style: TextStyle(
                  color: active ? MobileColors.success : MobileColors.textSecondary,
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: MobileColors.surfaceTertiary,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  provider.toUpperCase(),
                  style: const TextStyle(
                    color: MobileColors.textMuted,
                    fontSize: 10,
                    fontWeight: FontWeight.w600,
                  ),
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
                    content: Text('URL copied'),
                    duration: Duration(seconds: 1),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                decoration: BoxDecoration(
                  color: MobileColors.surfaceSecondary,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        url,
                        style: const TextStyle(
                          color: MobileColors.primary,
                          fontSize: 13,
                          fontFamily: 'monospace',
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    const SizedBox(width: 8),
                    const Icon(Icons.copy,
                        size: 14, color: MobileColors.textMuted),
                  ],
                ),
              ),
            ),
          ],
          if (error.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              error,
              style: const TextStyle(
                color: MobileColors.error,
                fontSize: 12,
              ),
              maxLines: 3,
              overflow: TextOverflow.ellipsis,
            ),
          ],
          if (_endpointUrl.isNotEmpty) ...[
            const SizedBox(height: 12),
            const Text(
              'Active Endpoint',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 4),
            GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: _endpointUrl));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Endpoint URL copied'),
                    duration: Duration(seconds: 1),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                decoration: BoxDecoration(
                  color: MobileColors.surfaceSecondary,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        _endpointUrl,
                        style: const TextStyle(
                          color: MobileColors.primary,
                          fontSize: 13,
                          fontFamily: 'monospace',
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    const SizedBox(width: 8),
                    const Icon(Icons.copy,
                        size: 14, color: MobileColors.textMuted),
                  ],
                ),
              ),
            ),
            if (_endpointSource.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(
                'Source: $_endpointSource',
                style: const TextStyle(
                  color: MobileColors.textMuted,
                  fontSize: 11,
                ),
              ),
            ],
          ],
        ],
      ),
    );
  }

  Widget _buildProviderSelector() {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Tunnel Provider',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 16,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 12),
          _buildProviderOption(
            'grapeid',
            'Grape ID',
            'Permanent URLs via GrapeID Hub (e.g. grapeid.org/alice)',
            Icons.vpn_key_outlined,
            enabled: true,
            badge: _grapeIdHubAvailable == null
                ? null
                : (_grapeIdHubAvailable! ? 'Available' : 'Unavailable'),
            badgeIsError: _grapeIdHubAvailable == false,
          ),
          const SizedBox(height: 8),
          _buildProviderOption(
            'cloudflare',
            'Cloudflare',
            'Free quick tunnels or authenticated. Desktop only.',
            Icons.cloud_outlined,
            enabled: _cloudflaredAvailable,
            badge: _cloudflaredAvailable ? 'Available' : 'Not Found',
            badgeIsError: !_cloudflaredAvailable,
          ),
          const SizedBox(height: 8),
          _buildProviderOption(
            'ngrok',
            'Ngrok',
            'In-memory tunnel. Works on desktop & mobile.',
            Icons.swap_vert,
            enabled: true,
            badge: _hasNgrokToken ? 'Available' : 'No Token',
            badgeIsError: !_hasNgrokToken,
          ),
          const SizedBox(height: 8),
          _buildProviderOption(
            'none',
            'None',
            'No tunnel. Uses request host or PUBLIC_URL env var.',
            Icons.block,
            enabled: true,
          ),
        ],
      ),
    );
  }

  Widget _buildProviderOption(
    String value,
    String label,
    String description,
    IconData icon, {
    bool enabled = true,
    String? badge,
    bool badgeIsError = false,
  }) {
    final selected = _selectedProvider == value;

    return GestureDetector(
      onTap: enabled ? () => setState(() => _selectedProvider = value) : null,
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: selected
              ? MobileColors.primary.withOpacity(0.06)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: selected
                ? MobileColors.primary.withOpacity(0.4)
                : MobileColors.border,
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(
              icon,
              size: 22,
              color: enabled
                  ? (selected ? MobileColors.primary : MobileColors.textSecondary)
                  : MobileColors.textMuted.withOpacity(0.5),
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
                          color: enabled
                              ? (selected
                                  ? MobileColors.primary
                                  : MobileColors.textPrimary)
                              : MobileColors.textMuted,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (badge != null) ...[
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: (!enabled || badgeIsError)
                                ? MobileColors.warning.withOpacity(0.15)
                                : MobileColors.success.withOpacity(0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            badge,
                            style: TextStyle(
                              color: (!enabled || badgeIsError)
                                  ? MobileColors.warning
                                  : MobileColors.success,
                              fontSize: 10,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    description,
                    style: TextStyle(
                      color: enabled
                          ? MobileColors.textMuted
                          : MobileColors.textMuted.withOpacity(0.5),
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
            Radio<String>(
              value: value,
              groupValue: _selectedProvider,
              onChanged:
                  enabled ? (v) => setState(() => _selectedProvider = v!) : null,
              activeColor: MobileColors.primary,
              fillColor: WidgetStateProperty.resolveWith((states) {
                if (!enabled) return MobileColors.textMuted.withOpacity(0.3);
                if (states.contains(WidgetState.selected)) {
                  return MobileColors.primary;
                }
                return MobileColors.textMuted;
              }),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildGrapeIdConfig() {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Grape ID Configuration',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Domain',
            style: TextStyle(
              color: MobileColors.textSecondary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          TextField(
            controller: _grapeIdDomainController,
            readOnly: _grapeIdNameLocked,
            style: TextStyle(
              color: _grapeIdNameLocked
                  ? MobileColors.textMuted
                  : MobileColors.textPrimary,
              fontSize: 14,
            ),
            decoration: InputDecoration(
              hintText: 'e.g. grapeid.org',
              hintStyle: const TextStyle(
                  color: MobileColors.textMuted, fontSize: 14),
              filled: true,
              fillColor: _grapeIdNameLocked
                  ? MobileColors.surfaceTertiary
                  : MobileColors.surfaceSecondary,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: MobileColors.border),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: MobileColors.border),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide:
                    const BorderSide(color: MobileColors.primary, width: 2),
              ),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            _grapeIdNameLocked ? 'Claimed Name' : 'Extension Name',
            style: const TextStyle(
              color: MobileColors.textSecondary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          if (_grapeIdNameLocked) ...[
            GestureDetector(
              onTap: () {
                final domain =
                    _grapeIdDomainController.text.trim().isNotEmpty
                        ? _grapeIdDomainController.text.trim()
                        : 'grapeid.org';
                final fullUrl = 'https://$domain/$_grapeIdLockedName';
                Clipboard.setData(ClipboardData(text: fullUrl));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('Copied $fullUrl'),
                    duration: const Duration(seconds: 2),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
              child: Container(
                width: double.infinity,
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                decoration: BoxDecoration(
                  color: MobileColors.primary.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                      color: MobileColors.primary.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.link,
                        size: 16, color: MobileColors.primary),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        '${_grapeIdDomainController.text.trim().isNotEmpty ? _grapeIdDomainController.text.trim() : "grapeid.org"}/$_grapeIdLockedName',
                        style: const TextStyle(
                          color: MobileColors.primary,
                          fontSize: 14,
                          fontFamily: 'monospace',
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    const Icon(Icons.copy,
                        size: 14, color: MobileColors.textMuted),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _isReleasingName ? null : _changeTunnelName,
                    icon: _isReleasingName
                        ? const SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: MobileColors.primary))
                        : const Icon(Icons.edit, size: 16),
                    label: const Text('Change',
                        style: TextStyle(fontSize: 13)),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: MobileColors.primary,
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8)),
                      side: const BorderSide(color: MobileColors.border),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed:
                        _isReleasingName ? null : () => _confirmReleaseName(),
                    icon: _isReleasingName
                        ? const SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: MobileColors.warning))
                        : const Icon(Icons.link_off, size: 16),
                    label: const Text('Release',
                        style: TextStyle(fontSize: 13)),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: MobileColors.warning,
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8)),
                      side: BorderSide(
                          color: MobileColors.warning.withOpacity(0.5)),
                    ),
                  ),
                ),
              ],
            ),
          ] else ...[
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _grapeIdExtController,
                    style: const TextStyle(
                        color: MobileColors.textPrimary, fontSize: 14),
                    decoration: InputDecoration(
                      prefixText: '/',
                      prefixStyle: const TextStyle(
                          color: MobileColors.textMuted, fontSize: 14),
                      hintText: 'your-name',
                      hintStyle: const TextStyle(
                          color: MobileColors.textMuted, fontSize: 14),
                      filled: true,
                      fillColor: MobileColors.surfaceSecondary,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide:
                            const BorderSide(color: MobileColors.border),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide:
                            const BorderSide(color: MobileColors.border),
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(
                            color: MobileColors.primary, width: 2),
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 12),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                OutlinedButton(
                  onPressed:
                      _isCheckingGrapeId ? null : _checkGrapeIdAvailability,
                  style: OutlinedButton.styleFrom(
                    foregroundColor: MobileColors.primary,
                    padding: const EdgeInsets.symmetric(
                        horizontal: 16, vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8)),
                    side: const BorderSide(color: MobileColors.border),
                  ),
                  child: _isCheckingGrapeId
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: MobileColors.primary))
                      : const Text('Check',
                          style: TextStyle(
                              fontSize: 13, fontWeight: FontWeight.w600)),
                ),
              ],
            ),
            if (_isGrapeIdAvailable != null ||
                _grapeIdCheckError != null) ...[
              const SizedBox(height: 10),
              Row(
                children: [
                  if (_grapeIdCheckError != null) ...[
                    const Icon(Icons.warning_amber_outlined,
                        size: 16, color: MobileColors.warning),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(
                        'Hub not responsive. You can still save and try connecting.',
                        style: const TextStyle(
                            color: MobileColors.warning, fontSize: 12),
                      ),
                    ),
                  ] else if (_isGrapeIdAvailable == true) ...[
                    const Icon(Icons.check_circle_outline,
                        size: 16, color: MobileColors.success),
                    const SizedBox(width: 6),
                    const Text(
                      'This name is available!',
                      style: TextStyle(
                          color: MobileColors.success, fontSize: 13),
                    ),
                  ] else if (_isGrapeIdAvailable == false) ...[
                    const Icon(Icons.cancel_outlined,
                        size: 16, color: MobileColors.error),
                    const SizedBox(width: 6),
                    const Text(
                      'This name is already taken.',
                      style: TextStyle(
                          color: MobileColors.error, fontSize: 13),
                    ),
                  ],
                ],
              ),
            ],
          ],
        ],
      ),
    );
  }

  Widget _buildNgrokConfig() {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Ngrok Auth Token',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            _hasNgrokToken
                ? 'A token is configured. Enter a new one to replace it.'
                : 'Get your token at dashboard.ngrok.com',
            style: const TextStyle(
              color: MobileColors.textMuted,
              fontSize: 13,
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _ngrokTokenController,
            style: const TextStyle(
                color: MobileColors.textPrimary, fontSize: 14),
            decoration: InputDecoration(
              hintText:
                  _hasNgrokToken ? '(token configured)' : 'Paste auth token...',
              hintStyle:
                  const TextStyle(color: MobileColors.textMuted, fontSize: 14),
              filled: true,
              fillColor: MobileColors.surfaceSecondary,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: MobileColors.border),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: MobileColors.border),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide:
                    const BorderSide(color: MobileColors.primary, width: 2),
              ),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            ),
            obscureText: true,
          ),
        ],
      ),
    );
  }

  Widget _buildCloudflareConfig() {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Cloudflare Tunnel Token',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'Optional. Leave empty for free Quick Tunnel.',
            style: TextStyle(
              color: MobileColors.textMuted,
              fontSize: 13,
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _cfTokenController,
            style: const TextStyle(
                color: MobileColors.textPrimary, fontSize: 14),
            decoration: InputDecoration(
              hintText: _hasCfToken
                  ? '(token configured)'
                  : 'Paste tunnel token (optional)...',
              hintStyle:
                  const TextStyle(color: MobileColors.textMuted, fontSize: 14),
              filled: true,
              fillColor: MobileColors.surfaceSecondary,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: MobileColors.border),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: MobileColors.border),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide:
                    const BorderSide(color: MobileColors.primary, width: 2),
              ),
              contentPadding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            ),
            obscureText: true,
          ),
          if (!_cloudflaredAvailable) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: MobileColors.warning.withOpacity(0.08),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                    color: MobileColors.warning.withOpacity(0.3)),
              ),
              child: const Row(
                children: [
                  Icon(Icons.warning_amber,
                      size: 16, color: MobileColors.warning),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'cloudflared binary not found. Install it or use another provider.',
                      style: TextStyle(
                        color: MobileColors.warning,
                        fontSize: 12,
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
        color: MobileColors.error.withOpacity(0.08),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: MobileColors.error.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline,
              size: 16, color: MobileColors.error),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              _error ?? '',
              style: const TextStyle(
                color: MobileColors.error,
                fontSize: 12,
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
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10)),
              disabledBackgroundColor:
                  MobileColors.primary.withOpacity(0.3),
            ),
            child: _saving
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: MobileColors.textOnPrimary))
                : const Text(
                    'Save',
                    style: TextStyle(
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: OutlinedButton(
            onPressed: _restarting ? null : _restartTunnel,
            style: OutlinedButton.styleFrom(
              foregroundColor: MobileColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10)),
              side: BorderSide(
                  color: _restarting
                      ? MobileColors.border
                      : MobileColors.primary.withOpacity(0.5)),
            ),
            child: _restarting
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: MobileColors.primary))
                : const Text(
                    'Reconnect',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
          ),
        ),
      ],
    );
  }

  Widget _buildAuthSection() {
    return GestureDetector(
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute(
            builder: (_) => const MobileAuthManagementScreen()),
      ),
      child: _buildCard(
        child: Row(
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: MobileColors.primary.withOpacity(0.1),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.lock_outlined,
                  color: MobileColors.primary, size: 20),
            ),
            const SizedBox(width: 14),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Authentication & Security',
                    style: TextStyle(
                      color: MobileColors.textPrimary,
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  SizedBox(height: 2),
                  Text(
                    'PIN, password, biometrics, and Identity Level',
                    style: TextStyle(
                        color: MobileColors.textMuted, fontSize: 12),
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right,
                color: MobileColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoSection() {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: const [
          Text(
            'About Tunneling',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
          SizedBox(height: 8),
          Text(
            'Tunnels create a public HTTPS URL so your OOBI endpoints are reachable from anywhere. '
            'This lets other agents discover and verify your identity.\n\n'
            'Grape ID: Permanent URL via a dedicated tunneling hub (e.g. grapeid.org/alice).\n\n'
            'Cloudflare: Free quick tunnels via cloudflared binary (desktop only).\n\n'
            'Ngrok: In-memory tunnel via Go library. Works on desktop and mobile.\n\n'
            'None: No tunnel. Uses PUBLIC_URL env var or request host header.',
            style: TextStyle(
              color: MobileColors.textMuted,
              fontSize: 13,
              height: 1.5,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildResetSection() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.error.withOpacity(0.04),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
            color: MobileColors.error.withOpacity(0.2), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Developer Tools',
            style: TextStyle(
              color: MobileColors.error,
              fontSize: 15,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Reset all data and return to setup. This will delete your identity, contacts, settings, and all stored events.',
            style: TextStyle(
              color: MobileColors.textSecondary,
              fontSize: 13,
              height: 1.5,
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
                          strokeWidth: 2, color: Colors.white))
                  : const Icon(Icons.restart_alt, size: 18),
              label: Text(
                _resetting ? 'Resetting...' : 'Reset Identity',
                style: const TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: MobileColors.error,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10)),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCard({required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border, width: 1),
        boxShadow: [
          BoxShadow(
            color: MobileColors.cardShadow,
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: child,
    );
  }
}
