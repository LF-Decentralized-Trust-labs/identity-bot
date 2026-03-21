import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../theme/app_theme.dart';
import '../../config/agent_config.dart';
import '../../services/core_service.dart';
import '../../services/keri_service.dart';
import '../../services/mobile_on_device_keri_service.dart';
import '../../widgets/identity_level_badge.dart';
import '../../widgets/key_storage_badge.dart';
import '../../widgets/log_entry.dart';
import '../auth_setup_screen.dart';

/// Desktop dashboard — 3-section layout designed for full-width desktop.
///
/// Sections: Identity (left) | Notifications (center) | Engagement (right)
class DesktopDashboardScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const DesktopDashboardScreen({super.key, required this.keriService, this.serverUrl});

  @override
  State<DesktopDashboardScreen> createState() => _DesktopDashboardScreenState();
}

class _DesktopDashboardScreenState extends State<DesktopDashboardScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    if (widget.keriService is MobileOnDeviceKeriService) {
      final s = widget.keriService as MobileOnDeviceKeriService;
      if (s.isCoreReady) return s.mobileCore.baseUrl;
    }
    return null;
  }

  // Identity
  IdentityResponse? _identity;
  ProfileResponse? _profile;
  OobiResponse? _oobi;

  // Notifications
  List<ContactResponse> _alerts = [];
  List<PendingRequestResponse> _pendingRequests = [];

  // Activity
  final List<LogEntry> _logs = [];

  // Status
  HealthResponse? _health;
  CoreConnectionState _connectionState = CoreConnectionState.disconnected;

  Timer? _healthTimer;
  Timer? _alertTimer;

  @override
  void initState() {
    super.initState();
    _addLog('Dashboard initialized', LogLevel.info);
    _load();
  }

  @override
  void dispose() {
    _healthTimer?.cancel();
    _alertTimer?.cancel();
    _coreService.dispose();
    super.dispose();
  }

  void _addLog(String message, LogLevel level) {
    if (!mounted) return;
    setState(() {
      _logs.insert(0, LogEntry(message: message, timestamp: _timeNow(), level: level));
      if (_logs.length > 30) _logs.removeLast();
    });
  }

  String _timeNow() {
    final now = DateTime.now();
    return '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}:${now.second.toString().padLeft(2, '0')}';
  }

  Future<void> _load() async {
    setState(() => _connectionState = CoreConnectionState.connecting);
    try {
      final health = await _coreService.getHealth();
      setState(() {
        _health = health;
        _connectionState = health.isActive ? CoreConnectionState.connected : CoreConnectionState.error;
      });
      if (health.isActive) {
        _addLog('Connected to ${health.agent} v${health.version}', LogLevel.success);
        await _loadIdentityData();
        _startPolling();
      }
    } catch (e) {
      if (mounted) {
        setState(() => _connectionState = CoreConnectionState.error);
        _addLog('Connection failed: ${e.toString().split(': ').last}', LogLevel.error);
      }
    }
  }

  Future<void> _loadIdentityData() async {
    try {
      final results = await Future.wait([
        _coreService.getIdentity(),
        _coreService.getProfile(),
        _coreService.getOobi().catchError((_) => OobiResponse(
              oobiUrl: '',
              aid: '',
              publicKey: '',
              baseUrl: '',
              endpointSource: '',
              tunnelProvider: '',
              tunnelError: '',
            )),
      ]);
      if (mounted) {
        setState(() {
          _identity = results[0] as IdentityResponse;
          _profile = results[1] as ProfileResponse;
          _oobi = results[2] as OobiResponse;
        });
        if ((_identity?.initialized ?? false) && _identity?.aid != null) {
          _addLog('Identity: ${_identity!.aid!.substring(0, 12)}…', LogLevel.info);
        }
      }
    } catch (_) {}
  }

  Future<void> _fetchAlerts() async {
    try {
      final result = await _coreService.getAlerts();
      if (mounted) {
        setState(() {
          _alerts = result.alerts;
          _pendingRequests = result.pendingRequests;
        });
      }
    } catch (_) {}
  }

  void _startPolling() {
    _fetchAlerts();
    _alertTimer = Timer.periodic(const Duration(seconds: 15), (_) => _fetchAlerts());
    _healthTimer = Timer.periodic(Duration(seconds: AgentConfig.healthPollIntervalSeconds), (_) async {
      try {
        final h = await _coreService.getHealth();
        if (mounted) {
          setState(() {
            _health = h;
            _connectionState = h.isActive ? CoreConnectionState.connected : CoreConnectionState.error;
          });
        }
      } catch (_) {
        if (mounted) setState(() => _connectionState = CoreConnectionState.error);
      }
    });
  }

  Future<void> _acceptContact(String aid) async {
    try {
      await _coreService.acceptContact(aid);
      _addLog('Contact accepted', LogLevel.success);
      _fetchAlerts();
    } catch (e) {
      _addLog('Accept failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _rejectContact(String aid) async {
    try {
      await _coreService.rejectContact(aid);
      _addLog('Contact rejected', LogLevel.info);
      _fetchAlerts();
    } catch (e) {
      _addLog('Reject failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _dismissPendingRequest(String aid) async {
    try {
      await _coreService.deletePendingRequest(aid);
      _fetchAlerts();
    } catch (_) {}
  }

  void _showShareDialog() {
    if (_oobi == null || _oobi!.oobiUrl.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No OOBI URL available. Complete setup first.')),
      );
      return;
    }
    showDialog(context: context, builder: (_) => _ShareDialog(oobi: _oobi!));
  }

  void _showAddContactDialog() {
    final controller = TextEditingController();
    bool resolving = false;
    String? resolveError;

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: const BorderSide(color: AppColors.border),
          ),
          title: const Text('Add Contact',
              style: TextStyle(color: AppColors.textPrimary, fontSize: 15,
                  fontWeight: FontWeight.w600)),
          content: SizedBox(
            width: 420,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Paste an OOBI URL to resolve and add the identity.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
                const SizedBox(height: 16),
                TextField(
                  controller: controller,
                  style: const TextStyle(color: AppColors.accent, fontSize: 12,
                      fontFamily: 'monospace'),
                  decoration: InputDecoration(
                    hintText: 'http://…/public/oobi/…',
                    hintStyle: TextStyle(color: AppColors.textMuted.withOpacity(0.5),
                        fontSize: 12, fontFamily: 'monospace'),
                    filled: true,
                    fillColor: AppColors.surfaceLight,
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(color: AppColors.border)),
                    enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(color: AppColors.border)),
                    focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(color: AppColors.accent)),
                    contentPadding: const EdgeInsets.all(12),
                  ),
                ),
                if (resolveError != null) ...[
                  const SizedBox(height: 8),
                  Text(resolveError!,
                      style: const TextStyle(color: AppColors.error, fontSize: 11)),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cancel', style: TextStyle(color: AppColors.textMuted)),
            ),
            ElevatedButton(
              onPressed: resolving ? null : () async {
                final url = controller.text.trim();
                if (url.isEmpty) return;
                setS(() { resolving = true; resolveError = null; });
                try {
                  await _coreService.addContact(oobiUrl: url);
                  if (ctx.mounted) Navigator.of(ctx).pop();
                  _addLog('Contact added', LogLevel.success);
                  _fetchAlerts();
                } catch (e) {
                  setS(() { resolving = false; resolveError = e.toString().split(': ').last; });
                }
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: Colors.white,
              ),
              child: resolving
                  ? const SizedBox(width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                  : const Text('Resolve & Add'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final totalAlerts = _alerts.length + _pendingRequests.length;

    return Scaffold(
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            const SizedBox(height: 20),
            // 3-column dashboard layout
            IntrinsicHeight(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // ── Identity column ──────────────────────────────────────
                  Expanded(
                    flex: 3,
                    child: _buildIdentitySection(),
                  ),
                  const SizedBox(width: 16),
                  // ── Notifications column ─────────────────────────────────
                  Expanded(
                    flex: 4,
                    child: _buildNotificationsSection(totalAlerts),
                  ),
                  const SizedBox(width: 16),
                  // ── Engagement column ────────────────────────────────────
                  Expanded(
                    flex: 2,
                    child: _buildEngagementSection(),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    final isConnected = _connectionState == CoreConnectionState.connected;
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Dashboard', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 4),
              const Text('Your identity at a glance.',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
            ],
          ),
        ),
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(
            color: isConnected ? AppColors.success : AppColors.error,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 6),
        Text(
          isConnected ? 'Connected' : _connectionState == CoreConnectionState.connecting ? 'Connecting…' : 'Disconnected',
          style: TextStyle(
            color: isConnected ? AppColors.success : AppColors.textMuted,
            fontSize: 12,
          ),
        ),
        const SizedBox(width: 12),
        IconButton(
          onPressed: _load,
          icon: const Icon(Icons.refresh),
          color: AppColors.textSecondary,
          tooltip: 'Refresh',
          iconSize: 18,
        ),
      ],
    );
  }

  Widget _buildIdentitySection() {
    final hasIdentity = _identity?.initialized == true && _identity?.aid != null;

    return _sectionCard(
      title: 'Identity',
      icon: Icons.fingerprint,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Profile header
          _buildProfileHeader(),
          if (hasIdentity) ...[
            const SizedBox(height: 16),
            // AID
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border),
              ),
              child: SelectableText(
                _identity!.aid!,
                style: const TextStyle(
                  color: AppColors.primary,
                  fontSize: 10,
                  fontFamily: 'monospace',
                  height: 1.4,
                ),
              ),
            ),
            const SizedBox(height: 12),
            // Badges row
            Row(
              children: [
                KeyStorageBadge(coreService: _coreService),
                const Spacer(),
                LiveIdentityLevelBadge(
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            // Event count
            if (_identity!.eventCount != null)
              Text(
                '${_identity!.eventCount} key event${_identity!.eventCount == 1 ? '' : 's'}',
                style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
              ),
          ] else if (_connectionState == CoreConnectionState.connected) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.warning.withOpacity(0.08),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.warning.withOpacity(0.3)),
              ),
              child: const Row(
                children: [
                  Icon(Icons.warning_amber_rounded, color: AppColors.warning, size: 16),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text('No identity found. Complete the setup wizard.',
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 12)),
                  ),
                ],
              ),
            ),
          ] else ...[
            const SizedBox(height: 20),
            const Center(child: CircularProgressIndicator()),
          ],
        ],
      ),
    );
  }

  Widget _buildProfileHeader() {
    Widget avatar;
    if (_profile?.photo != null && _profile!.photo.isNotEmpty) {
      try {
        final bytes = base64Decode(_profile!.photo);
        avatar = CircleAvatar(radius: 24, backgroundImage: MemoryImage(bytes));
      } catch (_) {
        avatar = _initialsAvatar();
      }
    } else {
      avatar = _initialsAvatar();
    }

    final name = _profile?.fullName.isNotEmpty == true
        ? _profile!.fullName
        : 'Identity Agent';

    return Row(
      children: [
        avatar,
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(name,
                  style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600,
                      color: AppColors.textPrimary),
                  maxLines: 1, overflow: TextOverflow.ellipsis),
              if (_profile?.org.isNotEmpty == true)
                Text(_profile!.org,
                    style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                    maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
          ),
        ),
      ],
    );
  }

  Widget _initialsAvatar() {
    final name = _profile?.fullName ?? '';
    final initials = name.isNotEmpty
        ? name.split(' ').take(2).map((w) => w.isNotEmpty ? w[0].toUpperCase() : '').join()
        : 'IA';
    return CircleAvatar(
      radius: 24,
      backgroundColor: AppColors.primary,
      child: Text(initials.isNotEmpty ? initials : 'IA',
          style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w600)),
    );
  }

  Widget _buildNotificationsSection(int totalAlerts) {
    return _sectionCard(
      title: 'Notifications',
      icon: Icons.notifications_outlined,
      trailing: totalAlerts > 0
          ? Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                color: AppColors.corePending.withOpacity(0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text('$totalAlerts',
                  style: const TextStyle(color: AppColors.corePending, fontSize: 11,
                      fontWeight: FontWeight.w700)),
            )
          : null,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Alerts sub-section
          if (_alerts.isNotEmpty || _pendingRequests.isNotEmpty) ...[
            _subSectionHeader('Alerts', Icons.notifications_active_outlined, AppColors.corePending),
            const SizedBox(height: 8),
            ..._alerts.take(3).map((a) => _alertItem(a)),
            ..._pendingRequests.take(2).map((r) => _pendingItem(r)),
            if (_alerts.length + _pendingRequests.length > 5)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                  '+ ${_alerts.length + _pendingRequests.length - 5} more…',
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11),
                ),
              ),
          ] else ...[
            _subSectionHeader('Alerts', Icons.notifications_none_outlined, AppColors.textMuted),
            const SizedBox(height: 8),
            const Text('No pending alerts.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
          ],
          const SizedBox(height: 16),
          // Activity sub-section
          _subSectionHeader('Activity', Icons.history, AppColors.textMuted),
          const SizedBox(height: 8),
          if (_logs.isEmpty)
            const Text('No activity yet.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 12))
          else
            ..._logs.take(8).map((log) => LogEntryWidget(entry: log)),
        ],
      ),
    );
  }

  Widget _subSectionHeader(String label, IconData icon, Color color) {
    return Row(
      children: [
        Icon(icon, size: 13, color: color),
        const SizedBox(width: 6),
        Text(label,
            style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                color: color, letterSpacing: 0.5)),
      ],
    );
  }

  Widget _alertItem(ContactResponse alert) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 14,
                backgroundColor: AppColors.corePending.withOpacity(0.12),
                child: Text(
                  alert.displayName.isNotEmpty ? alert.displayName[0].toUpperCase() : '?',
                  style: const TextStyle(color: AppColors.corePending, fontSize: 12,
                      fontWeight: FontWeight.w600),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(alert.displayName,
                    style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary)),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.corePending.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: const Text('INCOMING',
                    style: TextStyle(color: AppColors.corePending, fontSize: 8,
                        fontWeight: FontWeight.w700, letterSpacing: 0.8)),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(
                onPressed: () => _rejectContact(alert.aid),
                style: TextButton.styleFrom(
                  foregroundColor: AppColors.error,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                child: const Text('Reject', style: TextStyle(fontSize: 12)),
              ),
              const SizedBox(width: 6),
              ElevatedButton(
                onPressed: () => _acceptContact(alert.aid),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.success,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  elevation: 0,
                ),
                child: const Text('Accept', style: TextStyle(fontSize: 12)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _pendingItem(PendingRequestResponse req) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.error.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          const Icon(Icons.link_off, color: AppColors.error, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child: Text(req.displayName,
                style: const TextStyle(fontSize: 12, color: AppColors.textPrimary)),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
            decoration: BoxDecoration(
              color: AppColors.error.withOpacity(0.1),
              borderRadius: BorderRadius.circular(3),
            ),
            child: const Text('FAILED',
                style: TextStyle(color: AppColors.error, fontSize: 8,
                    fontWeight: FontWeight.w700, letterSpacing: 0.8)),
          ),
          const SizedBox(width: 6),
          TextButton(
            onPressed: () => _dismissPendingRequest(req.aid),
            style: TextButton.styleFrom(
              foregroundColor: AppColors.textMuted,
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              minimumSize: Size.zero,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            ),
            child: const Text('Dismiss', style: TextStyle(fontSize: 11)),
          ),
        ],
      ),
    );
  }

  Widget _buildEngagementSection() {
    return _sectionCard(
      title: 'Engagement',
      icon: Icons.hub_outlined,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Share
          _engagementButton(
            icon: Icons.share_outlined,
            label: 'Share My Identity',
            description: 'Share your OOBI URL so others can add you as a contact.',
            color: AppColors.primary,
            onTap: _showShareDialog,
          ),
          const SizedBox(height: 10),
          // Add Contact
          _engagementButton(
            icon: Icons.person_add_outlined,
            label: 'Add Contact',
            description: 'Resolve an OOBI URL to add a contact to your network.',
            color: AppColors.accent,
            onTap: _showAddContactDialog,
          ),
          const SizedBox(height: 16),
          // Backend status pill
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Backend',
                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                        color: AppColors.textMuted)),
                const SizedBox(height: 6),
                if (_health != null) ...[
                  Text(_health!.agent,
                      style: const TextStyle(fontSize: 12, color: AppColors.textPrimary)),
                  const SizedBox(height: 2),
                  Text('v${_health!.version} · ${_health!.mode}',
                      style: const TextStyle(fontSize: 11, color: AppColors.textMuted,
                          fontFamily: 'monospace')),
                  const SizedBox(height: 2),
                  Text('Uptime: ${_health!.uptime}',
                      style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
                ] else
                  const Text('Loading…',
                      style: TextStyle(fontSize: 12, color: AppColors.textMuted)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _engagementButton({
    required IconData icon,
    required String label,
    required String description,
    required Color color,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: color.withOpacity(0.06),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withOpacity(0.2)),
        ),
        child: Row(
          children: [
            Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: color.withOpacity(0.12),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(icon, color: color, size: 18),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label,
                      style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: color)),
                  const SizedBox(height: 2),
                  Text(description,
                      style: const TextStyle(fontSize: 11, color: AppColors.textMuted,
                          height: 1.3)),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: color.withOpacity(0.5), size: 18),
          ],
        ),
      ),
    );
  }

  Widget _sectionCard({
    required String title,
    required IconData icon,
    required Widget child,
    Widget? trailing,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: AppColors.textSecondary),
              const SizedBox(width: 8),
              Text(title,
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                      color: AppColors.textSecondary)),
              const Spacer(),
              if (trailing != null) trailing,
            ],
          ),
          const Divider(height: 20),
          child,
        ],
      ),
    );
  }
}

// ── Share dialog ─────────────────────────────────────────────────────────────

class _ShareDialog extends StatefulWidget {
  final OobiResponse oobi;
  const _ShareDialog({required this.oobi});

  @override
  State<_ShareDialog> createState() => _ShareDialogState();
}

class _ShareDialogState extends State<_ShareDialog> {
  bool _copied = false;

  void _copy() {
    Clipboard.setData(ClipboardData(text: widget.oobi.oobiUrl));
    setState(() => _copied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: AppColors.border),
      ),
      child: SizedBox(
        width: 440,
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.share_outlined, color: AppColors.primary, size: 20),
                  const SizedBox(width: 10),
                  const Expanded(
                    child: Text('Share My Identity',
                        style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700,
                            color: AppColors.textPrimary)),
                  ),
                  IconButton(
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close, size: 18, color: AppColors.textMuted),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              const Text(
                'Share your OOBI URL so others can verify and add you as a contact.',
                style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 20),
              // OOBI URL
              const Text('OOBI URL',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                      color: AppColors.textMuted, letterSpacing: 0.5)),
              const SizedBox(height: 6),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: AppColors.accent.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: SelectableText(
                        widget.oobi.oobiUrl,
                        style: const TextStyle(color: AppColors.accent, fontSize: 11,
                            fontFamily: 'monospace', height: 1.4),
                      ),
                    ),
                    const SizedBox(width: 8),
                    InkWell(
                      onTap: _copy,
                      borderRadius: BorderRadius.circular(6),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                        decoration: BoxDecoration(
                          color: _copied ? AppColors.success.withOpacity(0.12) : AppColors.surface,
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: _copied ? AppColors.success.withOpacity(0.3) : AppColors.border),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(_copied ? Icons.check : Icons.copy,
                                color: _copied ? AppColors.success : AppColors.textSecondary, size: 13),
                            const SizedBox(width: 4),
                            Text(_copied ? 'COPIED' : 'COPY',
                                style: TextStyle(
                                  color: _copied ? AppColors.success : AppColors.textSecondary,
                                  fontSize: 10, fontWeight: FontWeight.w600, letterSpacing: 1.0,
                                )),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),
              // QR Code
              const Text('QR Code',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                      color: AppColors.textMuted, letterSpacing: 0.5)),
              const SizedBox(height: 8),
              const Text('Scan from another device to add this identity.',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
              const SizedBox(height: 12),
              Center(
                child: Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: QrImageView(
                    data: widget.oobi.oobiUrl,
                    version: QrVersions.auto,
                    size: 180,
                    backgroundColor: Colors.white,
                    eyeStyle: const QrEyeStyle(
                        eyeShape: QrEyeShape.square, color: Color(0xFF0a0e1a)),
                    dataModuleStyle: const QrDataModuleStyle(
                        dataModuleShape: QrDataModuleShape.square, color: Color(0xFF0a0e1a)),
                  ),
                ),
              ),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () => Navigator.of(context).pop(),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.primary,
                    foregroundColor: Colors.white,
                  ),
                  child: const Text('Done'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
