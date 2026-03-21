import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'dart:async';
import 'dart:io' show Platform;
import '../theme/app_theme.dart';
import '../config/agent_config.dart';
import '../services/core_service.dart';
import '../services/keri_service.dart';
import '../services/mobile_on_device_keri_service.dart';
import '../widgets/status_indicator.dart';
import '../widgets/info_card.dart';
import '../widgets/log_entry.dart';
import '../widgets/identity_level_badge.dart';
import '../widgets/key_storage_badge.dart';
import 'auth_setup_screen.dart';

class DashboardScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const DashboardScreen({super.key, required this.keriService, this.serverUrl});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());
  CoreConnectionState _connectionState = CoreConnectionState.disconnected;
  HealthResponse? _healthData;
  CoreInfoResponse? _coreInfo;
  IdentityResponse? _identity;
  String? _errorMessage;
  final List<LogEntry> _logs = [];
  Timer? _healthTimer;
  List<ContactResponse> _alerts = [];
  List<PendingRequestResponse> _pendingRequests = [];
  Timer? _alertTimer;

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    if (widget.keriService is MobileOnDeviceKeriService) {
      final standalone = widget.keriService as MobileOnDeviceKeriService;
      if (standalone.isCoreReady) {
        return standalone.mobileCore.baseUrl;
      }
    }
    return null;
  }

  @override
  void initState() {
    super.initState();
    _addLog('Controller UI initialized', LogLevel.info);
    _addLog('Attempting handshake with Go Core...', LogLevel.info);
    _performHandshake();
  }

  @override
  void dispose() {
    _healthTimer?.cancel();
    _alertTimer?.cancel();
    _coreService.dispose();
    super.dispose();
  }

  bool get _isStandaloneMode {
    return widget.keriService is MobileOnDeviceKeriService;
  }

  String _timeNow() {
    final now = DateTime.now();
    return '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}:${now.second.toString().padLeft(2, '0')}';
  }

  void _addLog(String message, LogLevel level) {
    setState(() {
      _logs.insert(0, LogEntry(
        message: message,
        timestamp: _timeNow(),
        level: level,
      ));
      if (_logs.length > 50) _logs.removeLast();
    });
  }

  Future<void> _performHandshake() async {
    setState(() {
      _connectionState = CoreConnectionState.connecting;
      _errorMessage = null;
    });

    try {
      final health = await _coreService.getHealth();
      final info = await _coreService.getInfo();
      IdentityResponse? identity;
      try {
        identity = await _coreService.getIdentity();
      } catch (_) {}

      setState(() {
        _healthData = health;
        _coreInfo = info;
        _identity = identity;
        _connectionState = health.isActive
            ? CoreConnectionState.connected
            : CoreConnectionState.error;
      });

      if (health.isActive) {
        _addLog('Handshake successful with ${health.agent}', LogLevel.success);
        _addLog('Core version: ${health.version}', LogLevel.info);
        _addLog('Backend mode: ${health.mode}', LogLevel.info);
        _addLog('Phase: ${info.phase}', LogLevel.info);
        if (identity != null && identity.initialized) {
          _addLog('Identity active: ${identity.aid!.substring(0, 12)}...', LogLevel.success);
        }
        _startHealthPolling();
      } else {
        _addLog('Core responded but status is: ${health.status}', LogLevel.warning);
      }
    } catch (e) {
      setState(() {
        _connectionState = CoreConnectionState.error;
        _errorMessage = e.toString();
      });
      _addLog('Handshake failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _fetchAlerts() async {
    try {
      final result = await _coreService.getAlerts();
      if (mounted) {
        setState(() {
          _alerts = result.alerts;
          _pendingRequests = result.pendingRequests;
        });
        final totalCount = result.alerts.length + result.pendingRequests.length;
        if (totalCount > 0) {
          _addLog('$totalCount pending alert${totalCount == 1 ? '' : 's'}', LogLevel.warning);
        }
      }
    } catch (_) {}
  }

  void _startAlertPolling() {
    _alertTimer?.cancel();
    _fetchAlerts();
    _alertTimer = Timer.periodic(const Duration(seconds: 15), (_) => _fetchAlerts());
  }

  Future<void> _acceptContact(String aid) async {
    try {
      await _coreService.acceptContact(aid);
      _addLog('Contact accepted: ${aid.substring(0, 12)}...', LogLevel.success);
      _fetchAlerts();
    } catch (e) {
      _addLog('Accept failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  Future<void> _rejectContact(String aid) async {
    try {
      await _coreService.rejectContact(aid);
      _addLog('Contact rejected: ${aid.substring(0, 12)}...', LogLevel.info);
      _fetchAlerts();
    } catch (e) {
      _addLog('Reject failed: ${e.toString().split(': ').last}', LogLevel.error);
    }
  }

  void _startHealthPolling() {
    _healthTimer?.cancel();
    _startAlertPolling();
    _healthTimer = Timer.periodic(Duration(seconds: AgentConfig.healthPollIntervalSeconds), (_) async {
      try {
        final health = await _coreService.getHealth();
        setState(() {
          _healthData = health;
          _connectionState = health.isActive
              ? CoreConnectionState.connected
              : CoreConnectionState.error;
        });
      } catch (e) {
        setState(() {
          _connectionState = CoreConnectionState.error;
        });
        _addLog('Health poll failed: connection lost', LogLevel.error);
        _healthTimer?.cancel();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(32, 0, 32, 32),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildHeader(),
              const SizedBox(height: 28),
              // OmniFactor stub row
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(flex: 2, child: _buildCoreStatusCard()),
                  const SizedBox(width: 16),
                  Expanded(child: _buildOfaStubCard()),
                ],
              ),
              const SizedBox(height: 20),
              if (_connectionState == CoreConnectionState.connected) ...[
                if (_identity != null && _identity!.initialized) ...[
                  _buildIdentityCard(),
                  const SizedBox(height: 20),
                ],
                if (_alerts.isNotEmpty || _pendingRequests.isNotEmpty) ...[
                  _buildAlertsCard(),
                  const SizedBox(height: 20),
                ],
                if (_isStandaloneMode && _identity != null && _identity!.initialized) ...[
                  _buildMigrateButton(),
                  const SizedBox(height: 20),
                ],
                _buildInfoGrid(),
                const SizedBox(height: 20),
              ],
              _buildActivityLog(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(32, 32, 32, 0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Dashboard',
                    style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 4),
                const Text('Your identity at a glance.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
              ],
            ),
          ),
          StatusIndicator(state: _connectionState),
          const SizedBox(width: 8),
          IconButton(
            onPressed: _performHandshake,
            icon: const Icon(Icons.refresh),
            color: AppColors.textSecondary,
            tooltip: 'Refresh',
          ),
        ],
      ),
    );
  }

  Widget _buildCoreStatusCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Backend Status',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
          const Divider(height: 20),
          _buildStatusContent(),
        ],
      ),
    );
  }

  Widget _buildStatusContent() {
    switch (_connectionState) {
      case CoreConnectionState.connecting:
        return Row(
          children: [
            SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: AppColors.corePending,
              ),
            ),
            const SizedBox(width: 12),
            const Text(
              'Attempting handshake with Go Core...',
              style: TextStyle(
                color: AppColors.corePending,
                fontSize: 13,
              ),
            ),
          ],
        );

      case CoreConnectionState.connected:
        return Column(
          children: [
            Row(
              children: [
                const Icon(Icons.check_circle, color: AppColors.coreActive, size: 22),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Connected',
                        style: TextStyle(
                          color: AppColors.coreActive,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Connected to ${_healthData?.agent ?? "unknown"} v${_healthData?.version ?? "?"}',
                        style: const TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border, width: 1),
              ),
              child: Text(
                'GET /health -> {"status": "${_healthData?.status}", "agent": "${_healthData?.agent}"}',
                style: const TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ],
        );

      case CoreConnectionState.error:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.error_outline, color: AppColors.coreInactive, size: 22),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text(
                    'Connection Failed',
                    style: TextStyle(
                      color: AppColors.coreInactive,
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
            if (_errorMessage != null) ...[
              const SizedBox(height: 8),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: AppColors.coreInactive.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  _errorMessage!,
                  style: const TextStyle(
                    color: AppColors.coreInactive,
                    fontSize: 11,
                  ),
                ),
              ),
            ],
          ],
        );

      case CoreConnectionState.disconnected:
        return const Row(
          children: [
            Icon(Icons.power_off, color: AppColors.textMuted, size: 22),
            SizedBox(width: 10),
            Text(
              'Go Core not started',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 14,
              ),
            ),
          ],
        );
    }
  }

  Widget _buildOfaStubCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.border),
        borderRadius: BorderRadius.circular(12),
        color: AppColors.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('OmniFactor Score',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
          const Divider(height: 20),
          const SizedBox(height: 8),
          Center(
            child: Stack(
              alignment: Alignment.center,
              children: [
                SizedBox(
                  width: 80,
                  height: 80,
                  child: CircularProgressIndicator(
                    value: 0.0,
                    strokeWidth: 8,
                    backgroundColor: AppColors.border,
                    color: AppColors.primary.withValues(alpha: 0.3),
                  ),
                ),
                const Text('—', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700, color: AppColors.textMuted)),
              ],
            ),
          ),
          const SizedBox(height: 12),
          const Center(
            child: Text(
              'Coming soon',
              style: TextStyle(fontSize: 12, color: AppColors.textMuted),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildIdentityCard() {
    final aid = _identity!.aid ?? '';
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 28,
                height: 28,
                decoration: BoxDecoration(
                  color: AppColors.coreActive.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Icon(
                  Icons.fingerprint,
                  color: AppColors.coreActive,
                  size: 16,
                ),
              ),
              const SizedBox(width: 10),
              const Text(
                'Autonomous Identifier',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppColors.coreActive.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: const Text(
                  'ACTIVE',
                  style: TextStyle(
                    color: AppColors.coreActive,
                    fontSize: 9,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border, width: 1),
            ),
            child: SelectableText(
              aid,
              style: const TextStyle(
                color: AppColors.primary,
                fontSize: 12,
                fontFamily: 'monospace',
                height: 1.5,
              ),
            ),
          ),
          if (_identity!.created != null) ...[
            const SizedBox(height: 10),
            Row(
              children: [
                const Icon(Icons.access_time, color: AppColors.textMuted, size: 12),
                const SizedBox(width: 6),
                Text(
                  'Created: ${_identity!.created}',
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 10,
                  ),
                ),
                const Spacer(),
                Text(
                  'Events: ${_identity!.eventCount ?? 0}',
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 10,
                  ),
                ),
              ],
            ),
          ],
          const SizedBox(height: 14),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              KeyStorageBadge(coreService: _coreService),
              LiveIdentityLevelBadge(
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildMigrateButton() {
    return InkWell(
      onTap: () {
        showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            backgroundColor: AppColors.surface,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
              side: const BorderSide(color: AppColors.border),
            ),
            title: const Text(
              'Migrate to External Server',
              style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.w700,
              ),
            ),
            content: const Text(
              'This feature will allow you to migrate your identity '
              'to an external server while keeping your keys on this device.\n\n'
              'Your phone will become a Remote Controller WITH Keys, '
              'maintaining full cryptographic authority over your identity '
              'while delegating compute-heavy tasks to the server.\n\n'
              'Coming soon.',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                height: 1.5,
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(ctx).pop(),
                child: const Text(
                  'OK',
                  style: TextStyle(
                    color: AppColors.accent,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
        );
      },
      borderRadius: BorderRadius.circular(12),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: AppColors.corePending.withOpacity(0.3),
            width: 1,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                color: AppColors.corePending.withOpacity(0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(
                Icons.cloud_upload_outlined,
                color: AppColors.corePending,
                size: 18,
              ),
            ),
            const SizedBox(width: 14),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Migrate to External Server',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  SizedBox(height: 2),
                  Text(
                    'Move backend to a server, keep keys here',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 10,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: AppColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildAlertsCard() {
    final totalCount = _alerts.length + _pendingRequests.length;
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 28,
                height: 28,
                decoration: BoxDecoration(
                  color: AppColors.corePending.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Icon(
                  Icons.notifications_active_outlined,
                  color: AppColors.corePending,
                  size: 16,
                ),
              ),
              const SizedBox(width: 10),
              const Text(
                'Alerts',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppColors.corePending.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '$totalCount',
                  style: const TextStyle(
                    color: AppColors.corePending,
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          ..._alerts.map((alert) => Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: _buildAlertItem(alert),
          )),
          ..._pendingRequests.map((req) => Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: _buildPendingRequestItem(req),
          )),
        ],
      ),
    );
  }

  Widget _buildAlertAvatar(String name) {
    final initial = name.isNotEmpty ? name[0].toUpperCase() : '?';
    return Container(
      width: 36,
      height: 36,
      decoration: BoxDecoration(
        color: AppColors.corePending.withOpacity(0.12),
        border: Border.all(color: AppColors.corePending.withOpacity(0.25), width: 1.5),
        borderRadius: BorderRadius.circular(18),
      ),
      child: Center(
        child: Text(
          initial,
          style: const TextStyle(
            color: AppColors.corePending,
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }

  Widget _buildAlertItem(ContactResponse alert) {
    final aidShort = alert.aid.length > 16 ? alert.aid.substring(0, 16) : alert.aid;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.border, width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              _buildAlertAvatar(alert.displayName),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      alert.displayName,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      aidShort,
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 10,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.corePending.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: const Text(
                  'INCOMING',
                  style: TextStyle(
                    color: AppColors.corePending,
                    fontSize: 8,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.8,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              OutlinedButton(
                onPressed: () => _rejectContact(alert.aid),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppColors.error,
                  side: BorderSide(color: AppColors.error.withValues(alpha: 0.4)),
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                child: const Text('Reject', style: TextStyle(fontSize: 13)),
              ),
              const SizedBox(width: 10),
              ElevatedButton(
                onPressed: () => _acceptContact(alert.aid),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.success,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  elevation: 0,
                ),
                child: const Text('Accept', style: TextStyle(fontSize: 13)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPendingRequestItem(PendingRequestResponse req) {
    final aidShort = req.aid.length > 16 ? req.aid.substring(0, 16) : req.aid;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.error.withOpacity(0.3), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: AppColors.error.withOpacity(0.12),
                  border: Border.all(color: AppColors.error.withOpacity(0.25), width: 1.5),
                  borderRadius: BorderRadius.circular(18),
                ),
                child: const Center(
                  child: Icon(Icons.link_off, color: AppColors.error, size: 16),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      req.displayName,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      aidShort,
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 10,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.error.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: const Text(
                  'FAILED',
                  style: TextStyle(
                    color: AppColors.error,
                    fontSize: 8,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.8,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppColors.error.withOpacity(0.06),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.warning_amber_rounded, color: AppColors.corePending, size: 14),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    req.errorReason.isNotEmpty
                        ? req.errorReason
                        : 'Could not verify sender identity. They may need to set up tunneling to make their OOBI reachable.',
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 10,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerRight,
            child: OutlinedButton(
              onPressed: () => _dismissPendingRequest(req.aid),
              style: OutlinedButton.styleFrom(
                foregroundColor: AppColors.textMuted,
                side: const BorderSide(color: AppColors.border),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              child: const Text('Dismiss', style: TextStyle(fontSize: 13)),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _dismissPendingRequest(String aid) async {
    try {
      await _coreService.deletePendingRequest(aid);
      _fetchAlerts();
    } catch (e) {
      debugPrint('[Dashboard] Failed to dismiss pending request: $e');
    }
  }

  Widget _buildInfoGrid() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'System Info',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 13,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: InfoCard(
                label: 'Agent',
                value: _healthData?.agent ?? '--',
                icon: Icons.memory,
                valueColor: AppColors.accent,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: InfoCard(
                label: 'Version',
                value: _healthData?.version ?? '--',
                icon: Icons.tag,
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: InfoCard(
                label: 'Uptime',
                value: _healthData?.uptime ?? '--',
                icon: Icons.timer_outlined,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: InfoCard(
                label: 'Mode',
                value: _healthData?.mode ?? '--',
                icon: Icons.settings_outlined,
              ),
            ),
          ],
        ),
        if (_coreInfo != null) ...[
          const SizedBox(height: 10),
          InfoCard(
            label: 'Phase',
            value: _coreInfo!.phase,
            icon: Icons.flag_outlined,
            valueColor: AppColors.corePending,
          ),
        ],
      ],
    );
  }

  Widget _buildActivityLog() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const Text(
              'Activity Log',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
            const Spacer(),
            Text(
              '${_logs.length} entries',
              style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 10,
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: _logs.isEmpty
              ? const Text(
                  'No activity yet.',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 12,
                  ),
                )
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: _logs.map((log) => LogEntryWidget(entry: log)).toList(),
                ),
        ),
      ],
    );
  }
}
