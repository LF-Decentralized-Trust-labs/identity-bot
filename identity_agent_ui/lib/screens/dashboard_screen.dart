import 'package:flutter/material.dart';
import 'dart:async';
import '../theme/app_theme.dart';
import '../services/core_service.dart';
import '../widgets/status_indicator.dart';
import '../widgets/info_card.dart';
import '../widgets/log_entry.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final CoreService _coreService = CoreService();
  CoreConnectionState _connectionState = CoreConnectionState.disconnected;
  HealthResponse? _healthData;
  CoreInfoResponse? _coreInfo;
  String? _errorMessage;
  final List<LogEntry> _logs = [];
  Timer? _healthTimer;

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
    _coreService.dispose();
    super.dispose();
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

      setState(() {
        _healthData = health;
        _coreInfo = info;
        _connectionState = health.isActive
            ? CoreConnectionState.connected
            : CoreConnectionState.error;
      });

      if (health.isActive) {
        _addLog('Handshake successful with ${health.agent}', LogLevel.success);
        _addLog('Core version: ${health.version}', LogLevel.info);
        _addLog('Backend mode: ${health.mode}', LogLevel.info);
        _addLog('Phase: ${info.phase}', LogLevel.info);
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

  void _startHealthPolling() {
    _healthTimer?.cancel();
    _healthTimer = Timer.periodic(const Duration(seconds: 15), (_) async {
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
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: 24),
                    _buildCoreStatusCard(),
                    const SizedBox(height: 20),
                    if (_connectionState == CoreConnectionState.connected) ...[
                      _buildInfoGrid(),
                      const SizedBox(height: 20),
                    ],
                    _buildActivityLog(),
                    const SizedBox(height: 24),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 16, 20, 16),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: AppColors.accent.withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: AppColors.accent.withOpacity(0.3),
                width: 1,
              ),
            ),
            child: const Icon(
              Icons.shield_outlined,
              color: AppColors.accent,
              size: 20,
            ),
          ),
          const SizedBox(width: 12),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'IDENTITY AGENT',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 2.0,
                  fontFamily: 'monospace',
                ),
              ),
              Text(
                'CONTROLLER DASHBOARD',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontWeight: FontWeight.w500,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
          const Spacer(),
          StatusIndicator(state: _connectionState),
        ],
      ),
    );
  }

  Widget _buildCoreStatusCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: _connectionState == CoreConnectionState.connected
              ? AppColors.accent.withOpacity(0.3)
              : AppColors.border,
          width: 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'GO CORE STATUS',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const Spacer(),
              if (_connectionState != CoreConnectionState.connecting)
                InkWell(
                  onTap: _performHandshake,
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLight,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: const Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.refresh, color: AppColors.textSecondary, size: 14),
                        SizedBox(width: 4),
                        Text(
                          'RETRY',
                          style: TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
                            letterSpacing: 1.0,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 16),
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
              'Attempting handshake with Go Core on :8080...',
              style: TextStyle(
                color: AppColors.corePending,
                fontSize: 13,
                fontFamily: 'monospace',
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
                        'Handshake Successful',
                        style: TextStyle(
                          color: AppColors.coreActive,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                          fontFamily: 'monospace',
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Connected to ${_healthData?.agent ?? "unknown"} v${_healthData?.version ?? "?"}',
                        style: const TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 12,
                          fontFamily: 'monospace',
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
                color: AppColors.primary,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border, width: 1),
              ),
              child: Text(
                'GET /health -> {"status": "${_healthData?.status}", "agent": "${_healthData?.agent}"}',
                style: const TextStyle(
                  color: AppColors.accent,
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
                      fontFamily: 'monospace',
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
                    fontFamily: 'monospace',
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
                fontFamily: 'monospace',
              ),
            ),
          ],
        );
    }
  }

  Widget _buildInfoGrid() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'SYSTEM INFO',
          style: TextStyle(
            color: AppColors.textMuted,
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 1.5,
            fontFamily: 'monospace',
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
              'ACTIVITY LOG',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w600,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const Spacer(),
            Text(
              '${_logs.length} entries',
              style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 10,
                fontFamily: 'monospace',
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
                    fontFamily: 'monospace',
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
