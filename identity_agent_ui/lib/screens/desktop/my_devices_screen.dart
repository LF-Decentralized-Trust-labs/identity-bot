import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../services/keri_service.dart';
import '../../services/mobile_on_device_keri_service.dart';
import '../../config/agent_config.dart';

class MyDevicesScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const MyDevicesScreen({
    super.key,
    required this.keriService,
    this.serverUrl,
  });

  @override
  State<MyDevicesScreen> createState() => _MyDevicesScreenState();
}

class _MyDevicesScreenState extends State<MyDevicesScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveUrl());

  String? _resolveUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    if (widget.keriService is MobileOnDeviceKeriService) {
      final s = widget.keriService as MobileOnDeviceKeriService;
      if (s.isCoreReady) return s.mobileCore.baseUrl;
    }
    return null;
  }

  HealthResponse? _health;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final h = await _coreService.getHealth();
      if (mounted) setState(() { _health = h; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final isRemote = widget.serverUrl != null;
    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('My Devices',
                          style: Theme.of(context).textTheme.headlineMedium),
                      const SizedBox(height: 4),
                      const Text(
                        'Devices and servers connected to this identity.',
                        style: TextStyle(
                            color: AppColors.textSecondary, fontSize: 14),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  onPressed: _load,
                  icon: const Icon(Icons.refresh),
                  color: AppColors.textSecondary,
                  tooltip: 'Refresh',
                ),
              ],
            ),
            const SizedBox(height: 32),
            if (_loading)
              const Center(child: CircularProgressIndicator())
            else if (_error != null)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppColors.error.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: AppColors.error.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.error_outline,
                        color: AppColors.error, size: 20),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(_error!,
                          style: const TextStyle(
                              color: AppColors.error, fontSize: 13)),
                    ),
                  ],
                ),
              )
            else
              _buildDeviceList(isRemote),
          ],
        ),
      ),
    );
  }

  Widget _buildDeviceList(bool isRemote) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _deviceCard(
          label: isRemote ? 'Remote Server' : 'This Device',
          icon: isRemote ? Icons.dns_outlined : Icons.computer,
          isOnline: _health != null,
          agent: _health?.agent ?? '—',
          version: _health?.version ?? '—',
          mode: _health?.mode ?? '—',
          uptime: _health?.uptime ?? '—',
          url: widget.serverUrl ?? AgentConfig.coreBaseUrl,
          isPrimary: !isRemote,
        ),
        if (isRemote) ...[
          const SizedBox(height: 16),
          _deviceCard(
            label: 'This Device (Controller)',
            icon: Icons.computer,
            isOnline: true,
            agent: 'Identity Agent UI',
            version: '—',
            mode: 'controller',
            uptime: '—',
            url: 'local',
            isPrimary: true,
          ),
        ],
        const SizedBox(height: 32),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppColors.border),
          ),
          child: const Row(
            children: [
              Icon(Icons.add_circle_outline,
                  color: AppColors.textMuted, size: 16),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Additional devices — mobile controllers, remote servers, and other trusted devices — will appear here as they are paired with this identity.',
                  style: TextStyle(
                      color: AppColors.textMuted, fontSize: 13, height: 1.5),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _deviceCard({
    required String label,
    required IconData icon,
    required bool isOnline,
    required String agent,
    required String version,
    required String mode,
    required String uptime,
    required String url,
    required bool isPrimary,
  }) {
    final statusColor = isOnline ? AppColors.success : AppColors.error;
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(
          color: isPrimary
              ? AppColors.primary.withOpacity(0.3)
              : AppColors.border,
        ),
        borderRadius: BorderRadius.circular(12),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 18, color: AppColors.textSecondary),
              const SizedBox(width: 10),
              Expanded(
                child: Text(label,
                    style: const TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary)),
              ),
              Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                      color: statusColor, shape: BoxShape.circle)),
              const SizedBox(width: 6),
              Text(isOnline ? 'Online' : 'Offline',
                  style: TextStyle(fontSize: 12, color: statusColor)),
            ],
          ),
          const Divider(height: 20),
          _kv('Agent', agent),
          _kv('Version', 'v$version'),
          _kv('Mode', mode),
          if (uptime != '—') _kv('Uptime', uptime),
          if (url != 'local') _kv('URL', url),
        ],
      ),
    );
  }

  Widget _kv(String key, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(key,
                style: const TextStyle(
                    fontSize: 12,
                    color: AppColors.textMuted,
                    fontWeight: FontWeight.w500)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(
                    fontSize: 12,
                    color: AppColors.textPrimary,
                    fontFamily: 'monospace')),
          ),
        ],
      ),
    );
  }
}
