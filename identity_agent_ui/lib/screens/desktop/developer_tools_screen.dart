import 'dart:async';
import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../services/preferences_service.dart';
import '../../services/secure_key_store.dart';
import '../../services/setup_task_service.dart';
import '../../config/agent_config.dart';

class DeveloperToolsScreen extends StatefulWidget {
  final String? serverUrl;
  final VoidCallback? onResetIdentity;
  const DeveloperToolsScreen({super.key, this.serverUrl, this.onResetIdentity});

  @override
  State<DeveloperToolsScreen> createState() => _DeveloperToolsScreenState();
}

class _DeveloperToolsScreenState extends State<DeveloperToolsScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  HealthResponse? _health;
  CoreInfoResponse? _info;
  bool _loading = true;
  String? _error;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _load();
    _timer = Timer.periodic(const Duration(seconds: 15), (_) => _load());
  }

  @override
  void dispose() {
    _timer?.cancel();
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final results = await Future.wait([
        _coreService.getHealth(),
        _coreService.getInfo(),
      ]);
      if (mounted) {
        setState(() {
          _health  = results[0] as HealthResponse;
          _info    = results[1] as CoreInfoResponse;
          _loading = false;
          _error   = null;
        });
      }
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Developer Tools', style: Theme.of(context).textTheme.headlineMedium),
                      const SizedBox(height: 4),
                      Text('Backend status, engine info, and diagnostics.',
                          style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
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
              _errorBanner(_error!)
            else ...[
              _buildStatusCard(context),
              const SizedBox(height: 20),
              if (_info != null) _buildInfoCard(context),
            ],
            const SizedBox(height: 20),
            _buildResetCard(context),
          ],
        ),
        ),
      ),
    );
  }

  Widget _errorBanner(String msg) => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(
      color: AppColors.error.withOpacity(0.08),
      borderRadius: BorderRadius.circular(10),
      border: Border.all(color: AppColors.error.withOpacity(0.3)),
    ),
    child: Row(
      children: [
        const Icon(Icons.error_outline, color: AppColors.error, size: 20),
        const SizedBox(width: 12),
        Expanded(child: Text(msg, style: const TextStyle(color: AppColors.error, fontSize: 13))),
      ],
    ),
  );

  Widget _buildStatusCard(BuildContext context) {
    final h = _health;
    final isOk = h?.status == 'ok' || h?.isActive == true;
    final statusColor = isOk ? AppColors.success : AppColors.error;

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.border),
        borderRadius: BorderRadius.circular(12),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 10, height: 10,
                decoration: BoxDecoration(color: statusColor, shape: BoxShape.circle),
              ),
              const SizedBox(width: 10),
              Text('Backend Status',
                  style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: statusColor.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: statusColor.withOpacity(0.3)),
                ),
                child: Text(
                  (h?.status ?? 'unknown').toUpperCase(),
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: statusColor),
                ),
              ),
            ],
          ),
          const Divider(height: 24),
          _kv('Backend URL', widget.serverUrl ?? AgentConfig.coreBaseUrl),
          const SizedBox(height: 12),
          _kv('Agent', h?.agent ?? '—'),
          const SizedBox(height: 12),
          _kv('Version', h?.version ?? '—'),
          const SizedBox(height: 12),
          _kv('Mode', h?.mode ?? '—'),
          const SizedBox(height: 12),
          _kv('Uptime', h?.uptime ?? '—'),
        ],
      ),
    );
  }

  Widget _buildInfoCard(BuildContext context) {
    final info = _info!;
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.border),
        borderRadius: BorderRadius.circular(12),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Core Info',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
          const SizedBox(height: 16),
          _kv('Name', info.name),
          const SizedBox(height: 12),
          _kv('Version', info.version),
          const SizedBox(height: 12),
          _kv('Phase', info.phase),
          const SizedBox(height: 12),
          _kv('Description', info.description),
          const SizedBox(height: 12),
          _kv('Capabilities', info.capabilities.join(', ')),
        ],
      ),
    );
  }

  Future<void> _confirmReset() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Reset Identity'),
        content: const Text(
          'This will erase all local identity data including your keys, contacts, and settings. '
          'This action cannot be undone.\n\nAre you sure?',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(false), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.error, foregroundColor: Colors.white),
            child: const Text('Reset Identity'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      // 1. Reset backend data (contacts, credentials, KEL, etc.)
      try {
        await _coreService.resetAll();
      } catch (_) {
        // Backend may already be down — continue with local cleanup
      }

      // 2. Clear secure storage (mnemonic / keys)
      await SecureKeyStore.clearMnemonic();

      // 3. Clear setup task state
      for (final task in SetupTask.values) {
        await SetupTaskService.markIncomplete(task);
      }

      // 4. Clear SharedPreferences (onboarding, settings, etc.)
      await PreferencesService.clearAll();

      widget.onResetIdentity?.call();
    }
  }

  Widget _buildResetCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.error.withOpacity(0.4)),
        borderRadius: BorderRadius.circular(12),
        color: AppColors.error.withOpacity(0.04),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.warning_amber_rounded, color: AppColors.error, size: 20),
              const SizedBox(width: 8),
              const Text('Danger Zone',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600,
                      color: AppColors.textPrimary)),
            ],
          ),
          const SizedBox(height: 12),
          const Text(
            'Resetting your identity clears all local keys, contacts, credentials, and settings. '
            'This cannot be undone. Make sure you have a backup before proceeding.',
            style: TextStyle(fontSize: 14, color: AppColors.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 20),
          OutlinedButton.icon(
            onPressed: _confirmReset,
            icon: const Icon(Icons.delete_forever, size: 18),
            label: const Text('Reset Identity'),
            style: OutlinedButton.styleFrom(
              foregroundColor: AppColors.error,
              side: const BorderSide(color: AppColors.error),
            ),
          ),
        ],
      ),
    );
  }

  Widget _kv(String key, String value) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      SizedBox(
        width: 140,
        child: Text(key,
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: AppColors.textSecondary)),
      ),
      Expanded(
        child: Text(
          value,
          style: const TextStyle(fontSize: 13, fontFamily: 'monospace', color: AppColors.textPrimary),
        ),
      ),
    ],
  );
}
