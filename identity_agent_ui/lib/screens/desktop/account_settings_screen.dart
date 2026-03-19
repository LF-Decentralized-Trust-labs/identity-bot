import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/preferences_service.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

class AccountSettingsScreen extends StatefulWidget {
  final AgentMode? mode;
  final EntityType? entityType;
  final String? serverUrl;
  final VoidCallback? onResetIdentity;

  const AccountSettingsScreen({
    super.key,
    this.mode,
    this.entityType,
    this.serverUrl,
    this.onResetIdentity,
  });

  @override
  State<AccountSettingsScreen> createState() => _AccountSettingsScreenState();
}

class _AccountSettingsScreenState extends State<AccountSettingsScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  IdentityResponse? _identity;
  bool _loading = true;

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
    try {
      final id = await _coreService.getIdentity();
      setState(() { _identity = id; _loading = false; });
    } catch (_) {
      setState(() { _loading = false; });
    }
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
      await PreferencesService.clearAll();
      widget.onResetIdentity?.call();
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Account', style: Theme.of(context).textTheme.headlineMedium),
                  const SizedBox(height: 4),
                  Text('Identity and agent configuration.', style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
                  const SizedBox(height: 32),
                  _buildInfoCard(context),
                  const SizedBox(height: 24),
                  _buildDangerCard(context),
                ],
              ),
            ),
    );
  }

  Widget _buildInfoCard(BuildContext context) {
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
          Text('Identity Info', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
          const SizedBox(height: 16),
          _row('Agent Mode', widget.mode != null ? PreferencesService.modeDisplayName(widget.mode!) : '—'),
          const Divider(height: 24),
          _row('Identity Type', widget.entityType != null ? PreferencesService.entityTypeDisplayName(widget.entityType!) : '—'),
          const Divider(height: 24),
          _row('AID', _identity?.aid ?? '—'),
          const Divider(height: 24),
          _row('Events', '${_identity?.eventCount ?? 0}'),
          const Divider(height: 24),
          _row('Status', _identity?.initialized == true ? 'Initialized' : 'Not initialized'),
        ],
      ),
    );
  }

  Widget _row(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 140,
          child: Text(label, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: AppColors.textSecondary)),
        ),
        Expanded(
          child: Text(
            value.length > 72 ? '${value.substring(0, 72)}…' : value,
            style: const TextStyle(fontSize: 13, color: AppColors.textPrimary, fontFamily: 'monospace'),
          ),
        ),
      ],
    );
  }

  Widget _buildDangerCard(BuildContext context) {
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
              Icon(Icons.warning_amber_rounded, color: AppColors.error, size: 20),
              const SizedBox(width: 8),
              Text('Danger Zone', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600, color: AppColors.textPrimary)),
            ],
          ),
          const SizedBox(height: 12),
          Text(
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
              side: BorderSide(color: AppColors.error),
            ),
          ),
        ],
      ),
    );
  }
}
