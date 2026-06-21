import 'package:flutter/material.dart';
import '../../services/backup_service.dart';
import '../../services/secure_key_store.dart';
import '../../theme/app_theme.dart';
class BackupSettingsScreen extends StatefulWidget {
  const BackupSettingsScreen({super.key});

  @override
  State<BackupSettingsScreen> createState() => _BackupSettingsScreenState();
}

class _BackupSettingsScreenState extends State<BackupSettingsScreen> {
  BackupStatus? _status;
  BackupConfig? _config;
  bool _loading = true;
  String? _error;
  bool _exporting = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final status = await BackupService.getStatus();
      final config = await BackupService.getConfig();
      setState(() {
        _status = status;
        _config = config;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Color _healthColor(String health) {
    switch (health) {
      case 'green':
        return AppColors.success;
      case 'yellow':
        return AppColors.warning;
      default:
        return AppColors.error;
    }
  }

  Future<void> _toggleEnabled(bool value) async {
    final cfg = _config!;
    cfg.enabled = value;
    await BackupService.saveConfig(cfg);
    await _load();
  }

  Future<void> _exportBackup() async {
    final words = await SecureKeyStore.loadMnemonic();
    if (words == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No seed phrase available on this device')),
      );
      return;
    }
    setState(() => _exporting = true);
    try {
      final result = await BackupService.exportNow(
        mnemonic: words.join(' '),
        tiers: _config?.defaultTiers,
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Backup saved (${result['size_bytes']} bytes)')),
        );
      }
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Export failed: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _exporting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: AppColors.accent));
    }
    if (_error != null) {
      return Center(
        child: Text(_error!, style: const TextStyle(color: AppColors.error, fontFamily: 'monospace')),
      );
    }

    final status = _status!;
    final config = _config!;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 720),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text(
                  'BACKUP & RECOVERY',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 2,
                    fontFamily: 'monospace',
                  ),
                ),
                const Spacer(),
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                    color: _healthColor(status.health),
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  status.health.toUpperCase(),
                  style: TextStyle(color: _healthColor(status.health), fontFamily: 'monospace'),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              status.lastBackupAt != null
                  ? 'Last backup: ${status.lastBackupAt}'
                  : 'No backups yet — backup is off until you set it up.',
              style: const TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace'),
            ),
            if (status.redundancyWarning != null && status.redundancyWarning!.isNotEmpty) ...[
              const SizedBox(height: 16),
              _banner(status.redundancyWarning!, AppColors.warning),
            ],
            if (status.antiDeadlockWarning != null && status.antiDeadlockWarning!.isNotEmpty) ...[
              const SizedBox(height: 12),
              _banner(status.antiDeadlockWarning!, AppColors.error),
            ],
            const SizedBox(height: 24),
            SwitchListTile(
              title: const Text('Enable automated backup', style: TextStyle(fontFamily: 'monospace')),
              subtitle: const Text(
                'Off by default until you configure destinations.',
                style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 12),
              ),
              value: config.enabled,
              activeColor: AppColors.accent,
              onChanged: _toggleEnabled,
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _exporting ? null : _exportBackup,
              icon: _exporting
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.download_outlined),
              label: Text(_exporting ? 'EXPORTING...' : 'EXPORT BACKUP NOW'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: AppColors.background,
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
              ),
            ),
            const SizedBox(height: 32),
            const Text(
              'DESTINATIONS',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 12,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 12),
            if (status.destinations.isEmpty)
              const Text(
                'No destinations configured. Add Backup Location 1 and 2 in the setup wizard.',
                style: TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace'),
              )
            else
              ...status.destinations.map((d) => ListTile(
                    title: Text(d.label, style: const TextStyle(fontFamily: 'monospace')),
                    subtitle: Text('${d.type}${d.enabled ? '' : ' (disabled)'}',
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                    trailing: d.lastError != null
                        ? const Icon(Icons.error_outline, color: AppColors.error)
                        : const Icon(Icons.check_circle_outline, color: AppColors.success),
                  )),
          ],
        ),
      ),
    );
  }

  Widget _banner(String text, Color color) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        border: Border.all(color: color.withOpacity(0.4)),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(text, style: TextStyle(color: color, fontFamily: 'monospace', fontSize: 13)),
    );
  }
}