import 'package:flutter/material.dart';
import '../../services/backup_service.dart';
import '../../theme/app_theme.dart';

/// Onboarding wizard step: Set Up Backup (SCR6).
class BackupSetupWizardScreen extends StatefulWidget {
  final VoidCallback onComplete;
  final VoidCallback onDefer;

  const BackupSetupWizardScreen({
    super.key,
    required this.onComplete,
    required this.onDefer,
  });

  @override
  State<BackupSetupWizardScreen> createState() => _BackupSetupWizardScreenState();
}

class _BackupSetupWizardScreenState extends State<BackupSetupWizardScreen> {
  final _loc1Controller = TextEditingController();
  final _loc2Controller = TextEditingController();
  String _preset = 'seed';

  @override
  void dispose() {
    _loc1Controller.dispose();
    _loc2Controller.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final config = await BackupService.getConfig();
    config.enabled = true;
    config.recoveryPreset = _preset;
    config.destinations = [];
    if (_loc1Controller.text.trim().isNotEmpty) {
      config.destinations.add(BackupDestination(
        id: 'loc1',
        type: 'local_path',
        label: 'Backup Location 1',
        localPath: _loc1Controller.text.trim(),
        iaGated: false,
      ));
    }
    if (_loc2Controller.text.trim().isNotEmpty) {
      config.destinations.add(BackupDestination(
        id: 'loc2',
        type: 'local_path',
        label: 'Backup Location 2',
        localPath: _loc2Controller.text.trim(),
        iaGated: false,
      ));
    }
    await BackupService.saveConfig(config);
    widget.onComplete();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text(
                  'SET UP BACKUP',
                  style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 20,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 2,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppColors.accent.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.accent.withOpacity(0.3)),
                  ),
                  child: const Text(
                    'Recommend ≥2 destinations on different devices. Ideal: 3. '
                    'Keep ≥1 copy on hardware you own (anti-deadlock).',
                    style: TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace', fontSize: 13),
                  ),
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: _loc1Controller,
                  decoration: const InputDecoration(
                    labelText: 'Backup Location 1 (local path)',
                    labelStyle: TextStyle(fontFamily: 'monospace'),
                  ),
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: _loc2Controller,
                  decoration: const InputDecoration(
                    labelText: 'Backup Location 2 (optional)',
                    labelStyle: TextStyle(fontFamily: 'monospace'),
                  ),
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
                const SizedBox(height: 24),
                const Text('Recovery preset', style: TextStyle(fontFamily: 'monospace', color: AppColors.textMuted)),
                RadioListTile<String>(
                  title: const Text('Seed only (default)', style: TextStyle(fontFamily: 'monospace')),
                  value: 'seed',
                  groupValue: _preset,
                  onChanged: (v) => setState(() => _preset = v!),
                ),
                RadioListTile<String>(
                  title: const Text('Seed + guardians (OR) — recommended', style: TextStyle(fontFamily: 'monospace')),
                  value: 'seed_guardians_or',
                  groupValue: _preset,
                  onChanged: (v) => setState(() => _preset = v!),
                ),
                const SizedBox(height: 32),
                ElevatedButton(
                  onPressed: _save,
                  style: ElevatedButton.styleFrom(backgroundColor: AppColors.accent),
                  child: const Text('ENABLE BACKUP', style: TextStyle(fontFamily: 'monospace')),
                ),
                TextButton(
                  onPressed: widget.onDefer,
                  child: const Text('Defer (with warning)', style: TextStyle(fontFamily: 'monospace')),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}