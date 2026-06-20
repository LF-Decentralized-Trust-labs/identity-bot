import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';

/// Minimal UI for a backup-only device (SCR1). No sidebar, no dashboard.
class BackupOnlyStandbyScreen extends StatelessWidget {
  final String? pairedIdentityAlias;
  final String? lastBackupReceived;
  final String connectionStatus;

  const BackupOnlyStandbyScreen({
    super.key,
    this.pairedIdentityAlias,
    this.lastBackupReceived,
    this.connectionStatus = 'waiting',
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.archive_outlined, color: AppColors.accent, size: 56),
                  const SizedBox(height: 24),
                  const Text(
                    'BACKUP STANDBY',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 20,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 2,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    pairedIdentityAlias ?? 'Awaiting pairing',
                    style: const TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace'),
                  ),
                  const SizedBox(height: 24),
                  _row('Connection', connectionStatus),
                  _row('Last backup', lastBackupReceived ?? 'None yet'),
                  const SizedBox(height: 32),
                  const Text(
                    'This device stores encrypted archives only. It cannot decrypt or sign.',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: AppColors.textMuted, fontSize: 12, fontFamily: 'monospace'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _row(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: AppColors.textMuted, fontFamily: 'monospace')),
          Text(value, style: const TextStyle(color: AppColors.textPrimary, fontFamily: 'monospace')),
        ],
      ),
    );
  }
}