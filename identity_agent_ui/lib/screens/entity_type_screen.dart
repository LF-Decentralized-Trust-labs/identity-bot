import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import '../services/preferences_service.dart';

class EntityTypeScreen extends StatelessWidget {
  final void Function(EntityType type) onEntityTypeSelected;
  final VoidCallback onBack;

  const EntityTypeScreen({
    super.key,
    required this.onEntityTypeSelected,
    required this.onBack,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Text(
                    'IDENTITY TYPE',
                    style: TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Who is this identity for?',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 20,
                      fontWeight: FontWeight.w700,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'This determines how your identity is structured. '
                    'You can always create additional identities later.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      height: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 36),
                  _buildTypeCard(
                    icon: Icons.person_outline,
                    title: 'INDIVIDUAL',
                    description:
                        'A personal digital identity for a single human. '
                        'Ideal for personal use, self-sovereign credentials, '
                        'and individual communications.',
                    onTap: () => onEntityTypeSelected(EntityType.individual),
                  ),
                  const SizedBox(height: 16),
                  _buildTypeCard(
                    icon: Icons.business_outlined,
                    title: 'ORGANIZATION',
                    description:
                        'An identity representing a group, company, or '
                        'institution. Supports multi-signature governance '
                        'and delegated authority structures.',
                    onTap: () => onEntityTypeSelected(EntityType.organization),
                  ),
                  const SizedBox(height: 32),
                  TextButton(
                    onPressed: onBack,
                    child: const Text(
                      'GO BACK',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 12,
                        fontWeight: FontWeight.w500,
                        letterSpacing: 1.0,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildTypeCard({
    required IconData icon,
    required String title,
    required String description,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppColors.border, width: 1),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    color: AppColors.accent.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(14),
                  ),
                  child: Icon(icon, color: AppColors.accent, size: 28),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 15,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
                const Icon(
                  Icons.chevron_right,
                  color: AppColors.textMuted,
                  size: 24,
                ),
              ],
            ),
            const SizedBox(height: 14),
            Text(
              description,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                height: 1.6,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ),
      ),
    );
  }
}
