import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/preferences_service.dart';

class MobileEntityTypeScreen extends StatelessWidget {
  final void Function(EntityType type) onEntityTypeSelected;
  final VoidCallback onBack;

  const MobileEntityTypeScreen({
    super.key,
    required this.onEntityTypeSelected,
    required this.onBack,
  });

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        body: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 480),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      'Identity Type',
                      style: TextStyle(
                        color: MobileColors.textMuted,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        letterSpacing: 0.5,
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Who is this identity for?',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: MobileColors.textPrimary,
                        fontSize: 22,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'This determines how your identity is structured. '
                      'You can always create additional identities later.',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: MobileColors.textSecondary,
                        fontSize: 14,
                        height: 1.5,
                      ),
                    ),
                    const SizedBox(height: 36),
                    _buildTypeCard(
                      icon: Icons.person_outline,
                      title: 'Individual',
                      description:
                          'A personal digital identity for a single human. '
                          'Ideal for personal use, self-sovereign credentials, '
                          'and individual communications.',
                      onTap: () => onEntityTypeSelected(EntityType.individual),
                    ),
                    const SizedBox(height: 16),
                    _buildTypeCard(
                      icon: Icons.business_outlined,
                      title: 'Organization',
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
                        'Go Back',
                        style: TextStyle(
                          color: MobileColors.textMuted,
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  ],
                ),
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
          color: MobileColors.surface,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: MobileColors.border, width: 1),
          boxShadow: [
            BoxShadow(
              color: MobileColors.cardShadow,
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
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
                    color: MobileColors.primary.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(14),
                  ),
                  child: Icon(icon, color: MobileColors.primary, size: 28),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(
                      color: MobileColors.textPrimary,
                      fontSize: 17,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                const Icon(
                  Icons.chevron_right,
                  color: MobileColors.textMuted,
                  size: 24,
                ),
              ],
            ),
            const SizedBox(height: 14),
            Text(
              description,
              style: const TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 13,
                height: 1.6,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
