import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/preferences_service.dart';

class MobileModeSelectionScreen extends StatelessWidget {
  final void Function(AgentMode mode) onModeSelected;

  const MobileModeSelectionScreen({super.key, required this.onModeSelected});

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
                    Container(
                      width: 80,
                      height: 80,
                      decoration: BoxDecoration(
                        color: MobileColors.primary.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                          color: MobileColors.primary.withOpacity(0.3),
                          width: 1.5,
                        ),
                      ),
                      child: const Icon(
                        Icons.shield_outlined,
                        color: MobileColors.primary,
                        size: 40,
                      ),
                    ),
                    const SizedBox(height: 32),
                    const Text(
                      'Identity Agent',
                      style: TextStyle(
                        color: MobileColors.textPrimary,
                        fontSize: 26,
                        fontWeight: FontWeight.w700,
                        letterSpacing: -0.5,
                      ),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Setup',
                      style: TextStyle(
                        color: MobileColors.primary,
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'How would you like to get started?',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: MobileColors.textSecondary,
                        fontSize: 15,
                        height: 1.5,
                      ),
                    ),
                    const SizedBox(height: 36),
                    _buildModeCard(
                      icon: Icons.add_circle_outline,
                      title: 'Create New Identity',
                      description:
                          'Set up a brand new digital identity on this device. '
                          'You will generate a secure seed phrase and create your '
                          'root identity from scratch.',
                      badge: 'Recommended',
                      onTap: () => onModeSelected(AgentMode.createNew),
                    ),
                    const SizedBox(height: 16),
                    _buildModeCard(
                      icon: Icons.link,
                      title: 'Connect to Existing Identity',
                      description:
                          'Connect this device to an identity that is already '
                          'running on another server or device. You will need '
                          'the server URL.',
                      onTap: () => onModeSelected(AgentMode.connectExisting),
                    ),
                    const SizedBox(height: 32),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildModeCard({
    required IconData icon,
    required String title,
    required String description,
    String? badge,
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
          border: Border.all(
            color: badge != null
                ? MobileColors.primary.withOpacity(0.3)
                : MobileColors.border,
            width: 1,
          ),
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
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: MobileColors.primary.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(icon, color: MobileColors.primary, size: 24),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: const TextStyle(
                          color: MobileColors.textPrimary,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (badge != null) ...[
                        const SizedBox(height: 4),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 2),
                          decoration: BoxDecoration(
                            color: MobileColors.primary.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            badge,
                            style: const TextStyle(
                              color: MobileColors.primary,
                              fontSize: 11,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ],
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
