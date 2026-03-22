import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';

class MobileComingSoonScreen extends StatelessWidget {
  final String title;
  final String? description;
  final IconData icon;

  const MobileComingSoonScreen({
    super.key,
    required this.title,
    this.description,
    this.icon = Icons.construction_outlined,
  });

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          backgroundColor: MobileColors.surface,
          foregroundColor: MobileColors.textPrimary,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back),
            onPressed: () => Navigator.of(context).pop(),
          ),
        ),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 80,
                  height: 80,
                  decoration: BoxDecoration(
                    color: MobileColors.primary.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Icon(icon, size: 40, color: MobileColors.primary),
                ),
                const SizedBox(height: 24),
                Text(
                  title,
                  style: const TextStyle(
                    color: MobileColors.textPrimary,
                    fontSize: 22,
                    fontWeight: FontWeight.w700,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 10),
                Text(
                  description ?? 'This feature is coming in a future update.',
                  style: const TextStyle(
                    color: MobileColors.textSecondary,
                    fontSize: 15,
                    height: 1.5,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  decoration: BoxDecoration(
                    color: MobileColors.primary.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                        color: MobileColors.primary.withOpacity(0.3)),
                  ),
                  child: const Text(
                    'Coming Soon',
                    style: TextStyle(
                      color: MobileColors.primary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
