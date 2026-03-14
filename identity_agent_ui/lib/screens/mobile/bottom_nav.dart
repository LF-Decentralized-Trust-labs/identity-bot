import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';

class MobileBottomNav extends StatelessWidget {
  final VoidCallback onShare;
  final VoidCallback onScan;
  final VoidCallback onChatbot;

  const MobileBottomNav({
    super.key,
    required this.onShare,
    required this.onScan,
    required this.onChatbot,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: MobileColors.bottomNavBackground,
        boxShadow: [
          BoxShadow(
            color: MobileColors.cardShadow,
            blurRadius: 8,
            offset: Offset(0, -2),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: [
              _NavButton(
                icon: Icons.share_outlined,
                label: 'Share',
                onTap: onShare,
              ),
              _CenterButton(
                icon: Icons.chat_bubble_outline,
                label: 'Chat',
                onTap: onChatbot,
              ),
              _NavButton(
                icon: Icons.qr_code_scanner,
                label: 'Scan',
                onTap: onScan,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _NavButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _NavButton({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: MobileColors.textSecondary, size: 24),
            const SizedBox(height: 4),
            Text(
              label,
              style: const TextStyle(
                fontSize: 11,
                color: MobileColors.textSecondary,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CenterButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _CenterButton({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 64,
        height: 64,
        decoration: BoxDecoration(
          color: MobileColors.primary,
          shape: BoxShape.circle,
          boxShadow: [
            BoxShadow(
              color: MobileColors.primary.withOpacity(0.3),
              blurRadius: 12,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, color: MobileColors.textOnPrimary, size: 24),
            Text(
              label,
              style: const TextStyle(
                color: MobileColors.textOnPrimary,
                fontSize: 9,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
