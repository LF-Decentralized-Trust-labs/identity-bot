import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';

class ShareMenu extends StatelessWidget {
  const ShareMenu({super.key});

  void _showComingSoon(BuildContext context, String feature) {
    Navigator.of(context).pop();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Coming Soon'),
        content: Text('$feature will be available in a future update.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 8),
          Container(
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: MobileColors.surfaceTertiary,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Share',
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.w700,
              color: MobileColors.textPrimary,
            ),
          ),
          const SizedBox(height: 8),
          _ShareItem(
            icon: Icons.badge_outlined,
            label: 'Show ID',
            subtitle: 'Display your identity QR code',
            onTap: () => _showComingSoon(context, 'Show ID'),
          ),
          _ShareItem(
            icon: Icons.share_outlined,
            label: 'Share Contact Info',
            subtitle: 'Share your OOBI URL',
            onTap: () => _showComingSoon(context, 'Share Contact Info'),
          ),
          _ShareItem(
            icon: Icons.payment_outlined,
            label: 'Request Payment',
            subtitle: 'Send a payment request',
            onTap: () => _showComingSoon(context, 'Request Payment'),
          ),
          _ShareItem(
            icon: Icons.attach_file,
            label: 'Share a File',
            subtitle: 'Send an encrypted file',
            onTap: () => _showComingSoon(context, 'Share a File'),
          ),
          _ShareItem(
            icon: Icons.verified_outlined,
            label: 'Share Credential',
            subtitle: 'Present a verifiable credential',
            onTap: () => _showComingSoon(context, 'Share Credential'),
          ),
          SizedBox(height: MediaQuery.of(context).padding.bottom + 12),
        ],
      ),
    );
  }
}

class _ShareItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final String subtitle;
  final VoidCallback onTap;

  const _ShareItem({
    required this.icon,
    required this.label,
    required this.subtitle,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Container(
        width: 40,
        height: 40,
        decoration: BoxDecoration(
          color: MobileColors.primary.withOpacity(0.1),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(icon, color: MobileColors.primary, size: 22),
      ),
      title: Text(
        label,
        style: const TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w600,
          color: MobileColors.textPrimary,
        ),
      ),
      subtitle: Text(
        subtitle,
        style: const TextStyle(
          fontSize: 12,
          color: MobileColors.textMuted,
        ),
      ),
      trailing: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: MobileColors.surfaceTertiary,
          borderRadius: BorderRadius.circular(4),
        ),
        child: const Text(
          'Soon',
          style: TextStyle(
            fontSize: 10,
            color: MobileColors.textMuted,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      onTap: onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 2),
    );
  }
}
