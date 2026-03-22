import 'dart:convert';
import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';
import 'identity_level_badge.dart';

class IdentityCard extends StatelessWidget {
  final String displayName;
  final String agentUrl;
  final String? photoBase64;
  final VoidCallback? onBadgeTap;

  const IdentityCard({
    super.key,
    required this.displayName,
    required this.agentUrl,
    this.photoBase64,
    this.onBadgeTap,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(16),
        boxShadow: const [
          BoxShadow(
            color: MobileColors.cardShadow,
            blurRadius: 8,
            offset: Offset(0, 2),
          ),
        ],
      ),
      child: Row(
        children: [
          _buildAvatar(),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  displayName.isNotEmpty ? displayName : 'Identity Agent',
                  style: const TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    color: MobileColors.textPrimary,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 4),
                Text(
                  agentUrl.isNotEmpty ? agentUrl : 'No endpoint configured',
                  style: const TextStyle(
                    fontSize: 12,
                    color: MobileColors.textMuted,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          LiveIdentityLevelBadge(onTap: onBadgeTap),
        ],
      ),
    );
  }

  Widget _buildAvatar() {
    if (photoBase64 != null && photoBase64!.isNotEmpty) {
      try {
        final bytes = base64Decode(photoBase64!);
        return CircleAvatar(
          radius: 28,
          backgroundImage: MemoryImage(bytes),
        );
      } catch (_) {}
    }

    final initials = displayName.isNotEmpty
        ? displayName.split(' ').take(2).map((w) => w.isNotEmpty ? w[0].toUpperCase() : '').join()
        : 'IA';

    return CircleAvatar(
      radius: 28,
      backgroundColor: MobileColors.primary,
      child: Text(
        initials,
        style: const TextStyle(
          color: MobileColors.textOnPrimary,
          fontWeight: FontWeight.w600,
          fontSize: 16,
        ),
      ),
    );
  }
}
