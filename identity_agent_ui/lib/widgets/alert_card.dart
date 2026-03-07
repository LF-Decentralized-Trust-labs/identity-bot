import 'dart:convert';
import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';

enum AlertCardType { connectionRequest, pendingRequest }

class AlertCard extends StatelessWidget {
  final String displayName;
  final String aid;
  final AlertCardType type;
  final String? subtitle;
  final String photo;
  final VoidCallback? onApprove;
  final VoidCallback? onDeny;
  final VoidCallback? onDismiss;
  final VoidCallback? onTap;

  const AlertCard({
    super.key,
    required this.displayName,
    required this.aid,
    required this.type,
    this.subtitle,
    this.photo = '',
    this.onApprove,
    this.onDeny,
    this.onDismiss,
    this.onTap,
  });

  String _getInitials() {
    final parts = displayName.split(' ').where((w) => w.isNotEmpty).take(2);
    if (parts.isEmpty) return '?';
    return parts.map((w) => w[0].toUpperCase()).join();
  }

  Widget _buildAvatar() {
    if (photo.isNotEmpty) {
      try {
        final photoData = photo.contains(',') ? photo.split(',').last : photo;
        return CircleAvatar(
          radius: 20,
          backgroundImage: MemoryImage(base64Decode(photoData)),
        );
      } catch (_) {}
    }
    return CircleAvatar(
      radius: 20,
      backgroundColor: type == AlertCardType.connectionRequest
          ? MobileColors.primary.withOpacity(0.12)
          : MobileColors.warning.withOpacity(0.12),
      child: Text(
        _getInitials(),
        style: TextStyle(
          color: type == AlertCardType.connectionRequest
              ? MobileColors.primary
              : MobileColors.warning,
          fontWeight: FontWeight.w700,
          fontSize: 14,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: MobileColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: MobileColors.border),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  type == AlertCardType.connectionRequest
                      ? Icons.person_add
                      : Icons.hourglass_top,
                  color: type == AlertCardType.connectionRequest
                      ? MobileColors.primary
                      : MobileColors.warning,
                  size: 16,
                ),
                const SizedBox(width: 6),
                Text(
                  type == AlertCardType.connectionRequest
                      ? 'Connection Request'
                      : 'Pending Request',
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: MobileColors.textMuted,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                _buildAvatar(),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        type == AlertCardType.connectionRequest
                            ? '$displayName wants to add you as a contact'
                            : displayName,
                        style: const TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                          color: MobileColors.textPrimary,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        aid.length > 24 ? '${aid.substring(0, 24)}...' : aid,
                        style: const TextStyle(
                          fontSize: 11,
                          color: MobileColors.textMuted,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            if (subtitle != null && subtitle!.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(
                subtitle!,
                style: const TextStyle(fontSize: 12, color: MobileColors.textMuted),
              ),
            ],
            const SizedBox(height: 12),
            if (type == AlertCardType.connectionRequest)
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: onDeny,
                      style: OutlinedButton.styleFrom(
                        foregroundColor: MobileColors.error,
                        side: const BorderSide(color: MobileColors.error),
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                      child: const Text('Deny', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: onApprove,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: MobileColors.success,
                        foregroundColor: MobileColors.textOnPrimary,
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                      child: const Text('Approve', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                    ),
                  ),
                ],
              ),
            if (type == AlertCardType.pendingRequest)
              SizedBox(
                width: double.infinity,
                child: OutlinedButton(
                  onPressed: onDismiss,
                  style: OutlinedButton.styleFrom(
                    foregroundColor: MobileColors.textSecondary,
                    side: const BorderSide(color: MobileColors.border),
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  child: const Text('Dismiss', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
