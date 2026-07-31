import 'dart:convert';
import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';

/// What kind of thing this card is showing.
///
/// Every switch on this enum below is exhaustive, with no wildcard arm. That is
/// deliberate: the arms used to end in `_ =>`, so adding a case here compiled
/// clean and silently rendered as "Pending Request" in four places at once.
/// Exhaustive switches turn that into a compile error, which is where it
/// belongs.
enum AlertCardType {
  connectionRequest,
  pendingRequest,
  credentialIncoming,

  /// Something another agent said. Not a request for approval — there may be
  /// nothing to approve — so it carries no accept or deny.
  notification,

  /// A notification the sender marked critical: a deadline, or something about
  /// to stop working. Separate from [notification] because "for your
  /// information" and "this ends on Friday" should not look the same.
  notificationCritical,
}

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
    final Color avatarColor = switch (type) {
      AlertCardType.connectionRequest     => MobileColors.primary,
      AlertCardType.credentialIncoming    => MobileColors.success,
      AlertCardType.pendingRequest        => MobileColors.warning,
      AlertCardType.notification          => MobileColors.primary,
      AlertCardType.notificationCritical  => MobileColors.error,
    };
    return CircleAvatar(
      radius: 20,
      backgroundColor: avatarColor.withOpacity(0.12),
      child: Text(
        _getInitials(),
        style: TextStyle(
          color: avatarColor,
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
                  switch (type) {
                    AlertCardType.connectionRequest     => Icons.person_add,
                    AlertCardType.credentialIncoming    => Icons.verified_outlined,
                    AlertCardType.pendingRequest        => Icons.hourglass_top,
                    AlertCardType.notification          => Icons.notifications_outlined,
                    AlertCardType.notificationCritical  => Icons.warning_amber_rounded,
                  },
                  color: switch (type) {
                    AlertCardType.connectionRequest     => MobileColors.primary,
                    AlertCardType.credentialIncoming    => MobileColors.success,
                    AlertCardType.pendingRequest        => MobileColors.warning,
                    AlertCardType.notification          => MobileColors.primary,
                    AlertCardType.notificationCritical  => MobileColors.error,
                  },
                  size: 16,
                ),
                const SizedBox(width: 6),
                Text(
                  switch (type) {
                    AlertCardType.connectionRequest     => 'Connection Request',
                    AlertCardType.credentialIncoming    => 'Incoming Credential',
                    AlertCardType.pendingRequest        => 'Pending Request',
                    AlertCardType.notification          => 'Notification',
                    AlertCardType.notificationCritical  => 'Needs Attention',
                  },
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
                            : type == AlertCardType.credentialIncoming
                                ? '$displayName has issued you a credential'
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
            if (type == AlertCardType.credentialIncoming)
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: onDeny,
                      style: OutlinedButton.styleFrom(
                        foregroundColor: MobileColors.error,
                        side: const BorderSide(color: MobileColors.error),
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      ),
                      child: const Text('Reject', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
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
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      ),
                      child: const Text('Accept', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
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
