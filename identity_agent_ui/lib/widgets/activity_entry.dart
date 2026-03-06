import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';
import '../models/activity_log_entry.dart';

class ActivityEntryWidget extends StatelessWidget {
  final ActivityLogEntry entry;

  const ActivityEntryWidget({super.key, required this.entry});

  IconData get _icon {
    switch (entry.type) {
      case ActivityType.contactAdded:
        return Icons.person_add;
      case ActivityType.identityCreated:
        return Icons.fingerprint;
      case ActivityType.credentialIssued:
        return Icons.verified;
      case ActivityType.keyRotation:
        return Icons.refresh;
      case ActivityType.oobiShared:
        return Icons.qr_code;
    }
  }

  Color get _iconColor {
    switch (entry.type) {
      case ActivityType.contactAdded:
        return MobileColors.primary;
      case ActivityType.identityCreated:
        return MobileColors.success;
      case ActivityType.credentialIssued:
        return MobileColors.info;
      case ActivityType.keyRotation:
        return MobileColors.warning;
      case ActivityType.oobiShared:
        return MobileColors.primary;
    }
  }

  String get _timeString {
    final now = DateTime.now();
    final diff = now.difference(entry.timestamp);

    if (diff.inMinutes < 1) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';

    return '${entry.timestamp.month}/${entry.timestamp.day}/${entry.timestamp.year}';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 3),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: MobileColors.borderLight),
      ),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: _iconColor.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(_icon, size: 18, color: _iconColor),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              entry.message,
              style: const TextStyle(
                fontSize: 14,
                color: MobileColors.textPrimary,
              ),
            ),
          ),
          Text(
            _timeString,
            style: const TextStyle(
              fontSize: 11,
              color: MobileColors.textMuted,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }
}
