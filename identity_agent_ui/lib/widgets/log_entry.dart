import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

enum LogLevel { info, success, warning, error }

class LogEntry {
  final String message;
  final String timestamp;
  final LogLevel level;

  LogEntry({
    required this.message,
    required this.timestamp,
    required this.level,
  });

  Color get color {
    switch (level) {
      case LogLevel.info:
        return AppColors.textSecondary;
      case LogLevel.success:
        return AppColors.coreActive;
      case LogLevel.warning:
        return AppColors.corePending;
      case LogLevel.error:
        return AppColors.coreInactive;
    }
  }

  String get prefix {
    switch (level) {
      case LogLevel.info:
        return 'INFO';
      case LogLevel.success:
        return ' OK ';
      case LogLevel.warning:
        return 'WARN';
      case LogLevel.error:
        return 'ERR ';
    }
  }
}

class LogEntryWidget extends StatelessWidget {
  final LogEntry entry;

  const LogEntryWidget({super.key, required this.entry});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            entry.timestamp,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
            decoration: BoxDecoration(
              color: entry.color.withOpacity(0.15),
              borderRadius: BorderRadius.circular(3),
            ),
            child: Text(
              entry.prefix,
              style: TextStyle(
                color: entry.color,
                fontSize: 10,
                fontWeight: FontWeight.w700,
                fontFamily: 'monospace',
                letterSpacing: 0.5,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              entry.message,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                fontFamily: 'monospace',
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
