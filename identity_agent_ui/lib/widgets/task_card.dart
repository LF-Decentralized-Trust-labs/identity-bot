import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';
import 'package:agent_client/models/background_task.dart';

class TaskCard extends StatelessWidget {
  final BackgroundTask task;

  const TaskCard({super.key, required this.task});

  @override
  Widget build(BuildContext context) {
    return Container(
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
              Expanded(
                child: Text(
                  task.title,
                  style: const TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                    color: MobileColors.textPrimary,
                  ),
                ),
              ),
              _buildStatusBadge(),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            task.description,
            style: const TextStyle(
              fontSize: 13,
              color: MobileColors.textSecondary,
            ),
          ),
          if (task.status == TaskStatus.inProgress) ...[
            const SizedBox(height: 10),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(
                value: task.progress,
                backgroundColor: MobileColors.borderLight,
                valueColor: const AlwaysStoppedAnimation<Color>(MobileColors.primary),
                minHeight: 6,
              ),
            ),
            const SizedBox(height: 4),
            Align(
              alignment: Alignment.centerRight,
              child: Text(
                '${(task.progress * 100).toInt()}%',
                style: const TextStyle(fontSize: 11, color: MobileColors.textMuted),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildStatusBadge() {
    Color color;
    String label;
    IconData icon;

    switch (task.status) {
      case TaskStatus.inProgress:
        color = MobileColors.primary;
        label = 'In Progress';
        icon = Icons.sync;
        break;
      case TaskStatus.completed:
        color = MobileColors.success;
        label = 'Completed';
        icon = Icons.check_circle;
        break;
      case TaskStatus.failed:
        color = MobileColors.error;
        label = 'Failed';
        icon = Icons.error;
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: color,
            ),
          ),
        ],
      ),
    );
  }
}
