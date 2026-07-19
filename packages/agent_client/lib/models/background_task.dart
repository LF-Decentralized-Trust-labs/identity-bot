enum TaskStatus { inProgress, completed, failed }

class BackgroundTask {
  final String id;
  final String title;
  final String description;
  final TaskStatus status;
  final double progress;
  final DateTime createdAt;

  const BackgroundTask({
    required this.id,
    required this.title,
    required this.description,
    required this.status,
    this.progress = 0.0,
    required this.createdAt,
  });

  static List<BackgroundTask> dummyTasks() {
    final now = DateTime.now();
    return [
      BackgroundTask(
        id: '1',
        title: 'KEL Synchronization',
        description: 'Syncing key event log with witnesses',
        status: TaskStatus.inProgress,
        progress: 0.65,
        createdAt: now.subtract(const Duration(minutes: 5)),
      ),
      BackgroundTask(
        id: '2',
        title: 'Credential Verification',
        description: 'Verifying credential schema',
        status: TaskStatus.completed,
        progress: 1.0,
        createdAt: now.subtract(const Duration(hours: 1)),
      ),
      BackgroundTask(
        id: '3',
        title: 'Backup Identity',
        description: 'Creating encrypted backup',
        status: TaskStatus.completed,
        progress: 1.0,
        createdAt: now.subtract(const Duration(hours: 3)),
      ),
    ];
  }
}
