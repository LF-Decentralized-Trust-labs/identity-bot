enum ActivityType { contactAdded, identityCreated, credentialIssued, keyRotation, oobiShared }

class ActivityLogEntry {
  final String id;
  final String message;
  final ActivityType type;
  final DateTime timestamp;

  const ActivityLogEntry({
    required this.id,
    required this.message,
    required this.type,
    required this.timestamp,
  });

  static List<ActivityLogEntry> dummyEntries() {
    final now = DateTime.now();
    return [
      ActivityLogEntry(
        id: '1',
        message: 'Identity agent initialized',
        type: ActivityType.identityCreated,
        timestamp: now.subtract(const Duration(days: 2)),
      ),
      ActivityLogEntry(
        id: '2',
        message: 'OOBI shared via QR code',
        type: ActivityType.oobiShared,
        timestamp: now.subtract(const Duration(days: 1, hours: 5)),
      ),
      ActivityLogEntry(
        id: '3',
        message: 'New contact added: Alice',
        type: ActivityType.contactAdded,
        timestamp: now.subtract(const Duration(hours: 12)),
      ),
      ActivityLogEntry(
        id: '4',
        message: 'Key rotation completed',
        type: ActivityType.keyRotation,
        timestamp: now.subtract(const Duration(hours: 3)),
      ),
      ActivityLogEntry(
        id: '5',
        message: 'Credential issued to Bob',
        type: ActivityType.credentialIssued,
        timestamp: now.subtract(const Duration(hours: 1)),
      ),
    ];
  }
}
