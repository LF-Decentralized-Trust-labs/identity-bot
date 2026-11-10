import 'dart:convert';

import 'package:agent_client/services/backup_service.dart';
import 'package:test/test.dart';

void main() {
  test('a destination keeps which cloud provider it is', () {
    final d = BackupDestination.fromJson({
      'id': 'google-drive',
      'type': 'cloud_user_managed',
      'label': 'Google Drive',
      'cloud_provider': 'google_drive',
    });
    expect(d.cloudProvider, 'google_drive');
  });

  test('the core answer for a build with no client is recognised', () {
    final body = jsonEncode({
      'error': 'Cannot start Google sign-in',
      'details':
          'Google Drive backup is not set up in this build: no Google OAuth client id (IDENTITY_GOOGLE_OAUTH_CLIENT_ID)'
    });
    final why = (jsonDecode(body) as Map)['details'] as String;
    expect(why.contains(GoogleDriveNotSetUp.marker), isTrue);
  });
}
