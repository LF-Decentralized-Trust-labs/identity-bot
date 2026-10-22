import 'package:test/test.dart';
import 'package:agent_client/services/backend_process_service.dart';

/// A product names the relays its backend is reached through; whoever runs
/// the app can still name others.
void main() {
  tearDown(() => BackendProcessService.environmentDefaults = const {});

  test('a default reaches the backend when the environment has none', () {
    BackendProcessService.environmentDefaults = {'RELAY_BASE_URL': 'https://relay.example.org'};
    final env = BackendProcessService.withEnvironmentDefaults({'HOME': '/h'});
    expect(env['RELAY_BASE_URL'], 'https://relay.example.org');
    expect(env['HOME'], '/h');
  });

  test('the environment wins over the default', () {
    BackendProcessService.environmentDefaults = {'RELAY_BASE_URL': 'https://relay.example.org'};
    final env = BackendProcessService.withEnvironmentDefaults({'RELAY_BASE_URL': 'https://mine.example.net'});
    expect(env['RELAY_BASE_URL'], 'https://mine.example.net');
  });

  test('an empty value in the environment counts as unset', () {
    BackendProcessService.environmentDefaults = {'RELAY_BASE_URL': 'https://relay.example.org'};
    final env = BackendProcessService.withEnvironmentDefaults({'RELAY_BASE_URL': ' '});
    expect(env['RELAY_BASE_URL'], 'https://relay.example.org');
  });
}
