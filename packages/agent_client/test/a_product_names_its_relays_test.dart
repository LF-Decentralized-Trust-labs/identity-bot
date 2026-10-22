import 'package:test/test.dart';
import 'package:agent_client/services/backend_process_service.dart';
import 'package:agent_client/services/mobile_core_service.dart';

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

  // A phone app names its relays the same way, once: the native side hands
  // them to the core before it starts.
  test('a phone core is started with the same relays', () {
    BackendProcessService.environmentDefaults = {
      'RELAY_BASE_URL': 'https://relay.example.org',
      'PUBLIC_RELAY_BASE_URL': 'https://example.org',
    };
    final args = MobileCoreService.startArguments(dataDir: '/d');
    expect(args['privateRelay'], 'https://relay.example.org');
    expect(args['publicRelay'], 'https://example.org');
    expect(args['dataDir'], '/d');
  });

  test('a phone core with no relays named is given none', () {
    final args = MobileCoreService.startArguments();
    expect(args.containsKey('privateRelay'), isFalse);
    expect(args.containsKey('publicRelay'), isFalse);
  });
}
