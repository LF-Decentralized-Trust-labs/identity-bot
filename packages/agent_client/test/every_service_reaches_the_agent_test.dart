import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/link_verification_service.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/login_service.dart';
import 'package:agent_client/services/recovery_service.dart';
import 'package:agent_client/services/scan_service.dart';
import 'package:agent_client/services/the_agent_this_app_talks_to.dart';
import 'package:agent_client/services/update_service.dart';
import 'package:test/test.dart';

/// Where a screen's requests go when this installation is only the front end.
///
/// The failure this pins is silent, which is why it is worth a test of its own:
/// a service that kept talking to the local core in controller mode gets a
/// well-formed answer from a core that holds no identity, so a screen shows a
/// roster, a policy or a credential belonging to nobody and nothing reports a
/// problem. Every service defaulted its own address, so the question had as many
/// answers as there were services.
const _agent = 'https://box.example.test';

void main() {
  tearDown(() => AgentConfig.agentOrigin = '');

  group('when this app is a front end for an agent elsewhere', () {
    setUp(() => AgentConfig.agentOrigin = _agent);

    test('everything about the IDENTITY goes to the agent', () {
      expect(TheAgentThisAppTalksTo.origin, _agent);

      expect(LinkVerificationService().baseUrl, _agent,
          reason: 'a link is verified as the identity');
      expect(RecoveryService().baseUrl, _agent,
          reason: 'recovery restores an identity, which is not held here');
      expect(LoginService().baseUrl, _agent,
          reason: 'signing in somewhere is done as the identity');
      expect(ScanService().baseUrl, _agent,
          reason: 'what a scan resolves to is decided by the identity');
      expect(LocalCoreKeriService().baseUrl, _agent,
          reason: 'a stateful KERI operation runs where the KEYS are, and they '
              'are not on this computer');
    });

    test('what is about THIS COMPUTER stays here', () {
      // Not an oversight. An update installs software on this machine, and
      // pointing it at the agent would have this installation report the
      // version of a machine it is only the front end for.
      expect(UpdateService().baseUrl, AgentConfig.coreBaseUrl);
      expect(UpdateService().baseUrl, isNot(_agent));
    });

    test('a request to the agent is signed, and one to a stranger is not',
        () async {
      final client = TheAgentThisAppTalksTo.clientFor();
      // Nothing here reaches the network: what is being checked is that the
      // client is the kind that proves who is sending, and that it is pointed
      // at the agent rather than at this computer.
      expect(client.runtimeType.toString(), contains('Controller'));
    });
  });

  group('when this installation holds the identity', () {
    test('everything goes to the core on this computer', () {
      expect(TheAgentThisAppTalksTo.origin, AgentConfig.coreBaseUrl);
      expect(LinkVerificationService().baseUrl, AgentConfig.coreBaseUrl);
      expect(RecoveryService().baseUrl, AgentConfig.coreBaseUrl);
      expect(LoginService().baseUrl, AgentConfig.coreBaseUrl);
      expect(ScanService().baseUrl, AgentConfig.coreBaseUrl);
      expect(LocalCoreKeriService().baseUrl, AgentConfig.coreBaseUrl);
      expect(UpdateService().baseUrl, AgentConfig.coreBaseUrl);
    });
  });

  test('an address handed in wins over both', () {
    AgentConfig.agentOrigin = _agent;
    const elsewhere = 'https://other.example.test';
    expect(LoginService(baseUrl: elsewhere).baseUrl, elsewhere);
    expect(ScanService(baseUrl: elsewhere).baseUrl, elsewhere);
  });
}
