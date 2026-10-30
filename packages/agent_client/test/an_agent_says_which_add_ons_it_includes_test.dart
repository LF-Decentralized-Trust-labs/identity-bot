import 'package:agent_client/services/agent_add_ons.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:test/test.dart';

CoreInfoResponse info(Map<String, dynamic> json) => CoreInfoResponse.fromJson({
      'name': 'Identity Agent Core',
      'capabilities': <String>[],
      ...json,
    });

void main() {
  setUp(AgentAddOns.forgetAll);

  test('an agent that names its add-ons has those and no others', () async {
    final got = await AgentAddOns.at('http://one',
        ask: () async => info({'add_ons': ['sandboxed_apps']}));
    expect(got.hasSandboxedApps, isTrue);
    expect(got.hasAiAgents, isFalse);
  });

  test('an agent that includes none has none', () async {
    final got = await AgentAddOns.at('http://none',
        ask: () async => info({'add_ons': <String>[]}));
    expect(got.hasSandboxedApps, isFalse);
    expect(got.hasAiAgents, isFalse);
  });

  test('a core older than add-ons, which does not say, has everything', () async {
    final got = await AgentAddOns.at('http://older', ask: () async => info({}));
    expect(got.hasSandboxedApps, isTrue);
    expect(got.hasAiAgents, isTrue);
  });

  test('an agent that cannot be asked hides nothing, and is asked again', () async {
    var asked = 0;
    Future<CoreInfoResponse> failing() async {
      asked++;
      throw Exception('unreachable');
    }

    final first = await AgentAddOns.at('http://flaky', ask: failing);
    expect(first.hasAiAgents, isTrue);
    expect(first.hasSandboxedApps, isTrue);
    await AgentAddOns.at('http://flaky', ask: failing);
    expect(asked, 2, reason: 'a failed answer must not be kept');
  });

  test('one answer is kept per agent', () async {
    var asked = 0;
    Future<CoreInfoResponse> answer() async {
      asked++;
      return info({'add_ons': ['ai_agents', 'sandboxed_apps']});
    }

    await AgentAddOns.at('http://kept', ask: answer);
    await AgentAddOns.at('http://kept', ask: answer);
    expect(asked, 1);
    expect(AgentAddOns.known('http://kept').hasAiAgents, isTrue);
    expect(AgentAddOns.known('http://elsewhere').hasAiAgents, isTrue,
        reason: 'an agent not yet asked hides nothing');
  });
}
