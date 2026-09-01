import 'dart:convert';

import 'package:agent_client/config/agent_config.dart';
import 'package:agent_client/services/approving_a_machine_to_act_for_you.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

/// Both sides of authorising a computer, on one screen.
///
/// They are together because on a desktop the same person is on both, and
/// separating them would mean explaining which half they are looking at. What
/// each half does is unrelated:
///
///   - **This computer** shows what it would offer if somebody authorised it —
///     its own identifier, which is its key. Read by whoever is approving.
///   - **Machines that may act** is the owner's list: what has been authorised,
///     and the way to take it away.
///
/// The approving half only works where this app can already act as the owner —
/// it posts to an owner-only route. On the device holding the identity's key
/// that is true; on a machine that is only a front end it is not, and the list
/// will say so rather than appearing empty.
class MachinesThatMayActScreen extends StatefulWidget {
  const MachinesThatMayActScreen({super.key, this.serverUrl});

  /// The agent this app talks to. Null means the ordinary case — the core on
  /// this machine — which is what every other screen here assumes too.
  final String? serverUrl;

  @override
  State<MachinesThatMayActScreen> createState() => _MachinesThatMayActScreenState();
}

class _MachinesThatMayActScreenState extends State<MachinesThatMayActScreen> {
  Map<String, dynamic>? _thisMachine;
  String _thisMachineProblem = '';

  List<AnApprovedMachine> _machines = const [];
  String _listProblem = '';
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  CoreService get _core => CoreService(baseUrl: widget.serverUrl);

  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([_loadThisMachine(), _loadTheList()]);
    if (mounted) setState(() => _loading = false);
  }

  /// What this computer would offer. Answered by its OWN core, always — the
  /// enclave key is here, and no other machine can say what it is.
  Future<void> _loadThisMachine() async {
    try {
      final res = await http
          .get(Uri.parse('${AgentConfig.coreBaseUrl}/api/controller/this-machine'));
      if (res.statusCode == 200) {
        _thisMachine = jsonDecode(res.body) as Map<String, dynamic>;
        _thisMachineProblem = '';
      } else {
        _thisMachine = null;
        // 501 is the honest answer on hardware that cannot keep a key to
        // itself, and it is not a fault. Shown as what it is.
        _thisMachineProblem = _detailFrom(res.body);
      }
    } catch (e) {
      _thisMachine = null;
      _thisMachineProblem = 'this computer\'s own agent could not be reached ($e)';
    }
  }

  Future<void> _loadTheList() async {
    final core = _core;
    try {
      _machines = await ApprovingAMachineToActForYou(
        agentOrigin: core.baseUrl,
        client: core.client,
      ).theMachinesThatMayAct();
      _listProblem = '';
    } on ApprovalRefused catch (e) {
      _machines = const [];
      _listProblem = e.status == 403
          ? 'This app cannot see that list, because it is not acting as this '
              'identity\'s owner here. Open it on the device holding the key.'
          : 'The agent would not answer (${e.status}).';
    } catch (e) {
      _machines = const [];
      _listProblem = 'Could not reach the agent ($e)';
    } finally {
      core.dispose();
    }
  }

  static String _detailFrom(String body) {
    try {
      final m = jsonDecode(body) as Map<String, dynamic>;
      return (m['details'] ?? m['error'] ?? body).toString();
    } catch (_) {
      return body;
    }
  }

  Future<void> _approve() async {
    final asking = await showDialog<_Approval>(
      context: context,
      builder: (_) => const _ApproveAMachineDialog(),
    );
    if (asking == null || !mounted) return;

    final core = _core;
    try {
      await ApprovingAMachineToActForYou(
        agentOrigin: core.baseUrl,
        client: core.client,
      ).approve(
        machine: asking.machine,
        label: asking.label,
        theyAreKeepingIt: asking.theyAreKeepingIt,
      );
      _say('${asking.label} may now act for you.');
    } catch (e) {
      _say('$e');
    } finally {
      core.dispose();
    }
    await _load();
  }

  Future<void> _revoke(AnApprovedMachine m) async {
    final sure = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text('Stop ${m.label} acting for you?'),
        content: const Text(
            'It keeps its own key, and that key stops meaning anything here. '
            'Nothing needs to be reachable for this to take effect, so it works '
            'for a computer you no longer have.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Keep it')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Stop it')),
        ],
      ),
    );
    if (sure != true || !mounted) return;

    final core = _core;
    try {
      await ApprovingAMachineToActForYou(
        agentOrigin: core.baseUrl,
        client: core.client,
      ).revoke(m.aid);
      _say('${m.label} can no longer act for you.');
    } catch (e) {
      _say('$e');
    } finally {
      core.dispose();
    }
    await _load();
  }

  void _say(String s) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Machines that may act for you'),
        actions: [
          IconButton(
            onPressed: _loading ? null : _load,
            icon: const Icon(Icons.refresh),
            tooltip: 'Check again',
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _approve,
        icon: const Icon(Icons.add),
        label: const Text('Authorise a computer'),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                _ThisComputer(offer: _thisMachine, problem: _thisMachineProblem),
                const SizedBox(height: 24),
                Text('Authorised', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 8),
                if (_listProblem.isNotEmpty)
                  _Note(_listProblem)
                else if (_machines.isEmpty)
                  const _Note('No computer may act for this identity yet.')
                else
                  ..._machines.map((m) => _MachineRow(machine: m, onRevoke: () => _revoke(m))),
              ],
            ),
    );
  }
}

/// What this computer would offer, and what is protecting the key.
class _ThisComputer extends StatelessWidget {
  const _ThisComputer({required this.offer, required this.problem});

  final Map<String, dynamic>? offer;
  final String problem;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    if (offer == null) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('This computer cannot act for an identity', style: text.titleMedium),
              const SizedBox(height: 8),
              // Said plainly rather than softened. A machine that cannot keep a
              // key to itself should not be authorised, and the person is
              // better served knowing why than being offered a button that
              // will fail.
              Text(problem, style: text.bodyMedium),
            ],
          ),
        ),
      );
    }

    final aid = (offer!['aid'] ?? '').toString();
    final code = jsonEncode({
      'aid': aid,
      'public_key': offer!['public_key'],
      'protected_by': offer!['protected_by'],
    });

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('This computer', style: text.titleMedium),
            const SizedBox(height: 4),
            Text('Its key is held by ${offer!['protected_by']}.', style: text.bodyMedium),
            const SizedBox(height: 12),
            Text('Its identifier', style: text.labelMedium),
            SelectableText(aid, style: text.bodySmall),
            const SizedBox(height: 12),
            Row(children: [
              OutlinedButton.icon(
                onPressed: () => Clipboard.setData(ClipboardData(text: code)),
                icon: const Icon(Icons.copy, size: 18),
                label: const Text('Copy what to approve'),
              ),
            ]),
            const SizedBox(height: 8),
            Text(
              'Give this to the device holding your identity\'s key, and approve '
              'it there. This computer finds out by asking — nothing is sent to it.',
              style: text.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

class _MachineRow extends StatelessWidget {
  const _MachineRow({required this.machine, required this.onRevoke});

  final AnApprovedMachine machine;
  final VoidCallback onRevoke;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: Icon(machine.live ? Icons.laptop : Icons.laptop_outlined,
            color: machine.live ? null : Theme.of(context).disabledColor),
        title: Text(machine.label),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(machine.theyAreKeepingIt
                ? 'A computer you keep — until you remove it'
                : 'Using it for now'),
            if (!machine.live && machine.whyNot.isNotEmpty)
              Text(machine.whyNot, style: Theme.of(context).textTheme.bodySmall),
            SelectableText(machine.aid,
                style: Theme.of(context).textTheme.bodySmall),
          ],
        ),
        isThreeLine: true,
        trailing: TextButton(onPressed: onRevoke, child: const Text('Stop it')),
      ),
    );
  }
}

class _Note extends StatelessWidget {
  const _Note(this.text);
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 12),
        child: Text(text, style: Theme.of(context).textTheme.bodyMedium),
      );
}

class _Approval {
  const _Approval({
    required this.machine,
    required this.label,
    required this.theyAreKeepingIt,
  });
  final AMachineAsking machine;
  final String label;
  final bool theyAreKeepingIt;
}

/// The one question the person is asked, and the name they give the machine.
class _ApproveAMachineDialog extends StatefulWidget {
  const _ApproveAMachineDialog();

  @override
  State<_ApproveAMachineDialog> createState() => _ApproveAMachineDialogState();
}

class _ApproveAMachineDialogState extends State<_ApproveAMachineDialog> {
  final _code = TextEditingController();
  final _label = TextEditingController();
  bool _keeping = true;
  String _problem = '';

  @override
  void dispose() {
    _code.dispose();
    _label.dispose();
    super.dispose();
  }

  void _submit() {
    try {
      final machine = ApprovingAMachineToActForYou.readWhatItOffers(_code.text);
      if (_label.text.trim().isEmpty) {
        setState(() => _problem = 'Give it a name you will recognise later.');
        return;
      }
      Navigator.pop(
          context,
          _Approval(
              machine: machine,
              label: _label.text.trim(),
              theyAreKeepingIt: _keeping));
    } catch (e) {
      setState(() => _problem = '$e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Authorise a computer'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              controller: _code,
              minLines: 2,
              maxLines: 4,
              decoration: const InputDecoration(
                labelText: 'What that computer showed you',
                helperText: 'Copied from its own screen',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _label,
              decoration: const InputDecoration(
                labelText: 'What to call it',
                helperText: 'You choose this, not the computer',
              ),
            ),
            const SizedBox(height: 16),
            // The question, and its consequence written into the options —
            // "will you keep it" asks somebody to predict something and never
            // says why it matters.
            const Text('Is this a computer you keep, or one you are using for now?'),
            RadioListTile<bool>(
              value: true,
              groupValue: _keeping,
              onChanged: (v) => setState(() => _keeping = v ?? true),
              title: const Text('A computer I keep'),
              subtitle: const Text('It stays here until you remove it.'),
            ),
            RadioListTile<bool>(
              value: false,
              groupValue: _keeping,
              onChanged: (v) => setState(() => _keeping = v ?? false),
              title: const Text('Using it for now'),
              subtitle: const Text('It stops on its own, and leaves nothing behind.'),
            ),
            if (_problem.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(_problem, style: TextStyle(color: Theme.of(context).colorScheme.error)),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: _submit, child: const Text('Authorise')),
      ],
    );
  }
}
