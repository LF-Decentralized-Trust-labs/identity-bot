import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import '../services/setup_task_service.dart';
import '../services/preferences_service.dart';
import '../services/keri_service.dart';
import '../services/core_service.dart';
import '../services/secure_key_store.dart';
import 'hosting_choice_screen.dart';
import 'desktop/coming_soon_screen.dart';

class SetupChecklistScreen extends StatefulWidget {
  final VoidCallback onDone;
  final KeriService keriService;
  final String? serverUrl;
  final HostingChoice? hostingChoice;
  final String? remoteBrainUrl;

  const SetupChecklistScreen({
    super.key,
    required this.onDone,
    required this.keriService,
    this.serverUrl,
    this.hostingChoice,
    this.remoteBrainUrl,
  });

  @override
  State<SetupChecklistScreen> createState() => _SetupChecklistScreenState();
}

class _SetupChecklistScreenState extends State<SetupChecklistScreen> {
  Map<SetupTask, bool> _state = {};
  bool _loading = true;

  bool get _needsRemoteBrain =>
      widget.hostingChoice == HostingChoice.keysHereBrainLater;

  List<SetupTask> get _tasks =>
      SetupTaskService.orderedTasks(needsRemoteBrain: _needsRemoteBrain);

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final s = await SetupTaskService.loadState(_tasks);
    if (mounted) setState(() { _state = s; _loading = false; });
  }

  int get _doneCount => _state.values.where((v) => v).length;
  int get _totalCount => _tasks.length;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildHeader(),
                  const SizedBox(height: 32),
                  if (_loading)
                    const Center(
                      child: CircularProgressIndicator(color: AppColors.accent),
                    )
                  else ...[
                    _buildSection('Security', [
                      if (_needsRemoteBrain) SetupTask.connectRemoteBrain,
                      SetupTask.backupSeedPhrase,
                      SetupTask.setupAuthentication,
                      SetupTask.inviteContacts,
                    ]),
                    const SizedBox(height: 20),
                    _buildSection('Connections', [
                      SetupTask.connectEmail,
                      SetupTask.addPhoneNumber,
                    ]),
                    const SizedBox(height: 20),
                    _buildSection('Profile & Trust', [
                      SetupTask.completeProfile,
                      SetupTask.getVerified,
                    ]),
                  ],
                  const SizedBox(height: 32),
                  SizedBox(
                    width: double.infinity,
                    child: TextButton(
                      onPressed: widget.onDone,
                      child: const Text(
                        "I'LL DO THIS LATER — GO TO DASHBOARD",
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 12,
                          letterSpacing: 0.5,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Progress
        Row(
          children: [
            _buildProgressRing(),
            const SizedBox(width: 20),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'SECURE YOUR IDENTITY\nAND MAKE IT USEFUL.',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 20,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.0,
                      height: 1.3,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _loading
                        ? ''
                        : '$_doneCount of $_totalCount tasks complete.',
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        const Text(
          'These steps are optional — your identity is already live. '
          'But completing them makes your identity more secure, more useful, and easier to recover.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 12,
            height: 1.6,
            fontFamily: 'monospace',
          ),
        ),
      ],
    );
  }

  Widget _buildProgressRing() {
    final pct = _loading || _totalCount == 0
        ? 0.0
        : _doneCount / _totalCount;
    return SizedBox(
      width: 64,
      height: 64,
      child: Stack(
        alignment: Alignment.center,
        children: [
          CircularProgressIndicator(
            value: pct,
            backgroundColor: AppColors.border,
            color: pct == 1.0 ? AppColors.coreActive : AppColors.accent,
            strokeWidth: 5,
          ),
          Text(
            '$_doneCount/$_totalCount',
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w700,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSection(String title, List<SetupTask> tasks) {
    // Filter to tasks that are in our ordered list
    final filtered = tasks.where((t) => _tasks.contains(t)).toList();
    if (filtered.isEmpty) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title.toUpperCase(),
          style: const TextStyle(
            color: AppColors.textMuted,
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 2.0,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 10),
        ...filtered.map((t) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _buildTaskCard(t),
            )),
      ],
    );
  }

  Widget _buildTaskCard(SetupTask task) {
    final meta = SetupTaskMeta(
      task: task,
      title: SetupTaskService.meta(task).title,
      description: SetupTaskService.meta(task).description,
      isStub: SetupTaskService.meta(task).isStub,
      isCritical: SetupTaskService.meta(task).isCritical,
    );
    final done = _state[task] ?? false;

    return GestureDetector(
      onTap: done ? null : () => _handleTaskTap(task, meta),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: done
              ? AppColors.coreActive.withOpacity(0.04)
              : AppColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: done
                ? AppColors.coreActive.withOpacity(0.2)
                : meta.isCritical && !done
                    ? AppColors.accent.withOpacity(0.3)
                    : AppColors.border,
            width: 1,
          ),
        ),
        child: Row(
          children: [
            _buildStatusIcon(task, done, meta.isStub),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          meta.title,
                          style: TextStyle(
                            color: done
                                ? AppColors.textMuted
                                : AppColors.textPrimary,
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            fontFamily: 'monospace',
                            decoration:
                                done ? TextDecoration.lineThrough : null,
                          ),
                        ),
                      ),
                      if (meta.isStub && !done)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: AppColors.textMuted.withOpacity(0.08),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text(
                            'COMING SOON',
                            style: TextStyle(
                              color: AppColors.textMuted,
                              fontSize: 8,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.8,
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      if (meta.isCritical && !done)
                        Padding(
                          padding: const EdgeInsets.only(left: 6),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: AppColors.corePending.withOpacity(0.12),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: const Text(
                              'IMPORTANT',
                              style: TextStyle(
                                color: AppColors.corePending,
                                fontSize: 8,
                                fontWeight: FontWeight.w700,
                                letterSpacing: 0.8,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    meta.description,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 11,
                      height: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            if (!done)
              const Icon(
                Icons.chevron_right,
                color: AppColors.textMuted,
                size: 20,
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusIcon(SetupTask task, bool done, bool isStub) {
    if (done) {
      return const Icon(Icons.check_circle, color: AppColors.coreActive, size: 22);
    }
    if (isStub) {
      return const Icon(Icons.schedule_outlined, color: AppColors.textMuted, size: 22);
    }
    return const Icon(Icons.radio_button_unchecked, color: AppColors.accent, size: 22);
  }

  Future<void> _handleTaskTap(SetupTask task, SetupTaskMeta meta) async {
    if (meta.isStub) {
      // Navigate to placeholder
      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => ComingSoonScreen(
          title: meta.title,
          description:
              '${meta.description}\n\nThis feature is actively being built.',
          icon: _taskIcon(task),
        ),
      ));
      return;
    }

    switch (task) {
      case SetupTask.connectRemoteBrain:
        await _doConnectRemoteBrain();
      case SetupTask.backupSeedPhrase:
        await _doBackupSeedPhrase();
      case SetupTask.inviteContacts:
        await _doInviteContacts();
      case SetupTask.completeProfile:
        _doCompleteProfile();
      default:
        break;
    }
  }

  Future<void> _doConnectRemoteBrain() async {
    // Show inline connect dialog
    final urlController = TextEditingController();
    String? error;
    bool connecting = false;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: AppColors.accent.withOpacity(0.3)),
          ),
          title: const Text(
            'CONNECT REMOTE BRAIN',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 14,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.0,
              fontFamily: 'monospace',
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Enter the URL of your remote server to unlock full features.',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: urlController,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
                decoration: InputDecoration(
                  hintText: 'https://my-server.example.com',
                  hintStyle: TextStyle(
                    color: AppColors.textMuted.withOpacity(0.5),
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                  filled: true,
                  fillColor: AppColors.primary,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: AppColors.border),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: AppColors.border),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: AppColors.accent),
                  ),
                  contentPadding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 10),
                ),
                autocorrect: false,
                keyboardType: TextInputType.url,
              ),
              if (error != null) ...[
                const SizedBox(height: 8),
                Text(
                  error!,
                  style: const TextStyle(
                    color: AppColors.coreInactive,
                    fontSize: 11,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text(
                'CANCEL',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            ElevatedButton(
              onPressed: connecting
                  ? null
                  : () async {
                      final url = urlController.text.trim();
                      if (url.isEmpty) {
                        setS(() => error = 'Enter a server URL.');
                        return;
                      }
                      setS(() { connecting = true; error = null; });
                      try {
                        final svc = CoreService(baseUrl: url);
                        await svc.getHealth();
                        svc.dispose();
                        await SetupTaskService.markComplete(
                            SetupTask.connectRemoteBrain);
                        if (ctx.mounted) Navigator.of(ctx).pop();
                        _load();
                      } catch (_) {
                        setS(() {
                          connecting = false;
                          error = 'Could not reach that server. Check the URL.';
                        });
                      }
                    },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: AppColors.primary,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
              child: connecting
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(
                          color: AppColors.primary, strokeWidth: 2),
                    )
                  : const Text(
                      'CONNECT',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                        fontFamily: 'monospace',
                      ),
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _doBackupSeedPhrase() async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: AppColors.corePending.withOpacity(0.4)),
        ),
        title: const Text(
          'BACK UP YOUR SEED PHRASE',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.0,
            fontFamily: 'monospace',
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildBackupOption(
              ctx: ctx,
              icon: Icons.edit_note,
              title: "Write it down",
              description: "View your 12 words and write them on paper.",
              onTap: () async {
                Navigator.of(ctx).pop();
                await _showSeedWords();
              },
            ),
            const SizedBox(height: 10),
            _buildBackupOption(
              ctx: ctx,
              icon: Icons.nfc,
              title: "Write to NFC tag",
              description: "Save to a physical NFC tag for hardware backup.",
              isStub: true,
              onTap: () {
                Navigator.of(ctx).pop();
                Navigator.of(context).push(MaterialPageRoute(
                  builder: (_) => const ComingSoonScreen(
                    title: 'NFC Seed Backup',
                    description:
                        'Write your seed phrase to an NFC tag for hardware backup. '
                        'This feature is actively being built.',
                    icon: Icons.nfc,
                  ),
                ));
              },
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text(
              'CLOSE',
              style: TextStyle(
                color: AppColors.textMuted,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBackupOption({
    required BuildContext ctx,
    required IconData icon,
    required String title,
    required String description,
    required VoidCallback onTap,
    bool isStub = false,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.primary,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppColors.border),
        ),
        child: Row(
          children: [
            Icon(icon,
                color: isStub ? AppColors.textMuted : AppColors.accent,
                size: 22),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        title,
                        style: TextStyle(
                          color: isStub
                              ? AppColors.textMuted
                              : AppColors.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          fontFamily: 'monospace',
                        ),
                      ),
                      if (isStub) ...[
                        const SizedBox(width: 6),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 5, vertical: 1),
                          decoration: BoxDecoration(
                            color: AppColors.textMuted.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(3),
                          ),
                          child: const Text(
                            'COMING SOON',
                            style: TextStyle(
                              color: AppColors.textMuted,
                              fontSize: 8,
                              letterSpacing: 0.5,
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    description,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: AppColors.textMuted, size: 18),
          ],
        ),
      ),
    );
  }

  Future<void> _showSeedWords() async {
    final mnemonic = await _loadMnemonic();
    if (!mounted) return;
    bool confirmed = false;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: AppColors.corePending.withOpacity(0.4)),
          ),
          title: const Row(
            children: [
              Icon(Icons.warning_amber_rounded,
                  color: AppColors.corePending, size: 22),
              SizedBox(width: 8),
              Text(
                'YOUR SEED PHRASE',
                style: TextStyle(
                  color: AppColors.corePending,
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.0,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Never share these words. Never store them digitally. Write them on paper and keep them safe.',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 16),
              if (mnemonic == null)
                const Text(
                  'Could not retrieve seed phrase. It may have been cleared from secure storage.',
                  style: TextStyle(
                    color: AppColors.coreInactive,
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                )
              else
                _buildWordGrid(mnemonic),
              const SizedBox(height: 16),
              GestureDetector(
                onTap: () => setS(() => confirmed = !confirmed),
                child: Row(
                  children: [
                    Icon(
                      confirmed
                          ? Icons.check_box
                          : Icons.check_box_outline_blank,
                      color: confirmed
                          ? AppColors.coreActive
                          : AppColors.textMuted,
                      size: 20,
                    ),
                    const SizedBox(width: 8),
                    const Expanded(
                      child: Text(
                        "I've written these words down in a safe place.",
                        style: TextStyle(
                          color: AppColors.textSecondary,
                          fontSize: 12,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text(
                'CANCEL',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            ElevatedButton(
              onPressed: confirmed
                  ? () async {
                      await SetupTaskService.markComplete(
                          SetupTask.backupSeedPhrase);
                      if (ctx.mounted) Navigator.of(ctx).pop();
                      _load();
                    }
                  : null,
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.coreActive,
                foregroundColor: AppColors.primary,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
              child: const Text(
                'DONE — MARK AS BACKED UP',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildWordGrid(List<String> words) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.primary,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
            color: AppColors.corePending.withOpacity(0.3), width: 1),
      ),
      child: Column(
        children: [
          for (int row = 0; row < (words.length / 3).ceil(); row++)
            Padding(
              padding:
                  EdgeInsets.only(bottom: row < (words.length / 3).ceil() - 1 ? 8 : 0),
              child: Row(
                children: [
                  for (int col = 0; col < 3; col++)
                    if (row * 3 + col < words.length)
                      Expanded(
                        child: Padding(
                          padding: EdgeInsets.only(left: col > 0 ? 6 : 0),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 8, vertical: 8),
                            decoration: BoxDecoration(
                              color: AppColors.surface,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: AppColors.border),
                            ),
                            child: Row(
                              children: [
                                Text(
                                  '${row * 3 + col + 1}.',
                                  style: const TextStyle(
                                    color: AppColors.textMuted,
                                    fontSize: 10,
                                    fontFamily: 'monospace',
                                  ),
                                ),
                                const SizedBox(width: 4),
                                Expanded(
                                  child: Text(
                                    words[row * 3 + col],
                                    style: const TextStyle(
                                      color: AppColors.textPrimary,
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      fontFamily: 'monospace',
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      )
                    else
                      const Expanded(child: SizedBox()),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Future<List<String>?> _loadMnemonic() async {
    try {
      return await SecureKeyStore.loadMnemonic();
    } catch (_) {
      return null;
    }
  }

  Future<void> _doInviteContacts() async {
    String? oobiUrl;
    try {
      final coreService = CoreService(
          baseUrl: widget.serverUrl ?? 'http://127.0.0.1:5000');
      final oobi = await coreService.getOobi();
      coreService.dispose();
      oobiUrl = oobi.oobiUrl;
    } catch (_) {}

    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: AppColors.accent.withOpacity(0.3)),
        ),
        title: const Text(
          'INVITE CONTACTS',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 14,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.0,
            fontFamily: 'monospace',
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Share your Identity Address with people you trust. They will be your witnesses and recovery contacts.',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                fontFamily: 'monospace',
                height: 1.5,
              ),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.primary,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border),
              ),
              child: SelectableText(
                oobiUrl ?? 'Could not fetch your address. Is the backend running?',
                style: const TextStyle(
                  color: AppColors.accent,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text(
              'CLOSE',
              style: TextStyle(
                color: AppColors.textMuted,
                fontFamily: 'monospace',
              ),
            ),
          ),
          if (oobiUrl != null)
            ElevatedButton(
              onPressed: () async {
                await SetupTaskService.markComplete(SetupTask.inviteContacts);
                if (ctx.mounted) Navigator.of(ctx).pop();
                _load();
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: AppColors.primary,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
              child: const Text(
                'MARK AS DONE',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  fontFamily: 'monospace',
                ),
              ),
            ),
        ],
      ),
    );
  }

  void _doCompleteProfile() {
    // Navigate to profile screen — user can fill in bio/org/title
    // Mark complete when they come back (best-effort)
    Navigator.of(context).pop();
    SetupTaskService.markComplete(SetupTask.completeProfile);
  }

  IconData _taskIcon(SetupTask task) {
    switch (task) {
      case SetupTask.connectRemoteBrain:
        return Icons.cloud_outlined;
      case SetupTask.backupSeedPhrase:
        return Icons.key_outlined;
      case SetupTask.setupAuthentication:
        return Icons.lock_outlined;
      case SetupTask.inviteContacts:
        return Icons.people_outline;
      case SetupTask.connectEmail:
        return Icons.email_outlined;
      case SetupTask.addPhoneNumber:
        return Icons.phone_outlined;
      case SetupTask.completeProfile:
        return Icons.person_outline;
      case SetupTask.getVerified:
        return Icons.verified_outlined;
    }
  }
}
