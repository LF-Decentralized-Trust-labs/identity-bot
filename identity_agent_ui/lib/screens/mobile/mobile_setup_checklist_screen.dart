import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/setup_task_service.dart';
import '../../services/preferences_service.dart';
import '../../services/keri_service.dart';
import '../../services/core_service.dart';
import '../../services/enclave_service.dart';
import '../../services/secure_key_store.dart';
import '../../config/agent_config.dart';
import 'mobile_auth_setup_screen.dart';
import 'mobile_coming_soon_screen.dart';
import 'mobile_nfc_seed_screen.dart';

class MobileSetupChecklistScreen extends StatefulWidget {
  final VoidCallback onDone;
  final KeriService keriService;
  final String? serverUrl;
  final HostingChoice? hostingChoice;
  final String? remoteBrainUrl;

  const MobileSetupChecklistScreen({
    super.key,
    required this.onDone,
    required this.keriService,
    this.serverUrl,
    this.hostingChoice,
    this.remoteBrainUrl,
  });

  @override
  State<MobileSetupChecklistScreen> createState() =>
      _MobileSetupChecklistScreenState();
}

class _MobileSetupChecklistScreenState
    extends State<MobileSetupChecklistScreen> {
  Map<SetupTask, bool> _state = {};
  bool _loading = true;
  EnclaveStatusResponse? _enclaveStatus;

  bool get _needsRemoteBrain =>
      widget.hostingChoice == HostingChoice.keysHereBrainLater;

  List<SetupTask> get _tasks =>
      SetupTaskService.orderedTasks(needsRemoteBrain: _needsRemoteBrain);

  String get _effectiveServerUrl =>
      widget.serverUrl ?? widget.remoteBrainUrl ?? AgentConfig.coreBaseUrl;

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
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        body: SafeArea(
          child: Column(
            children: [
              _buildHeader(),
              Expanded(
                child: _loading
                    ? const Center(
                        child: CircularProgressIndicator(
                            color: MobileColors.primary),
                      )
                    : ListView(
                        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
                        children: [
                          // Only show incomplete tasks — completed ones disappear
                          ...(_tasks
                              .where((t) => !(_state[t] ?? false))
                              .map((t) => Padding(
                                    padding: const EdgeInsets.only(bottom: 8),
                                    child: _buildTaskCard(t),
                                  ))),
                          const SizedBox(height: 8),
                          TextButton(
                            onPressed: widget.onDone,
                            child: const Text(
                              "I'll do this later",
                              style: TextStyle(
                                color: MobileColors.textMuted,
                                fontSize: 14,
                              ),
                            ),
                          ),
                        ],
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    final remaining = _totalCount - _doneCount;
    final subtitle = _loading
        ? 'Loading...'
        : '$remaining step${remaining == 1 ? '' : 's'} remaining';

    return Container(
      color: MobileColors.surface,
      padding: const EdgeInsets.fromLTRB(20, 20, 8, 16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Complete Your Setup',
                  style: TextStyle(
                    color: MobileColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    height: 1.2,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  subtitle,
                  style: const TextStyle(
                    color: MobileColors.textMuted,
                    fontSize: 13,
                  ),
                ),
                const SizedBox(height: 2),
                const Text(
                  'Required for basic security.',
                  style: TextStyle(
                    color: MobileColors.textSecondary,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          IconButton(
            icon: const Icon(Icons.close, size: 20),
            color: MobileColors.textMuted,
            onPressed: widget.onDone,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 40, minHeight: 40),
          ),
        ],
      ),
    );
  }

  Widget _buildTaskCard(SetupTask task) {
    final meta = SetupTaskService.meta(task);
    final done = _state[task] ?? false;

    return GestureDetector(
      onTap: done ? null : () => _handleTaskTap(task, meta),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: done
              ? MobileColors.success.withOpacity(0.04)
              : MobileColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: done
                ? MobileColors.success.withOpacity(0.25)
                : meta.isCritical && !done
                    ? MobileColors.primary.withOpacity(0.3)
                    : MobileColors.border,
          ),
          boxShadow: [
            BoxShadow(
              color: MobileColors.cardShadow,
              blurRadius: 4,
              offset: const Offset(0, 1),
            ),
          ],
        ),
        child: Row(
          children: [
            _buildStatusIcon(done, meta.isStub),
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
                                ? MobileColors.textMuted
                                : MobileColors.textPrimary,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                            decoration:
                                done ? TextDecoration.lineThrough : null,
                          ),
                        ),
                      ),
                      if (meta.isStub && !done)
                        _buildBadge('SOON', MobileColors.textMuted),
                      if (meta.isCritical && !done)
                        Padding(
                          padding: const EdgeInsets.only(left: 4),
                          child: _buildBadge('IMPORTANT', MobileColors.primary),
                        ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    meta.description,
                    style: const TextStyle(
                      color: MobileColors.textMuted,
                      fontSize: 12,
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            if (!done)
              const Icon(Icons.chevron_right,
                  color: MobileColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusIcon(bool done, bool isStub) {
    if (done) {
      return const Icon(Icons.check_circle,
          color: MobileColors.success, size: 22);
    }
    if (isStub) {
      return const Icon(Icons.schedule_outlined,
          color: MobileColors.textMuted, size: 22);
    }
    return const Icon(Icons.radio_button_unchecked,
        color: MobileColors.primary, size: 22);
  }

  Widget _buildBadge(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 9,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.5,
        ),
      ),
    );
  }

  Future<void> _handleTaskTap(SetupTask task, SetupTaskMeta meta) async {
    if (meta.isStub) {
      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => MobileComingSoonScreen(
          title: meta.title,
          description: '${meta.description}\n\nThis feature is actively being built.',
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
      case SetupTask.setupAuthentication:
        await _doSetupAuthentication();
      case SetupTask.secureKeyStorage:
        await _doSecureKeyStorage();
      case SetupTask.inviteContacts:
        await _doInviteContacts();
    }
  }

  Future<void> _doSetupAuthentication() async {
    await Navigator.of(context).push(MaterialPageRoute(
      builder: (_) => const MobileAuthSetupScreen(),
    ));
    // Reload state — MobileAuthSetupScreen calls markComplete when Tier 2 is reached
    await _load();
  }

  Future<void> _doConnectRemoteBrain() async {
    final urlCtrl = TextEditingController();
    String? error;
    bool connecting = false;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => Padding(
          padding: EdgeInsets.fromLTRB(
              20, 20, 20, MediaQuery.of(ctx).viewInsets.bottom + 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Connect Remote Brain',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Enter the URL of your remote server to unlock full features.',
                style: TextStyle(color: MobileColors.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: urlCtrl,
                autofocus: true,
                keyboardType: TextInputType.url,
                autocorrect: false,
                decoration: InputDecoration(
                  hintText: 'https://my-server.example.com',
                  hintStyle: const TextStyle(color: MobileColors.textMuted),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: MobileColors.border),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: MobileColors.border),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide:
                        const BorderSide(color: MobileColors.primary, width: 2),
                  ),
                  errorText: error,
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: connecting
                      ? null
                      : () async {
                          final url = urlCtrl.text.trim();
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
                    backgroundColor: MobileColors.primary,
                    foregroundColor: MobileColors.textOnPrimary,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                  child: connecting
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                              color: Colors.white, strokeWidth: 2),
                        )
                      : const Text('Connect',
                          style: TextStyle(
                              fontSize: 16, fontWeight: FontWeight.w600)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _doBackupSeedPhrase() async {
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => Padding(
        padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Back Up Seed Phrase',
              style: TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 18,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 16),
            _buildBackupOption(
              ctx: ctx,
              icon: Icons.edit_note,
              title: 'Write it down',
              description: 'View your 12 words and write them on paper.',
              onTap: () async {
                Navigator.of(ctx).pop();
                await _showSeedWords();
              },
            ),
            const SizedBox(height: 10),
            _buildBackupOption(
              ctx: ctx,
              icon: Icons.nfc,
              title: 'Write to NFC tag',
              description: 'Save to a physical NFC tag for hardware backup.',
              onTap: () {
                Navigator.of(ctx).pop();
                Navigator.of(context).push(MaterialPageRoute(
                  builder: (_) =>
                      const MobileNfcSeedScreen(mode: NfcSeedMode.write),
                ));
              },
            ),
          ],
        ),
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
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: MobileColors.surfaceSecondary,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: MobileColors.border),
        ),
        child: Row(
          children: [
            Icon(icon,
                color: isStub ? MobileColors.textMuted : MobileColors.primary,
                size: 24),
            const SizedBox(width: 14),
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
                              ? MobileColors.textMuted
                              : MobileColors.textPrimary,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      if (isStub) ...[
                        const SizedBox(width: 6),
                        _buildBadge('SOON', MobileColors.textMuted),
                      ],
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    description,
                    style: const TextStyle(
                      color: MobileColors.textMuted,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right,
                color: MobileColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }

  Future<void> _showSeedWords() async {
    final mnemonic = await _loadMnemonic();
    if (!mounted) return;
    bool confirmed = false;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => DraggableScrollableSheet(
          expand: false,
          initialChildSize: 0.85,
          maxChildSize: 0.95,
          builder: (_, scrollCtrl) => ListView(
            controller: scrollCtrl,
            padding: const EdgeInsets.fromLTRB(20, 20, 20, 32),
            children: [
              Row(
                children: [
                  const Icon(Icons.warning_amber_rounded,
                      color: MobileColors.warning, size: 22),
                  const SizedBox(width: 8),
                  const Text(
                    'Your Seed Phrase',
                    style: TextStyle(
                      color: MobileColors.textPrimary,
                      fontSize: 18,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              const Text(
                'Never share these words. Never store them digitally. Write them on paper and keep them safe.',
                style: TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 16),
              if (mnemonic == null)
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: MobileColors.error.withOpacity(0.06),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                        color: MobileColors.error.withOpacity(0.2)),
                  ),
                  child: const Text(
                    'Could not retrieve seed phrase. It may have been cleared from secure storage.',
                    style: TextStyle(
                      color: MobileColors.error,
                      fontSize: 13,
                    ),
                  ),
                )
              else
                _buildWordGrid(mnemonic),
              const SizedBox(height: 20),
              GestureDetector(
                onTap: () => setS(() => confirmed = !confirmed),
                child: Row(
                  children: [
                    Icon(
                      confirmed
                          ? Icons.check_box
                          : Icons.check_box_outline_blank,
                      color: confirmed
                          ? MobileColors.success
                          : MobileColors.textMuted,
                      size: 22,
                    ),
                    const SizedBox(width: 10),
                    const Expanded(
                      child: Text(
                        "I've written these words down in a safe place.",
                        style: TextStyle(
                          color: MobileColors.textSecondary,
                          fontSize: 13,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: confirmed
                      ? () async {
                          await SetupTaskService.markComplete(
                              SetupTask.backupSeedPhrase);
                          if (ctx.mounted) Navigator.of(ctx).pop();
                          _load();
                        }
                      : null,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: MobileColors.success,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                  child: const Text(
                    'Done — Mark as Backed Up',
                    style:
                        TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildWordGrid(List<String> words) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.surfaceSecondary,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.warning.withOpacity(0.3)),
      ),
      child: Column(
        children: [
          for (int row = 0; row < (words.length / 3).ceil(); row++)
            Padding(
              padding: EdgeInsets.only(
                  bottom: row < (words.length / 3).ceil() - 1 ? 8 : 0),
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
                              color: MobileColors.surface,
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: MobileColors.border),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  '${row * 3 + col + 1}',
                                  style: const TextStyle(
                                    color: MobileColors.textMuted,
                                    fontSize: 9,
                                  ),
                                ),
                                Text(
                                  words[row * 3 + col],
                                  style: const TextStyle(
                                    color: MobileColors.textPrimary,
                                    fontSize: 12,
                                    fontWeight: FontWeight.w600,
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

  Future<void> _doSecureKeyStorage() async {
    if (_enclaveStatus == null) {
      try {
        final svc = EnclaveService(
          coreService: CoreService(baseUrl: _effectiveServerUrl),
        );
        final status = await svc.detect();
        if (mounted) setState(() => _enclaveStatus = status);
      } catch (_) {}
    }

    final status = _enclaveStatus;
    if (status == null) return;

    if (status.hardwareBacked) {
      await SetupTaskService.markComplete(SetupTask.secureKeyStorage);
      await _load();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Keys secured: ${status.backingLabel}'),
          backgroundColor: MobileColors.success,
        ),
      );
      return;
    }

    // Not hardware-backed — show options sheet
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (ctx) => Container(
        decoration: const BoxDecoration(
          color: MobileColors.surface,
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(
                width: 36,
                height: 4,
                decoration: BoxDecoration(
                  color: MobileColors.border,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              'Current: ${status.backingLabel}',
              style: const TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 15,
                fontWeight: FontWeight.w700,
              ),
            ),
            if (status.tpmPresent == true && status.tpmEnabled == false) ...[
              const SizedBox(height: 8),
              Text(
                'A TPM was detected but not enabled. Enable it in BIOS/UEFI for hardware protection.',
                style: TextStyle(color: MobileColors.textSecondary, fontSize: 13, height: 1.5),
              ),
            ],
            const SizedBox(height: 20),
            ListTile(
              leading: const Icon(Icons.devices_other, color: MobileColors.primary),
              title: const Text('Migrate to a different device', style: TextStyle(color: MobileColors.textPrimary, fontWeight: FontWeight.w600)),
              subtitle: Text('Keep this task open as a reminder.', style: TextStyle(color: MobileColors.textSecondary)),
              onTap: () => Navigator.pop(ctx),
            ),
            ListTile(
              leading: Icon(Icons.cloud_outlined, color: MobileColors.textSecondary),
              title: const Text('Cloud HSM — Coming Soon', style: TextStyle(color: MobileColors.textSecondary)),
              trailing: _soonBadge(),
              onTap: null,
            ),
            ListTile(
              leading: const Icon(Icons.check_circle_outline, color: MobileColors.primary),
              title: const Text('Continue with software storage', style: TextStyle(color: MobileColors.textPrimary, fontWeight: FontWeight.w600)),
              onTap: () async {
                Navigator.pop(ctx);
                await SetupTaskService.markComplete(SetupTask.secureKeyStorage);
                await _load();
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _soonBadge() => Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
        decoration: BoxDecoration(
          color: MobileColors.border,
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          'SOON',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 9,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.0,
          ),
        ),
      );

  Future<void> _doInviteContacts() async {
    String? oobiUrl;
    try {
      final svc = CoreService(baseUrl: _effectiveServerUrl);
      final oobi = await svc.getOobi();
      svc.dispose();
      oobiUrl = oobi.oobiUrl;
    } catch (_) {}

    if (!mounted) return;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => Padding(
        padding: EdgeInsets.fromLTRB(
            20, 20, 20, MediaQuery.of(ctx).viewInsets.bottom + 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Invite Contacts',
              style: TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 18,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Share your Identity Address with people you trust.',
              style: TextStyle(
                  color: MobileColors.textSecondary, fontSize: 13),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: MobileColors.surfaceSecondary,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: MobileColors.border),
              ),
              child: SelectableText(
                oobiUrl ??
                    'Could not fetch your address. Is the backend running?',
                style: TextStyle(
                  color: oobiUrl != null
                      ? MobileColors.primary
                      : MobileColors.error,
                  fontSize: 12,
                  height: 1.4,
                ),
              ),
            ),
            const SizedBox(height: 16),
            if (oobiUrl != null)
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () async {
                    await SetupTaskService.markComplete(
                        SetupTask.inviteContacts);
                    if (ctx.mounted) Navigator.of(ctx).pop();
                    _load();
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: MobileColors.primary,
                    foregroundColor: MobileColors.textOnPrimary,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                  child: const Text('Mark as Done',
                      style: TextStyle(
                          fontSize: 16, fontWeight: FontWeight.w600)),
                ),
              ),
          ],
        ),
      ),
    );
  }


  IconData _taskIcon(SetupTask task) {
    switch (task) {
      case SetupTask.connectRemoteBrain:
        return Icons.cloud_outlined;
      case SetupTask.backupSeedPhrase:
        return Icons.key_outlined;
      case SetupTask.setupAuthentication:
        return Icons.lock_outlined;
      case SetupTask.secureKeyStorage:
        return Icons.shield_outlined;
      case SetupTask.inviteContacts:
        return Icons.people_outline;
    }
  }
}
