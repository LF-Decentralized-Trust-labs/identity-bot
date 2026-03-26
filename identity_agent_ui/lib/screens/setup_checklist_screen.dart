import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../theme/app_theme.dart';
import '../services/setup_task_service.dart';
import '../services/preferences_service.dart';
import '../services/keri_service.dart';
import '../services/core_service.dart';
import '../services/enclave_service.dart';
import '../services/secure_key_store.dart';
import '../services/identity_level_service.dart';
import '../services/pin_password_service.dart';
import '../services/local_auth_service.dart';

/// Internal page state — all pages render inside the same modal container.
enum _Page { taskList, backupSeed, seedWords, setupAuth, inviteContacts, connectBrain }

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
  _Page _page = _Page.taskList;

  // Auth setup state
  ActiveFactors? _authFactors;
  BiometricAvailability _fpState = BiometricAvailability.unavailable;
  BiometricAvailability _faceState = BiometricAvailability.unavailable;
  String? _authExpanded; // 'pin' or 'password' or null
  final _pinCtrl = TextEditingController();
  final _pinConfirmCtrl = TextEditingController();
  final _pwCtrl = TextEditingController();
  final _pwConfirmCtrl = TextEditingController();
  String? _authError;
  bool _pwObscure = true;

  // Invite contacts state
  String? _oobiUrl;
  String? _inviterName;
  bool _inviteCopied = false;
  int _totalContacts = 0;
  int _trustedContacts = 0;

  // Connect brain state
  final _brainUrlCtrl = TextEditingController();
  String? _brainError;
  bool _brainConnecting = false;

  // Seed display state
  bool _seedConfirmed = false;

  bool get _needsRemoteBrain =>
      widget.hostingChoice == HostingChoice.keysHereBrainLater;

  List<SetupTask> get _tasks =>
      SetupTaskService.orderedTasks(needsRemoteBrain: _needsRemoteBrain, includeSecureKeyStorage: false);

  String get _baseUrl => widget.serverUrl ?? 'http://127.0.0.1:5000';

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _pinCtrl.dispose();
    _pinConfirmCtrl.dispose();
    _pwCtrl.dispose();
    _pwConfirmCtrl.dispose();
    _brainUrlCtrl.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final s = await SetupTaskService.loadState(_tasks);
    if (mounted) setState(() { _state = s; _loading = false; });
  }

  void _goBack() {
    setState(() {
      _page = _Page.taskList;
      _authExpanded = null;
      _authError = null;
      _inviteCopied = false;
      _brainError = null;
      _brainConnecting = false;
      _seedConfirmed = false;
    });
    _load();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  BUILD
  // ═══════════════════════════════════════════════════════════════════════════

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: cs.surface,
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 560, maxHeight: 680),
            child: Container(
              decoration: BoxDecoration(
                color: cs.surface,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: cs.outline),
              ),
              clipBehavior: Clip.antiAlias,
              child: Column(
                children: [
                  _buildTopBar(cs),
                  Expanded(
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
                      child: _buildPageContent(cs, isDark),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildTopBar(ColorScheme cs) {
    final showBack = _page != _Page.taskList;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: cs.outline.withOpacity(0.5))),
      ),
      child: Row(
        children: [
          if (showBack)
            IconButton(
              icon: Icon(Icons.arrow_back, size: 18, color: cs.onSurface),
              onPressed: _goBack,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
              tooltip: 'Back',
            ),
          if (showBack) const SizedBox(width: 8),
          Expanded(
            child: Text(
              _pageTitle(),
              style: TextStyle(
                color: cs.onSurface,
                fontSize: 15,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.5,
              ),
            ),
          ),
          IconButton(
            icon: Icon(Icons.close, size: 18, color: cs.onSurface.withOpacity(0.5)),
            onPressed: widget.onDone,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            tooltip: 'Close',
          ),
        ],
      ),
    );
  }

  String _pageTitle() {
    switch (_page) {
      case _Page.taskList: return 'Complete Your Setup';
      case _Page.backupSeed: return 'Back Up Your Seed Phrase';
      case _Page.seedWords: return 'Your Seed Phrase';
      case _Page.setupAuth: return 'Set Up Authentication';
      case _Page.inviteContacts: return 'Add Trusted Contacts';
      case _Page.connectBrain: return 'Connect Remote Server';
    }
  }

  Widget _buildPageContent(ColorScheme cs, bool isDark) {
    switch (_page) {
      case _Page.taskList:
        return _buildTaskList(cs);
      case _Page.backupSeed:
        return _buildBackupSeedPage(cs);
      case _Page.seedWords:
        return _buildSeedWordsPage(cs);
      case _Page.setupAuth:
        return _buildAuthPage(cs);
      case _Page.inviteContacts:
        return _buildInvitePage(cs);
      case _Page.connectBrain:
        return _buildConnectBrainPage(cs);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PAGE: Task List
  // ═══════════════════════════════════════════════════════════════════════════

  Widget _buildTaskList(ColorScheme cs) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'These steps help protect your identity and enable key recovery.',
          style: TextStyle(color: cs.onSurface.withOpacity(0.6), fontSize: 13, height: 1.5),
        ),
        const SizedBox(height: 20),
        if (_loading)
          const Center(child: Padding(
            padding: EdgeInsets.all(32),
            child: CircularProgressIndicator(),
          ))
        else ...[
          ...(_tasks
              .where((t) => !(_state[t] ?? false))
              .map((t) => Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: _buildTaskCard(t, cs),
                  ))),
          if (_tasks.every((t) => _state[t] == true))
            _buildAllDone(cs),
        ],
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: widget.onDone,
            child: Text(
              "I'LL DO THIS LATER",
              style: TextStyle(color: cs.onSurface.withOpacity(0.4), fontSize: 12, letterSpacing: 0.5),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildAllDone(ColorScheme cs) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.coreActive.withOpacity(0.06),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.coreActive.withOpacity(0.2)),
      ),
      child: Column(
        children: [
          const Icon(Icons.check_circle, color: AppColors.coreActive, size: 40),
          const SizedBox(height: 12),
          Text('All setup tasks complete!',
              style: TextStyle(color: cs.onSurface, fontSize: 15, fontWeight: FontWeight.w600)),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: widget.onDone,
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.coreActive,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
              child: const Text('GO TO DASHBOARD', style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 0.5)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTaskCard(SetupTask task, ColorScheme cs) {
    final meta = SetupTaskService.meta(task);
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: meta.isStub ? null : () => _openTask(task),
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest.withOpacity(0.5),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: cs.outline.withOpacity(0.5)),
          ),
          child: Row(
            children: [
              Icon(
                meta.isStub ? Icons.schedule_outlined : Icons.radio_button_unchecked,
                color: meta.isStub ? cs.onSurface.withOpacity(0.3) : cs.primary,
                size: 20,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(meta.title,
                              style: TextStyle(color: cs.onSurface, fontSize: 13, fontWeight: FontWeight.w600)),
                        ),
                        if (meta.isStub)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: cs.onSurface.withOpacity(0.06),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text('SOON',
                                style: TextStyle(color: cs.onSurface.withOpacity(0.35), fontSize: 9, fontWeight: FontWeight.w700, letterSpacing: 0.8)),
                          ),
                        if (meta.isCritical && !meta.isStub)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: AppColors.corePending.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: const Text('IMPORTANT',
                                style: TextStyle(color: AppColors.corePending, fontSize: 9, fontWeight: FontWeight.w700, letterSpacing: 0.8)),
                          ),
                      ],
                    ),
                    const SizedBox(height: 3),
                    Text(meta.description,
                        style: TextStyle(color: cs.onSurface.withOpacity(0.5), fontSize: 11, height: 1.4)),
                  ],
                ),
              ),
              if (!meta.isStub)
                Icon(Icons.chevron_right, color: cs.onSurface.withOpacity(0.3), size: 20),
            ],
          ),
        ),
      ),
    );
  }

  void _openTask(SetupTask task) {
    switch (task) {
      case SetupTask.backupSeedPhrase:
        setState(() => _page = _Page.backupSeed);
      case SetupTask.setupAuthentication:
        _loadAuthState();
        setState(() => _page = _Page.setupAuth);
      case SetupTask.inviteContacts:
        _loadInviteData();
        setState(() => _page = _Page.inviteContacts);
      case SetupTask.connectRemoteBrain:
        setState(() => _page = _Page.connectBrain);
      case SetupTask.secureKeyStorage:
        break; // excluded from checklist
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PAGE: Backup Seed Phrase
  // ═══════════════════════════════════════════════════════════════════════════

  Widget _buildBackupSeedPage(ColorScheme cs) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _infoBox(cs,
          icon: Icons.warning_amber_rounded,
          color: AppColors.corePending,
          text: 'Your seed phrase is the only way to recover your identity if you lose this device.',
        ),
        const SizedBox(height: 20),
        // Option: Write it down
        _actionTile(cs,
          icon: Icons.edit_note,
          title: 'Write it down on paper',
          subtitle: 'View your 12 words and write them somewhere safe.',
          onTap: () async {
            setState(() => _page = _Page.seedWords);
          },
        ),
        const SizedBox(height: 10),
        // Option: NFC
        _actionTile(cs,
          icon: Icons.nfc,
          title: 'Write to NFC tag',
          subtitle: 'Available on the Identity Agent mobile app.',
          onTap: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('NFC tag writing requires the mobile app.')),
            );
          },
        ),
      ],
    );
  }

  Widget _buildSeedWordsPage(ColorScheme cs) {
    return FutureBuilder<List<String>?>(
      future: SecureKeyStore.loadMnemonic(),
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Center(child: Padding(padding: EdgeInsets.all(32), child: CircularProgressIndicator()));
        }
        final words = snapshot.data;
        if (words == null || words.isEmpty) {
          return _infoBox(cs,
            icon: Icons.error_outline,
            color: AppColors.coreInactive,
            text: 'Could not retrieve seed phrase. It may have been cleared from secure storage.',
          );
        }
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _infoBox(cs,
              icon: Icons.warning_amber_rounded,
              color: AppColors.corePending,
              text: 'Never share these words. Never store them digitally. Write them on paper and keep them safe.',
            ),
            const SizedBox(height: 20),
            _buildWordGrid(words, cs),
            const SizedBox(height: 20),
            // Confirmation checkbox
            GestureDetector(
              onTap: () => setState(() => _seedConfirmed = !_seedConfirmed),
              child: Row(
                children: [
                  Icon(
                    _seedConfirmed ? Icons.check_box : Icons.check_box_outline_blank,
                    color: _seedConfirmed ? AppColors.coreActive : cs.onSurface.withOpacity(0.4),
                    size: 20,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      "I've written these words down in a safe place.",
                      style: TextStyle(color: cs.onSurface.withOpacity(0.7), fontSize: 13),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: _seedConfirmed
                    ? () async {
                        await SetupTaskService.markComplete(SetupTask.backupSeedPhrase);
                        _goBack();
                      }
                    : null,
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.coreActive,
                  foregroundColor: Colors.white,
                  disabledBackgroundColor: cs.onSurface.withOpacity(0.08),
                  disabledForegroundColor: cs.onSurface.withOpacity(0.3),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                child: const Text('MARK AS BACKED UP', style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 0.5)),
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _buildWordGrid(List<String> words, ColorScheme cs) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest.withOpacity(0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.corePending.withOpacity(0.2)),
      ),
      child: Column(
        children: [
          for (int row = 0; row < (words.length / 3).ceil(); row++)
            Padding(
              padding: EdgeInsets.only(bottom: row < (words.length / 3).ceil() - 1 ? 8 : 0),
              child: Row(
                children: [
                  for (int col = 0; col < 3; col++)
                    if (row * 3 + col < words.length)
                      Expanded(
                        child: Padding(
                          padding: EdgeInsets.only(left: col > 0 ? 6 : 0),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                            decoration: BoxDecoration(
                              color: cs.surface,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: cs.outline.withOpacity(0.5)),
                            ),
                            child: Row(
                              children: [
                                Text('${row * 3 + col + 1}.',
                                    style: TextStyle(color: cs.onSurface.withOpacity(0.35), fontSize: 10)),
                                const SizedBox(width: 4),
                                Expanded(
                                  child: Text(words[row * 3 + col],
                                      style: TextStyle(color: cs.onSurface, fontSize: 12, fontWeight: FontWeight.w600)),
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

  // ═══════════════════════════════════════════════════════════════════════════
  //  PAGE: Auth Setup
  // ═══════════════════════════════════════════════════════════════════════════

  Future<void> _loadAuthState() async {
    try {
      final f = await IdentityLevelService.loadFactors();
      final fp = await LocalAuthService.fingerprintAvailability();
      final face = await LocalAuthService.faceAvailability();
      if (mounted) {
        setState(() {
          _authFactors = f;
          _fpState = fp;
          _faceState = face;
        });
      }
    } catch (_) {}
  }

  Widget _buildAuthPage(ColorScheme cs) {
    if (_authFactors == null) {
      return const Center(child: Padding(padding: EdgeInsets.all(32), child: CircularProgressIndicator()));
    }
    final f = _authFactors!;
    final enabledCount = [f.hasPassword, f.hasPin,
      _fpState == BiometricAvailability.available,
      _faceState == BiometricAvailability.available,
    ].where((v) => v).length;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Protect your identity from unauthorized access. Enabling all methods is recommended.${enabledCount < 2 ? " (we recommend two)" : ""}.',
          style: TextStyle(color: cs.onSurface.withOpacity(0.6), fontSize: 13, height: 1.5),
        ),
        if (enabledCount >= 1) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: AppColors.coreActive.withOpacity(0.06),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.coreActive.withOpacity(0.2)),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.check_circle, color: AppColors.coreActive, size: 16),
                const SizedBox(width: 8),
                Text('$enabledCount method${enabledCount == 1 ? "" : "s"} enabled',
                    style: const TextStyle(color: AppColors.coreActive, fontSize: 12, fontWeight: FontWeight.w600)),
              ],
            ),
          ),
        ],
        const SizedBox(height: 16),

        // ── Password ──────────────────────────────────────────────────────
        _authMethodTile(cs,
          icon: Icons.password_outlined,
          label: 'Password',
          subtitle: f.hasPassword ? 'Enabled' : 'Set a password to lock the app',
          active: f.hasPassword,
          expandKey: 'password',
        ),
        if (_authExpanded == 'password' && !f.hasPassword) _buildPasswordForm(cs),
        const SizedBox(height: 8),

        // ── PIN ───────────────────────────────────────────────────────────
        _authMethodTile(cs,
          icon: Icons.pin_outlined,
          label: 'PIN',
          subtitle: f.hasPin ? 'Enabled' : 'Set a 4–6 digit PIN',
          active: f.hasPin,
          expandKey: 'pin',
        ),
        if (_authExpanded == 'pin' && !f.hasPin) _buildPinForm(cs),
        const SizedBox(height: 8),

        // ── Fingerprint ───────────────────────────────────────────────────
        _authMethodTile(cs,
          icon: Icons.fingerprint,
          label: 'Fingerprint',
          subtitle: _fpState == BiometricAvailability.available
              ? 'Enabled'
              : _fpState == BiometricAvailability.availableNotEnrolled
                  ? 'Supported — enable in OS settings'
                  : 'Not available on this device',
          active: _fpState == BiometricAvailability.available,
          caution: _fpState == BiometricAvailability.availableNotEnrolled,
          unavailable: _fpState == BiometricAvailability.unavailable,
        ),
        const SizedBox(height: 8),

        // ── Face Scan ─────────────────────────────────────────────────────
        _authMethodTile(cs,
          icon: Icons.face_outlined,
          label: 'Face Scan',
          subtitle: _faceState == BiometricAvailability.available
              ? 'Enabled'
              : _faceState == BiometricAvailability.availableNotEnrolled
                  ? 'Supported — enable in OS settings'
                  : 'Not available on this device',
          active: _faceState == BiometricAvailability.available,
          caution: _faceState == BiometricAvailability.availableNotEnrolled,
          unavailable: _faceState == BiometricAvailability.unavailable,
        ),

        if (enabledCount >= 1) ...[
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: () async {
                await SetupTaskService.markComplete(SetupTask.setupAuthentication);
                _goBack();
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.coreActive,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
              child: const Text('DONE', style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 0.5)),
            ),
          ),
        ],
      ],
    );
  }

  Widget _authMethodTile(ColorScheme cs, {
    required IconData icon,
    required String label,
    required String subtitle,
    bool active = false,
    bool caution = false,
    bool unavailable = false,
    String? expandKey,
  }) {
    final Color tileColor;
    final Color tileBorder;
    if (active) {
      tileColor = AppColors.coreActive.withOpacity(0.04);
      tileBorder = AppColors.coreActive.withOpacity(0.25);
    } else if (caution) {
      tileColor = const Color(0xFFFFB74D).withOpacity(0.04);
      tileBorder = const Color(0xFFFFB74D).withOpacity(0.25);
    } else {
      tileColor = cs.surfaceContainerHighest.withOpacity(0.5);
      tileBorder = cs.outline.withOpacity(0.5);
    }

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: (active || unavailable || expandKey == null)
            ? null
            : () => setState(() {
                _authExpanded = _authExpanded == expandKey ? null : expandKey;
                _authError = null;
                _pinCtrl.clear();
                _pinConfirmCtrl.clear();
                _pwCtrl.clear();
                _pwConfirmCtrl.clear();
              }),
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          decoration: BoxDecoration(
            color: tileColor,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: tileBorder),
          ),
          child: Row(
            children: [
              Icon(icon,
                  color: active
                      ? AppColors.coreActive
                      : caution
                          ? const Color(0xFFFFB74D)
                          : unavailable
                              ? cs.onSurface.withOpacity(0.25)
                              : cs.primary,
                  size: 22),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Text(label, style: TextStyle(
                          color: unavailable ? cs.onSurface.withOpacity(0.35) : cs.onSurface,
                          fontSize: 13, fontWeight: FontWeight.w600)),
                      if (active) ...[
                        const SizedBox(width: 6),
                        const Icon(Icons.check_circle, color: AppColors.coreActive, size: 14),
                      ],
                    ]),
                    const SizedBox(height: 2),
                    Text(subtitle, style: TextStyle(
                        color: caution ? const Color(0xFFFFB74D) : cs.onSurface.withOpacity(0.5),
                        fontSize: 11)),
                  ],
                ),
              ),
              if (!active && !unavailable && expandKey != null)
                Icon(
                  _authExpanded == expandKey ? Icons.expand_less : Icons.chevron_right,
                  color: cs.onSurface.withOpacity(0.3), size: 20,
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPasswordForm(ColorScheme cs) {
    return Container(
      margin: const EdgeInsets.only(top: 4),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest.withOpacity(0.3),
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(10),
          bottomRight: Radius.circular(10),
        ),
        border: Border.all(color: cs.outline.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Minimum 8 characters.', style: TextStyle(color: cs.onSurface.withOpacity(0.5), fontSize: 12)),
          const SizedBox(height: 12),
          TextField(
            controller: _pwCtrl,
            obscureText: _pwObscure,
            style: TextStyle(color: cs.onSurface, fontSize: 14),
            decoration: InputDecoration(
              labelText: 'Password',
              errorText: _authError,
              suffixIcon: IconButton(
                icon: Icon(_pwObscure ? Icons.visibility_off_outlined : Icons.visibility_outlined, size: 18),
                onPressed: () => setState(() => _pwObscure = !_pwObscure),
              ),
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _pwConfirmCtrl,
            obscureText: true,
            style: TextStyle(color: cs.onSurface, fontSize: 14),
            decoration: const InputDecoration(labelText: 'Confirm password'),
          ),
          const SizedBox(height: 14),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(
                onPressed: () => setState(() => _authExpanded = null),
                child: Text('Cancel', style: TextStyle(color: cs.onSurface.withOpacity(0.5))),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: () async {
                  final pw = _pwCtrl.text;
                  if (pw.length < 8) { setState(() => _authError = 'Minimum 8 characters'); return; }
                  if (pw != _pwConfirmCtrl.text) { setState(() => _authError = 'Passwords do not match'); return; }
                  await PinPasswordService.setPassword(pw);
                  await IdentityLevelService.refresh();
                  await _loadAuthState();
                  setState(() { _authExpanded = null; _authError = null; });
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: cs.primary,
                  foregroundColor: cs.onPrimary,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
                child: const Text('Save', style: TextStyle(fontWeight: FontWeight.w700)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPinForm(ColorScheme cs) {
    return Container(
      margin: const EdgeInsets.only(top: 4),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest.withOpacity(0.3),
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(10),
          bottomRight: Radius.circular(10),
        ),
        border: Border.all(color: cs.outline.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Enter a 4–6 digit PIN.', style: TextStyle(color: cs.onSurface.withOpacity(0.5), fontSize: 12)),
          const SizedBox(height: 12),
          TextField(
            controller: _pinCtrl,
            obscureText: true,
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly, LengthLimitingTextInputFormatter(6)],
            style: TextStyle(color: cs.onSurface, fontSize: 14),
            decoration: InputDecoration(labelText: 'PIN', errorText: _authError),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _pinConfirmCtrl,
            obscureText: true,
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly, LengthLimitingTextInputFormatter(6)],
            style: TextStyle(color: cs.onSurface, fontSize: 14),
            decoration: const InputDecoration(labelText: 'Confirm PIN'),
          ),
          const SizedBox(height: 14),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              TextButton(
                onPressed: () => setState(() => _authExpanded = null),
                child: Text('Cancel', style: TextStyle(color: cs.onSurface.withOpacity(0.5))),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: () async {
                  final pin = _pinCtrl.text.trim();
                  if (pin.length < 4 || pin.length > 6) { setState(() => _authError = 'PIN must be 4–6 digits'); return; }
                  if (pin != _pinConfirmCtrl.text.trim()) { setState(() => _authError = 'PINs do not match'); return; }
                  await PinPasswordService.setPin(pin);
                  await IdentityLevelService.refresh();
                  await _loadAuthState();
                  setState(() { _authExpanded = null; _authError = null; });
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: cs.primary,
                  foregroundColor: cs.onPrimary,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
                child: const Text('Save', style: TextStyle(fontWeight: FontWeight.w700)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PAGE: Invite Contacts
  // ═══════════════════════════════════════════════════════════════════════════

  Future<void> _loadInviteData() async {
    try {
      final coreService = CoreService(baseUrl: _baseUrl);
      final results = await Future.wait([
        coreService.getOobi(),
        coreService.getProfile(),
        coreService.getContacts(),
      ]);
      coreService.dispose();
      final oobi = results[0] as OobiResponse;
      final profile = results[1] as ProfileResponse;
      final contacts = results[2] as ContactsListResponse;
      if (mounted) {
        setState(() {
          _oobiUrl = oobi.oobiUrl;
          _inviterName = profile.fullName.isNotEmpty ? profile.fullName : null;
          _totalContacts = contacts.contacts.length;
          _trustedContacts = contacts.contacts.where((c) => c.contactType == 'trusted').length;
        });
      }
    } catch (_) {}
  }

  Widget _buildInvitePage(ColorScheme cs) {
    final contactUrl = _oobiUrl ?? '';
    final inviteMessage =
        "Hey! I set up a self-sovereign identity. Will you be one of my trusted contacts? "
        "Add me here: $contactUrl\n\n"
        "Questions? Ask me!";
    final hasEnough = _trustedContacts >= 1;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          "Invite people you trust to be witnesses for your identity. You need at least 1 trusted contact to complete setup (recommended: 7+).",
          style: TextStyle(color: cs.onSurface.withOpacity(0.6), fontSize: 13, height: 1.5),
        ),
        const SizedBox(height: 12),
        // Contact progress
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            color: hasEnough
                ? AppColors.coreActive.withOpacity(0.06)
                : cs.surfaceContainerHighest.withOpacity(0.5),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: hasEnough
                ? AppColors.coreActive.withOpacity(0.2)
                : cs.outline.withOpacity(0.5)),
          ),
          child: Row(
            children: [
              Icon(
                hasEnough ? Icons.check_circle : Icons.people_outline,
                color: hasEnough ? AppColors.coreActive : cs.primary,
                size: 18,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  '$_totalContacts contact${_totalContacts == 1 ? "" : "s"}, '
                  '$_trustedContacts trusted (need 1, recommended 7+)',
                  style: TextStyle(
                    color: hasEnough ? AppColors.coreActive : cs.onSurface.withOpacity(0.7),
                    fontSize: 12, fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              TextButton(
                onPressed: _loadInviteData,
                child: Text('Refresh', style: TextStyle(color: cs.primary, fontSize: 11)),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        // Invite message preview
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest.withOpacity(0.5),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: cs.primary.withOpacity(0.15)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.mail_outline, size: 14, color: cs.primary),
                  const SizedBox(width: 6),
                  Text('INVITE MESSAGE',
                      style: TextStyle(color: cs.primary, fontSize: 10, fontWeight: FontWeight.w700, letterSpacing: 0.8)),
                ],
              ),
              const SizedBox(height: 10),
              Text(inviteMessage,
                  style: TextStyle(color: cs.onSurface.withOpacity(0.6), fontSize: 12, height: 1.5)),
            ],
          ),
        ),
        const SizedBox(height: 14),
        // Copy button
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: inviteMessage));
              setState(() => _inviteCopied = true);
              Future.delayed(const Duration(seconds: 2), () {
                if (mounted) setState(() => _inviteCopied = false);
              });
            },
            icon: Icon(_inviteCopied ? Icons.check : Icons.copy, size: 14),
            label: Text(_inviteCopied ? 'Copied!' : 'Copy Message', style: const TextStyle(fontSize: 12)),
            style: OutlinedButton.styleFrom(
              foregroundColor: _inviteCopied ? AppColors.coreActive : cs.onSurface.withOpacity(0.6),
              side: BorderSide(color: _inviteCopied ? AppColors.coreActive : cs.outline),
              padding: const EdgeInsets.symmetric(vertical: 12),
            ),
          ),
        ),
        if (contactUrl.isNotEmpty) ...[
          const SizedBox(height: 16),
          Center(
            child: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(8),
              ),
              child: QrImageView(
                data: contactUrl,
                version: QrVersions.auto,
                size: 140,
                padding: EdgeInsets.zero,
              ),
            ),
          ),
          const SizedBox(height: 6),
          Center(
            child: Text('Scan to add you as a contact',
                style: TextStyle(color: cs.onSurface.withOpacity(0.35), fontSize: 10)),
          ),
        ],
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: hasEnough
                ? () async {
                    await SetupTaskService.markComplete(SetupTask.inviteContacts);
                    _goBack();
                  }
                : null,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.coreActive,
              foregroundColor: Colors.white,
              disabledBackgroundColor: cs.onSurface.withOpacity(0.08),
              disabledForegroundColor: cs.onSurface.withOpacity(0.3),
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            ),
            child: Text(
              hasEnough ? 'DONE' : 'NEED ${3 - _trustedContacts} MORE TRUSTED CONTACT${3 - _trustedContacts == 1 ? "" : "S"}',
              style: const TextStyle(fontWeight: FontWeight.w700, letterSpacing: 0.3),
            ),
          ),
        ),
        if (!hasEnough) ...[
          const SizedBox(height: 8),
          Center(
            child: Text(
              'Contacts must be marked as "Trusted" in your Contacts screen',
              style: TextStyle(color: cs.onSurface.withOpacity(0.4), fontSize: 11),
            ),
          ),
        ],
      ],
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  PAGE: Connect Remote Brain
  // ═══════════════════════════════════════════════════════════════════════════

  Widget _buildConnectBrainPage(ColorScheme cs) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Enter the URL of your remote server to unlock full features.',
          style: TextStyle(color: cs.onSurface.withOpacity(0.6), fontSize: 13, height: 1.5),
        ),
        const SizedBox(height: 16),
        TextField(
          controller: _brainUrlCtrl,
          style: TextStyle(color: cs.onSurface, fontSize: 13),
          decoration: InputDecoration(
            hintText: 'https://my-server.example.com',
            errorText: _brainError,
          ),
          autocorrect: false,
          keyboardType: TextInputType.url,
        ),
        const SizedBox(height: 20),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _brainConnecting
                ? null
                : () async {
                    final url = _brainUrlCtrl.text.trim();
                    if (url.isEmpty) {
                      setState(() => _brainError = 'Enter a server URL.');
                      return;
                    }
                    setState(() { _brainConnecting = true; _brainError = null; });
                    try {
                      final svc = CoreService(baseUrl: url);
                      await svc.getHealth();
                      svc.dispose();
                      await SetupTaskService.markComplete(SetupTask.connectRemoteBrain);
                      _goBack();
                    } catch (_) {
                      setState(() {
                        _brainConnecting = false;
                        _brainError = 'Could not reach that server. Check the URL.';
                      });
                    }
                  },
            style: ElevatedButton.styleFrom(
              backgroundColor: cs.primary,
              foregroundColor: cs.onPrimary,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            ),
            child: _brainConnecting
                ? const SizedBox(width: 16, height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                : const Text('CONNECT', style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 0.5)),
          ),
        ),
      ],
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  Shared helpers
  // ═══════════════════════════════════════════════════════════════════════════

  Widget _infoBox(ColorScheme cs, {required IconData icon, required Color color, required String text}) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withOpacity(0.06),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(text, style: TextStyle(color: color, fontSize: 12, height: 1.5, fontWeight: FontWeight.w500)),
          ),
        ],
      ),
    );
  }

  Widget _actionTile(ColorScheme cs, {
    required IconData icon,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest.withOpacity(0.5),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: cs.outline.withOpacity(0.5)),
          ),
          child: Row(
            children: [
              Icon(icon, color: cs.primary, size: 22),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title, style: TextStyle(color: cs.onSurface, fontSize: 13, fontWeight: FontWeight.w600)),
                    const SizedBox(height: 2),
                    Text(subtitle, style: TextStyle(color: cs.onSurface.withOpacity(0.5), fontSize: 11)),
                  ],
                ),
              ),
              Icon(Icons.chevron_right, color: cs.onSurface.withOpacity(0.3), size: 20),
            ],
          ),
        ),
      ),
    );
  }
}
