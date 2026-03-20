import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import '../theme/app_theme.dart';
import '../crypto/bip39.dart';
import '../services/keri_service.dart';
import '../services/core_service.dart';
import '../services/secure_key_store.dart';
import '../services/backend_process_service.dart';
import '../config/agent_config.dart';

enum WizardStep {
  seedDisplay,
  verifySeed,
  profile,
  creatingIdentity,
  identityCreated,
  addContacts,
  setupComplete,
}

class SetupWizardScreen extends StatefulWidget {
  final VoidCallback onComplete;
  final KeriService keriService;

  const SetupWizardScreen({
    super.key,
    required this.onComplete,
    required this.keriService,
  });

  @override
  State<SetupWizardScreen> createState() => _SetupWizardScreenState();
}

class _SetupWizardScreenState extends State<SetupWizardScreen> {
  WizardStep _currentStep = WizardStep.seedDisplay;
  List<String> _mnemonic = [];
  String? _aid;
  String? _errorMessage;

  // A3 — verify
  int _verifyWordIndex1 = 3;
  int _verifyWordIndex2 = 8;
  final _verifyController1 = TextEditingController();
  final _verifyController2 = TextEditingController();
  bool _verifyError = false;
  bool _backupVerified = false;

  // A4 — profile
  final _firstNameController = TextEditingController();
  final _lastNameController = TextEditingController();
  final _middleNameController = TextEditingController();
  final _displayNameController = TextEditingController();
  String? _profileFormError;

  // A5 — processing steps (0 = not started, 1–4 = each step done)
  int _processingStep = 0;

  // A6/A8
  String _displayName = '';
  int _contactsAdded = 0;

  // A7 — OOBI for invite
  String? _oobiUrl;

  @override
  void initState() {
    super.initState();
    _generateSeedPhrase();
  }

  @override
  void dispose() {
    _verifyController1.dispose();
    _verifyController2.dispose();
    _firstNameController.dispose();
    _lastNameController.dispose();
    _middleNameController.dispose();
    _displayNameController.dispose();
    super.dispose();
  }

  void _generateSeedPhrase() {
    final mnemonic = Bip39.generateMnemonic();
    final wordCount = mnemonic.length;
    setState(() {
      _mnemonic = mnemonic;
      _verifyWordIndex1 = 3;
      _verifyWordIndex2 = wordCount > 8 ? 8 : wordCount - 1;
    });
  }

  void _proceedToVerify() {
    setState(() {
      _verifyController1.clear();
      _verifyController2.clear();
      _verifyError = false;
      _currentStep = WizardStep.verifySeed;
    });
  }

  void _verifyAndProceedToProfile() {
    final word1 = _verifyController1.text.trim().toLowerCase();
    final word2 = _verifyController2.text.trim().toLowerCase();
    if (word1 != _mnemonic[_verifyWordIndex1] ||
        word2 != _mnemonic[_verifyWordIndex2]) {
      setState(() => _verifyError = true);
      return;
    }
    setState(() {
      _backupVerified = true;
      _currentStep = WizardStep.profile;
    });
  }

  Future<void> _skipVerificationWithWarning() async {
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.corePending, width: 1),
        ),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: AppColors.corePending, size: 28),
            SizedBox(width: 12),
            Expanded(
              child: Text(
                'SKIP BACKUP VERIFICATION',
                style: TextStyle(
                  color: AppColors.corePending,
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.0,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ],
        ),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'If you skip verification and lose your seed phrase, your identity CANNOT be recovered.',
              style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                height: 1.6,
                fontFamily: 'monospace',
              ),
            ),
            SizedBox(height: 12),
            Text(
              '- All credentials tied to this identity will be permanently lost\n'
              '- All signed data will become unverifiable\n'
              '- No one, including you, can restore access',
              style: TextStyle(
                color: AppColors.coreInactive,
                fontSize: 12,
                height: 1.6,
                fontFamily: 'monospace',
              ),
            ),
            SizedBox(height: 16),
            Text(
              'By proceeding, you accept full liability for any loss resulting from an unverified backup.',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                height: 1.5,
                fontFamily: 'monospace',
                fontStyle: FontStyle.italic,
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text(
              'GO BACK',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.corePending,
              foregroundColor: AppColors.primary,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            ),
            child: const Text(
              'I ACCEPT THE RISK',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.0,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      setState(() {
        _backupVerified = false;
        _currentStep = WizardStep.profile;
      });
    }
  }

  void _submitProfile() {
    final firstName = _firstNameController.text.trim();
    final lastName = _lastNameController.text.trim();
    if (firstName.isEmpty) {
      setState(() => _profileFormError = 'First name is required.');
      return;
    }
    if (lastName.isEmpty) {
      setState(() => _profileFormError = 'Last name is required.');
      return;
    }
    setState(() => _profileFormError = null);
    _performInception(firstName: firstName, lastName: lastName);
  }

  Future<void> _performInception({
    required String firstName,
    required String lastName,
  }) async {
    final middleName = _middleNameController.text.trim();
    final displayName = _displayNameController.text.trim().isNotEmpty
        ? _displayNameController.text.trim()
        : '$firstName $lastName'.trim();

    // Build full name including middle if provided
    final fullName = middleName.isNotEmpty
        ? '$firstName $middleName $lastName'.trim()
        : '$firstName $lastName'.trim();

    setState(() {
      _processingStep = 1;
      _currentStep = WizardStep.creatingIdentity;
      _errorMessage = null;
    });

    await Future.delayed(const Duration(milliseconds: 400));
    setState(() => _processingStep = 2);

    try {
      final result = await widget.keriService.inceptAid(
        name: 'default',
        code: _mnemonic.join(' '),
      );

      setState(() => _processingStep = 3);

      await SecureKeyStore.saveMnemonic(_mnemonic);

      // Save profile to backend (best-effort — non-fatal if it fails)
      try {
        final coreService = CoreService(baseUrl: AgentConfig.coreBaseUrl);
        await coreService.saveProfile(ProfileResponse(
          fullName: fullName,
          givenName: firstName,
          familyName: lastName,
        ));
        coreService.dispose();
      } catch (_) {}

      setState(() => _processingStep = 4);
      await Future.delayed(const Duration(milliseconds: 700));

      setState(() {
        _aid = result.aid;
        _displayName = displayName;
        _currentStep = WizardStep.identityCreated;
      });

      // Pre-fetch OOBI for A7 invite flow
      _fetchOobi();
    } catch (e) {
      String errorMsg = e.toString();
      if (errorMsg.contains('KERI_BRIDGE_NOT_AVAILABLE')) {
        final loadReason = RegExp(r'\((.+?)\)\. This is required')
            .firstMatch(errorMsg)?.group(1) ?? 'unknown';
        errorMsg =
            'The native KERI engine could not be loaded on this device. '
            'Please rebuild the app using the Codemagic CI/CD pipeline.\n\n'
            'Diagnostic: $loadReason';
      } else if (errorMsg.contains('UnimplementedError') ||
          errorMsg.contains('Placeholder')) {
        errorMsg =
            'The native KERI engine is not available in this build. '
            'Please rebuild using the Codemagic CI/CD pipeline.';
      } else if (errorMsg.contains('SocketException') ||
          errorMsg.contains('Connection refused') ||
          errorMsg.contains('Connection reset') ||
          errorMsg.contains('TimeoutException')) {
        if (!kIsWeb && BackendProcessService.isDesktopPlatform) {
          final backendError = BackendProcessService.instance.startupError;
          errorMsg = backendError ??
              'Cannot connect to the identity backend (127.0.0.1:5000). '
              'Please ensure Python 3.10+ is installed and try restarting the app.';
        } else {
          errorMsg =
              'Cannot reach the Identity Agent server. '
              'Please make sure your server is running and try again.';
        }
      }
      setState(() {
        _errorMessage = errorMsg;
        _processingStep = 0;
        _currentStep = WizardStep.profile;
      });
    }
  }

  Future<void> _fetchOobi() async {
    try {
      final coreService = CoreService(baseUrl: AgentConfig.coreBaseUrl);
      final oobi = await coreService.getOobi();
      coreService.dispose();
      if (mounted) setState(() => _oobiUrl = oobi.oobiUrl);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: _buildCurrentStep(),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildCurrentStep() {
    switch (_currentStep) {
      case WizardStep.seedDisplay:
        return _buildSeedDisplay();
      case WizardStep.verifySeed:
        return _buildSeedVerify();
      case WizardStep.profile:
        return _buildProfile();
      case WizardStep.creatingIdentity:
        return _buildCreating();
      case WizardStep.identityCreated:
        return _buildIdentityCreated();
      case WizardStep.addContacts:
        return _buildAddContacts();
      case WizardStep.setupComplete:
        return _buildSetupComplete();
    }
  }

  // ── A2: Seed Phrase ──────────────────────────────────────────────────────────

  Widget _buildSeedDisplay() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: AppColors.corePending.withOpacity(0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: AppColors.corePending.withOpacity(0.3),
              width: 1,
            ),
          ),
          child: const Row(
            children: [
              Icon(Icons.warning_amber_rounded,
                  color: AppColors.corePending, size: 20),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Your master key — store it safely.',
                  style: TextStyle(
                    color: AppColors.corePending,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'These 12 words are the only way to recover your identity if you lose this device. Never share them. Never store them on this device.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 13,
            height: 1.6,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 20),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: AppColors.corePending.withOpacity(0.3),
              width: 1,
            ),
          ),
          child: Column(
            children: [
              for (int row = 0; row < 4; row++)
                Padding(
                  padding: EdgeInsets.only(bottom: row < 3 ? 12 : 0),
                  child: Row(
                    children: [
                      for (int col = 0; col < 3; col++)
                        Expanded(
                          child: Padding(
                            padding: EdgeInsets.only(left: col > 0 ? 8 : 0),
                            child: _buildWordCell(row * 3 + col),
                          ),
                        ),
                    ],
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        _buildBackupOption(
          icon: '✍️',
          title: 'Write it on paper',
          subtitle: 'Keep it somewhere physically safe. Fireproof safe, safety deposit box, etc.',
        ),
        const SizedBox(height: 8),
        _buildBackupOption(
          icon: '🔄',
          title: 'Generate a new phrase',
          subtitle: 'Start over with a different seed phrase.',
          isAction: true,
          onTap: () {
            _generateSeedPhrase();
            setState(() {});
          },
        ),
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _proceedToVerify,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              "I'VE WRITTEN IT DOWN — CONTINUE",
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.2,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildWordCell(int index) {
    if (index >= _mnemonic.length) return const SizedBox.shrink();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border, width: 1),
      ),
      child: Row(
        children: [
          Text(
            '${index + 1}.',
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              _mnemonic[index],
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 13,
                fontWeight: FontWeight.w600,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBackupOption({
    required String icon,
    required String title,
    required String subtitle,
    bool isAction = false,
    VoidCallback? onTap,
  }) {
    final child = Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.border, width: 1),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(icon, style: const TextStyle(fontSize: 18)),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: isAction ? AppColors.accent : AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: const TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 11,
                    height: 1.4,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
    if (onTap != null) {
      return GestureDetector(onTap: onTap, child: child);
    }
    return child;
  }

  // ── A3: Verify Backup ────────────────────────────────────────────────────────

  Widget _buildSeedVerify() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'VERIFY BACKUP',
          style: TextStyle(
            color: AppColors.textMuted,
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 1.5,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Confirm you have backed up your seed phrase by entering the requested words.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 13,
            height: 1.5,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Word #${_verifyWordIndex1 + 1}',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.0,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 8),
              _buildVerifyField(_verifyController1, _verifyWordIndex1 + 1),
              const SizedBox(height: 20),
              Text(
                'Word #${_verifyWordIndex2 + 1}',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.0,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 8),
              _buildVerifyField(_verifyController2, _verifyWordIndex2 + 1),
            ],
          ),
        ),
        if (_verifyError) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.coreInactive.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.coreInactive.withOpacity(0.3)),
            ),
            child: const Row(
              children: [
                Icon(Icons.close, color: AppColors.coreInactive, size: 18),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Words do not match. Check your backup and try again.',
                    style: TextStyle(
                      color: AppColors.coreInactive,
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _verifyAndProceedToProfile,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'VERIFY & CONTINUE',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton(
            onPressed: _skipVerificationWithWarning,
            style: OutlinedButton.styleFrom(
              foregroundColor: AppColors.corePending,
              side: const BorderSide(color: AppColors.corePending, width: 1),
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
            child: const Text(
              'SKIP VERIFICATION',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () => setState(() => _currentStep = WizardStep.seedDisplay),
            child: const Text(
              'GO BACK',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 12,
                letterSpacing: 1.0,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildVerifyField(TextEditingController controller, int wordNum) {
    return TextField(
      controller: controller,
      style: const TextStyle(
        color: AppColors.textPrimary,
        fontSize: 16,
        fontFamily: 'monospace',
      ),
      decoration: InputDecoration(
        hintText: 'Enter word #$wordNum',
        hintStyle: TextStyle(
          color: AppColors.textMuted.withOpacity(0.5),
          fontFamily: 'monospace',
        ),
        filled: true,
        fillColor: AppColors.primary,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.accent),
        ),
      ),
      autocorrect: false,
      enableSuggestions: false,
    );
  }

  // ── A4: Profile ──────────────────────────────────────────────────────────────

  Widget _buildProfile() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'TELL US YOUR NAME.',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 20,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'This is how contacts will know you.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 13,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildProfileField(
                controller: _firstNameController,
                label: 'FIRST NAME',
                hint: 'First name',
                required: true,
              ),
              const SizedBox(height: 16),
              _buildProfileField(
                controller: _lastNameController,
                label: 'LAST NAME',
                hint: 'Last name',
                required: true,
              ),
              const SizedBox(height: 16),
              _buildProfileField(
                controller: _middleNameController,
                label: 'MIDDLE NAME',
                hint: 'Optional',
                required: false,
              ),
              const SizedBox(height: 16),
              _buildProfileField(
                controller: _displayNameController,
                label: 'DISPLAY NAME',
                hint: 'What contacts will see (defaults to First Last)',
                required: false,
              ),
            ],
          ),
        ),
        if (_profileFormError != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.coreInactive.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.coreInactive.withOpacity(0.3)),
            ),
            child: Row(
              children: [
                const Icon(Icons.error_outline, color: AppColors.coreInactive, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _profileFormError!,
                    style: const TextStyle(
                      color: AppColors.coreInactive,
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
        if (_errorMessage != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.coreInactive.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Text(
              _errorMessage!,
              style: const TextStyle(
                color: AppColors.coreInactive,
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _submitProfile,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'SAVE & CREATE IDENTITY',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () => setState(() => _currentStep = WizardStep.verifySeed),
            child: const Text(
              'GO BACK',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 12,
                letterSpacing: 1.0,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildProfileField({
    required TextEditingController controller,
    required String label,
    required String hint,
    required bool required,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              label,
              style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w600,
                letterSpacing: 1.2,
                fontFamily: 'monospace',
              ),
            ),
            if (required) ...[
              const SizedBox(width: 4),
              const Text(
                '*',
                style: TextStyle(
                  color: AppColors.coreInactive,
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 8),
        TextField(
          controller: controller,
          style: const TextStyle(
            color: AppColors.textPrimary,
            fontSize: 15,
            fontFamily: 'monospace',
          ),
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: TextStyle(
              color: AppColors.textMuted.withOpacity(0.5),
              fontFamily: 'monospace',
              fontSize: 13,
            ),
            filled: true,
            fillColor: AppColors.primary,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: const BorderSide(color: AppColors.border),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: const BorderSide(color: AppColors.border),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: const BorderSide(color: AppColors.accent),
            ),
            contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          ),
          autocorrect: false,
        ),
      ],
    );
  }

  // ── A5: Creating Identity (Processing) ──────────────────────────────────────

  Widget _buildCreating() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 32),
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: AppColors.accent.withOpacity(0.12),
            borderRadius: BorderRadius.circular(20),
          ),
          child: const Center(
            child: SizedBox(
              width: 40,
              height: 40,
              child: CircularProgressIndicator(
                color: AppColors.accent,
                strokeWidth: 3,
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
        const Text(
          'SETTING UP YOUR IDENTITY',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 18,
            fontWeight: FontWeight.w700,
            letterSpacing: 2.0,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 32),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: Column(
            children: [
              _buildProcessingRow(1, 'Generating your keys...'),
              const SizedBox(height: 14),
              _buildProcessingRow(2, 'Creating your identity on the network...'),
              const SizedBox(height: 14),
              _buildProcessingRow(3, 'Saving keys to secure storage...'),
              const SizedBox(height: 14),
              _buildProcessingRow(4, 'Enrolling in identity protection...'),
            ],
          ),
        ),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildProcessingRow(int step, String label) {
    final done = _processingStep > step;
    final active = _processingStep == step;
    return Row(
      children: [
        SizedBox(
          width: 22,
          height: 22,
          child: active
              ? const CircularProgressIndicator(
                  strokeWidth: 2,
                  color: AppColors.accent,
                )
              : Icon(
                  done ? Icons.check_circle : Icons.circle_outlined,
                  color: done
                      ? AppColors.coreActive
                      : AppColors.textMuted.withOpacity(0.3),
                  size: 20,
                ),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Text(
            label,
            style: TextStyle(
              color: done || active
                  ? AppColors.textPrimary
                  : AppColors.textMuted,
              fontSize: 13,
              fontFamily: 'monospace',
              fontWeight: done || active ? FontWeight.w600 : FontWeight.w400,
            ),
          ),
        ),
      ],
    );
  }

  // ── A6: Identity Created ─────────────────────────────────────────────────────

  Widget _buildIdentityCreated() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 16),
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: AppColors.coreActive.withOpacity(0.12),
            borderRadius: BorderRadius.circular(40),
            border: Border.all(
              color: AppColors.coreActive.withOpacity(0.3),
              width: 2,
            ),
          ),
          child: const Icon(
            Icons.person,
            color: AppColors.coreActive,
            size: 44,
          ),
        ),
        const SizedBox(height: 20),
        Text(
          _displayName.isNotEmpty ? _displayName : 'Your Identity',
          style: const TextStyle(
            color: AppColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Your identity is active.',
          style: TextStyle(
            color: AppColors.coreActive,
            fontSize: 14,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 24),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'YOUR IDENTIFIER (AID)',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 8),
              SelectableText(
                _aid ?? '',
                style: const TextStyle(
                  color: AppColors.accent,
                  fontSize: 11,
                  fontFamily: 'monospace',
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'This is your permanent identifier. Share it as your digital address.',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 11,
                  fontFamily: 'monospace',
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 28),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: () => setState(() => _currentStep = WizardStep.addContacts),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'CONTINUE SETUP',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
      ],
    );
  }

  // ── A7: Add Contacts ─────────────────────────────────────────────────────────

  Widget _buildAddContacts() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'ADD YOUR FIRST CONTACTS.',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 20,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.2,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Add contacts to protect your identity.',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                  fontFamily: 'monospace',
                ),
              ),
              SizedBox(height: 12),
              Text(
                'Your Identity Agent works best when trusted people you know are also using it. Your agents help each other behind the scenes — making each identity more trusted and easier to recover if something goes wrong.',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  height: 1.6,
                  fontFamily: 'monospace',
                ),
              ),
              SizedBox(height: 12),
              _BulletPoint(text: 'They help verify your identity is genuine.'),
              SizedBox(height: 6),
              _BulletPoint(text: 'If you ever get locked out, trusted contacts can help you recover.'),
              SizedBox(height: 12),
              Text(
                'We recommend inviting at least 3 contacts now. 7 is ideal.',
                style: TextStyle(
                  color: AppColors.accent,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppColors.coreActive.withOpacity(0.06),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: AppColors.coreActive.withOpacity(0.2),
              width: 1,
            ),
          ),
          child: const Row(
            children: [
              Icon(Icons.shield_outlined, color: AppColors.coreActive, size: 18),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Grape ID is already protecting your identity. Adding personal contacts makes it even stronger.',
                  style: TextStyle(
                    color: AppColors.coreActive,
                    fontSize: 11,
                    fontFamily: 'monospace',
                    height: 1.4,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _showInviteDialog,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'INVITE CONTACTS',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () => setState(() => _currentStep = WizardStep.setupComplete),
            child: const Text(
              'SKIP FOR NOW',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 12,
                letterSpacing: 1.0,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _showInviteDialog() async {
    final url = _oobiUrl ?? 'Fetching your address...';
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
            fontSize: 15,
            fontWeight: FontWeight.w700,
            fontFamily: 'monospace',
            letterSpacing: 1.0,
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Share your Identity Address (OOBI) with people you trust:',
              style: TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border),
              ),
              child: SelectableText(
                url,
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
          if (_oobiUrl != null)
            TextButton(
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: _oobiUrl!));
                if (ctx.mounted) Navigator.of(ctx).pop();
                setState(() => _contactsAdded++);
              },
              child: const Text(
                'COPY & CLOSE',
                style: TextStyle(
                  color: AppColors.accent,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          TextButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              setState(() => _currentStep = WizardStep.setupComplete);
            },
            child: const Text(
              'DONE',
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

  // ── A8: Setup Complete ───────────────────────────────────────────────────────

  Widget _buildSetupComplete() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 16),
        const Text(
          "YOU'RE ALL SET.",
          style: TextStyle(
            color: AppColors.coreActive,
            fontSize: 24,
            fontWeight: FontWeight.w700,
            letterSpacing: 2.0,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppColors.border, width: 1),
          ),
          child: Column(
            children: [
              _buildSummaryRow(true, 'Identity created'),
              const SizedBox(height: 12),
              _buildSummaryRow(true, 'Keys secured on this device'),
              const SizedBox(height: 12),
              _buildSummaryRow(
                _backupVerified,
                _backupVerified
                    ? 'Seed phrase backed up'
                    : 'Backup not verified — consider doing this soon',
              ),
              const SizedBox(height: 12),
              _buildSummaryRow(true, 'Identity protection active (Grape ID)'),
              const SizedBox(height: 12),
              _buildSummaryRow(
                _contactsAdded > 0,
                _contactsAdded > 0
                    ? 'Contacts: $_contactsAdded added'
                    : 'No contacts yet — add some when you\'re ready',
              ),
            ],
          ),
        ),
        const SizedBox(height: 32),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: widget.onComplete,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: AppColors.primary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'OPEN DASHBOARD',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSummaryRow(bool ok, String label) {
    return Row(
      children: [
        Icon(
          ok ? Icons.check_circle : Icons.warning_amber_rounded,
          color: ok ? AppColors.coreActive : AppColors.corePending,
          size: 20,
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            label,
            style: TextStyle(
              color: ok ? AppColors.textPrimary : AppColors.corePending,
              fontSize: 13,
              fontFamily: 'monospace',
            ),
          ),
        ),
      ],
    );
  }
}

class _BulletPoint extends StatelessWidget {
  final String text;
  const _BulletPoint({required this.text});

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('• ', style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace')),
        Expanded(
          child: Text(
            text,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontSize: 12,
              height: 1.5,
              fontFamily: 'monospace',
            ),
          ),
        ),
      ],
    );
  }
}
