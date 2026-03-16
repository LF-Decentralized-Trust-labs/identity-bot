import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import '../../theme/mobile_theme.dart';
import '../../crypto/bip39.dart';
import '../../services/keri_service.dart';
import '../../services/core_service.dart';
import '../../services/secure_key_store.dart';
import '../../services/backend_process_service.dart';
import '../../config/agent_config.dart';

enum _WizardStep {
  seedDisplay,
  verifySeed,
  profile,
  creatingIdentity,
  identityCreated,
  addContacts,
  setupComplete,
}

class MobileSetupWizardScreen extends StatefulWidget {
  final VoidCallback onComplete;
  final KeriService keriService;

  const MobileSetupWizardScreen({
    super.key,
    required this.onComplete,
    required this.keriService,
  });

  @override
  State<MobileSetupWizardScreen> createState() =>
      _MobileSetupWizardScreenState();
}

class _MobileSetupWizardScreenState extends State<MobileSetupWizardScreen> {
  _WizardStep _currentStep = _WizardStep.seedDisplay;
  List<String> _mnemonic = [];
  String? _aid;
  String? _errorMessage;

  // Verify step
  int _verifyWordIndex1 = 3;
  int _verifyWordIndex2 = 8;
  final _verifyController1 = TextEditingController();
  final _verifyController2 = TextEditingController();
  bool _verifyError = false;
  bool _backupVerified = false;

  // Profile step
  final _firstNameController = TextEditingController();
  final _lastNameController = TextEditingController();
  final _middleNameController = TextEditingController();
  final _displayNameController = TextEditingController();
  String? _profileFormError;

  // Processing steps (0 = not started, 1–4 = each step done)
  int _processingStep = 0;

  // Identity created / contacts
  String _displayName = '';
  int _contactsAdded = 0;

  // OOBI for invite
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
      _currentStep = _WizardStep.verifySeed;
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
      _currentStep = _WizardStep.profile;
    });
  }

  Future<void> _skipVerificationWithWarning() async {
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: MobileColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: MobileColors.warning, width: 1),
        ),
        title: Row(
          children: [
            Icon(Icons.warning_amber_rounded,
                color: MobileColors.warning, size: 28),
            const SizedBox(width: 12),
            const Expanded(
              child: Text(
                'Skip Backup Verification',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 17,
                  fontWeight: FontWeight.w700,
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
                color: MobileColors.textPrimary,
                fontSize: 14,
                height: 1.6,
              ),
            ),
            SizedBox(height: 12),
            Text(
              '- All credentials tied to this identity will be permanently lost\n'
              '- All signed data will become unverifiable\n'
              '- No one, including you, can restore access',
              style: TextStyle(
                color: MobileColors.error,
                fontSize: 13,
                height: 1.6,
              ),
            ),
            SizedBox(height: 16),
            Text(
              'By proceeding, you accept full liability for any loss resulting from an unverified backup.',
              style: TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 13,
                height: 1.5,
                fontStyle: FontStyle.italic,
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text(
              'Go Back',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.warning,
              foregroundColor: MobileColors.textPrimary,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            child: const Text(
              'I Accept the Risk',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      setState(() {
        _backupVerified = false;
        _currentStep = _WizardStep.profile;
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

    final fullName = middleName.isNotEmpty
        ? '$firstName $middleName $lastName'.trim()
        : '$firstName $lastName'.trim();

    setState(() {
      _processingStep = 1;
      _currentStep = _WizardStep.creatingIdentity;
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
        _currentStep = _WizardStep.identityCreated;
      });

      // Pre-fetch OOBI for invite flow
      _fetchOobi();
    } catch (e) {
      String errorMsg = e.toString();

      if (errorMsg.contains('KERI_BRIDGE_NOT_AVAILABLE')) {
        final loadReason = RegExp(r'\((.+?)\)\. This is required')
                .firstMatch(errorMsg)
                ?.group(1) ??
            'unknown';
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
        _currentStep = _WizardStep.profile;
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
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
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
      ),
    );
  }

  Widget _buildCurrentStep() {
    switch (_currentStep) {
      case _WizardStep.seedDisplay:
        return _buildSeedDisplay();
      case _WizardStep.verifySeed:
        return _buildSeedVerify();
      case _WizardStep.profile:
        return _buildProfile();
      case _WizardStep.creatingIdentity:
        return _buildCreating();
      case _WizardStep.identityCreated:
        return _buildIdentityCreated();
      case _WizardStep.addContacts:
        return _buildAddContacts();
      case _WizardStep.setupComplete:
        return _buildSetupComplete();
    }
  }

  // ── Seed Phrase ──────────────────────────────────────────────────────────────

  Widget _buildSeedDisplay() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: MobileColors.warning.withOpacity(0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: MobileColors.warning.withOpacity(0.3),
              width: 1,
            ),
          ),
          child: Row(
            children: [
              Icon(Icons.warning_amber_rounded,
                  color: MobileColors.warning, size: 20),
              const SizedBox(width: 10),
              const Expanded(
                child: Text(
                  'Your master key — store it safely.',
                  style: TextStyle(
                    color: MobileColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
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
            color: MobileColors.textSecondary,
            fontSize: 14,
            height: 1.6,
          ),
        ),
        const SizedBox(height: 20),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: MobileColors.warning.withOpacity(0.3),
              width: 1,
            ),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
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
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              "I've Written It Down — Continue",
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
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
        color: MobileColors.surfaceSecondary,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: MobileColors.border, width: 1),
      ),
      child: Row(
        children: [
          Text(
            '${index + 1}.',
            style: const TextStyle(
              color: MobileColors.textMuted,
              fontSize: 11,
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              _mnemonic[index],
              style: const TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 13,
                fontWeight: FontWeight.w600,
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
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: MobileColors.border, width: 1),
        boxShadow: [
          BoxShadow(
            color: MobileColors.cardShadow,
            blurRadius: 4,
            offset: const Offset(0, 1),
          ),
        ],
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
                    color: isAction ? MobileColors.primary : MobileColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: const TextStyle(
                    color: MobileColors.textSecondary,
                    fontSize: 12,
                    height: 1.4,
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

  // ── Verify Backup ────────────────────────────────────────────────────────────

  Widget _buildSeedVerify() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Verify Backup',
          style: TextStyle(
            color: MobileColors.textMuted,
            fontSize: 13,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.5,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Confirm you have backed up your seed phrase by entering the requested words.',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 15,
            height: 1.5,
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border, width: 1),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Word #${_verifyWordIndex1 + 1}',
                style: const TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 8),
              _buildVerifyField(_verifyController1, _verifyWordIndex1 + 1),
              const SizedBox(height: 20),
              Text(
                'Word #${_verifyWordIndex2 + 1}',
                style: const TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
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
              color: MobileColors.error.withOpacity(0.08),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: MobileColors.error.withOpacity(0.3)),
            ),
            child: const Row(
              children: [
                Icon(Icons.close, color: MobileColors.error, size: 18),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Words do not match. Check your backup and try again.',
                    style: TextStyle(
                      color: MobileColors.error,
                      fontSize: 13,
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
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Verify & Continue',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
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
              foregroundColor: MobileColors.warning,
              side: BorderSide(color: MobileColors.warning, width: 1),
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Skip Verification',
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () => setState(() => _currentStep = _WizardStep.seedDisplay),
            child: const Text(
              'Go Back',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 14,
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
        color: MobileColors.textPrimary,
        fontSize: 16,
      ),
      decoration: InputDecoration(
        hintText: 'Enter word #$wordNum',
        hintStyle: TextStyle(
          color: MobileColors.textMuted.withOpacity(0.6),
        ),
        filled: true,
        fillColor: MobileColors.surfaceSecondary,
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
          borderSide: const BorderSide(color: MobileColors.primary, width: 2),
        ),
      ),
      autocorrect: false,
      enableSuggestions: false,
    );
  }

  // ── Profile ──────────────────────────────────────────────────────────────────

  Widget _buildProfile() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Tell Us Your Name.',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.3,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'This is how contacts will know you.',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 15,
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border, width: 1),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildProfileField(
                controller: _firstNameController,
                label: 'First Name',
                hint: 'First name',
                required: true,
              ),
              const SizedBox(height: 16),
              _buildProfileField(
                controller: _lastNameController,
                label: 'Last Name',
                hint: 'Last name',
                required: true,
              ),
              const SizedBox(height: 16),
              _buildProfileField(
                controller: _middleNameController,
                label: 'Middle Name',
                hint: 'Optional',
                required: false,
              ),
              const SizedBox(height: 16),
              _buildProfileField(
                controller: _displayNameController,
                label: 'Display Name',
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
              color: MobileColors.error.withOpacity(0.08),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: MobileColors.error.withOpacity(0.3)),
            ),
            child: Row(
              children: [
                const Icon(Icons.error_outline, color: MobileColors.error, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _profileFormError!,
                    style: const TextStyle(
                      color: MobileColors.error,
                      fontSize: 13,
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
              color: MobileColors.error.withOpacity(0.08),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: MobileColors.error.withOpacity(0.3)),
            ),
            child: Text(
              _errorMessage!,
              style: const TextStyle(
                color: MobileColors.error,
                fontSize: 13,
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
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Save & Create Identity',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () => setState(() => _currentStep = _WizardStep.verifySeed),
            child: const Text(
              'Go Back',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 14,
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
                color: MobileColors.textSecondary,
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
            if (required) ...[
              const SizedBox(width: 4),
              const Text(
                '*',
                style: TextStyle(
                  color: MobileColors.error,
                  fontSize: 14,
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 8),
        TextField(
          controller: controller,
          style: const TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 16,
          ),
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: TextStyle(
              color: MobileColors.textMuted.withOpacity(0.6),
              fontSize: 14,
            ),
            filled: true,
            fillColor: MobileColors.surfaceSecondary,
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
              borderSide: const BorderSide(color: MobileColors.primary, width: 2),
            ),
            contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
          ),
          autocorrect: false,
        ),
      ],
    );
  }

  // ── Creating Identity (Processing) ──────────────────────────────────────────

  Widget _buildCreating() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 32),
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: MobileColors.primary.withOpacity(0.1),
            borderRadius: BorderRadius.circular(20),
          ),
          child: const Center(
            child: SizedBox(
              width: 40,
              height: 40,
              child: CircularProgressIndicator(
                color: MobileColors.primary,
                strokeWidth: 3,
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
        const Text(
          'Setting Up Your Identity',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 32),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border, width: 1),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
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
                  color: MobileColors.primary,
                )
              : Icon(
                  done ? Icons.check_circle : Icons.circle_outlined,
                  color: done
                      ? MobileColors.success
                      : MobileColors.textMuted.withOpacity(0.3),
                  size: 20,
                ),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Text(
            label,
            style: TextStyle(
              color: done || active
                  ? MobileColors.textPrimary
                  : MobileColors.textMuted,
              fontSize: 14,
              fontWeight: done || active ? FontWeight.w600 : FontWeight.w400,
            ),
          ),
        ),
      ],
    );
  }

  // ── Identity Created ─────────────────────────────────────────────────────────

  Widget _buildIdentityCreated() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 16),
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: MobileColors.success.withOpacity(0.1),
            borderRadius: BorderRadius.circular(40),
            border: Border.all(
              color: MobileColors.success.withOpacity(0.3),
              width: 2,
            ),
          ),
          child: const Icon(
            Icons.person,
            color: MobileColors.success,
            size: 44,
          ),
        ),
        const SizedBox(height: 20),
        Text(
          _displayName.isNotEmpty ? _displayName : 'Your Identity',
          style: const TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 24,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Your identity is active.',
          style: TextStyle(
            color: MobileColors.success,
            fontSize: 15,
          ),
        ),
        const SizedBox(height: 24),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: MobileColors.border, width: 1),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 6,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Your Identifier (AID)',
                style: TextStyle(
                  color: MobileColors.textMuted,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.3,
                ),
              ),
              const SizedBox(height: 8),
              SelectableText(
                _aid ?? '',
                style: const TextStyle(
                  color: MobileColors.primary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'This is your permanent identifier. Share it as your digital address.',
                style: TextStyle(
                  color: MobileColors.textMuted,
                  fontSize: 12,
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
            onPressed: () => setState(() => _currentStep = _WizardStep.addContacts),
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Continue Setup',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
      ],
    );
  }

  // ── Add Contacts ─────────────────────────────────────────────────────────────

  Widget _buildAddContacts() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Add Your First Contacts.',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.3,
          ),
        ),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: MobileColors.border, width: 1),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 6,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Add contacts to protect your identity.',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'Your Identity Agent works best when trusted people you know are also using it. Your agents help each other behind the scenes — making each identity more trusted and easier to recover if something goes wrong.',
                style: TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 14,
                  height: 1.6,
                ),
              ),
              const SizedBox(height: 12),
              const _MobileBulletPoint(
                  text: 'They help verify your identity is genuine.'),
              const SizedBox(height: 6),
              const _MobileBulletPoint(
                  text: 'If you ever get locked out, trusted contacts can help you recover.'),
              const SizedBox(height: 12),
              const Text(
                'We recommend inviting at least 3 contacts now. 7 is ideal.',
                style: TextStyle(
                  color: MobileColors.primary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: MobileColors.success.withOpacity(0.06),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: MobileColors.success.withOpacity(0.2),
              width: 1,
            ),
          ),
          child: const Row(
            children: [
              Icon(Icons.shield_outlined, color: MobileColors.success, size: 18),
              SizedBox(width: 10),
              Expanded(
                child: Text(
                  'Grape ID is already protecting your identity. Adding personal contacts makes it even stronger.',
                  style: TextStyle(
                    color: MobileColors.success,
                    fontSize: 12,
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
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Invite Contacts',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () => setState(() => _currentStep = _WizardStep.setupComplete),
            child: const Text(
              'Skip for Now',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 15,
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
        backgroundColor: MobileColors.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: MobileColors.primary.withOpacity(0.3)),
        ),
        title: const Text(
          'Invite Contacts',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 18,
            fontWeight: FontWeight.w700,
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Share your Identity Address (OOBI) with people you trust:',
              style: TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 14,
              ),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: MobileColors.surfaceSecondary,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: MobileColors.border),
              ),
              child: SelectableText(
                url,
                style: const TextStyle(
                  color: MobileColors.primary,
                  fontSize: 12,
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
                'Copy & Close',
                style: TextStyle(
                  color: MobileColors.primary,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          TextButton(
            onPressed: () {
              Navigator.of(ctx).pop();
              setState(() => _currentStep = _WizardStep.setupComplete);
            },
            child: const Text(
              'Done',
              style: TextStyle(
                color: MobileColors.textMuted,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ── Setup Complete ───────────────────────────────────────────────────────────

  Widget _buildSetupComplete() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 16),
        const Text(
          "You're all set.",
          style: TextStyle(
            color: MobileColors.success,
            fontSize: 26,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.5,
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border, width: 1),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
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
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Open Dashboard',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
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
          color: ok ? MobileColors.success : MobileColors.warning,
          size: 20,
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            label,
            style: TextStyle(
              color: ok ? MobileColors.textPrimary : MobileColors.warning,
              fontSize: 14,
            ),
          ),
        ),
      ],
    );
  }
}

class _MobileBulletPoint extends StatelessWidget {
  final String text;
  const _MobileBulletPoint({required this.text});

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('• ', style: TextStyle(color: MobileColors.textMuted)),
        Expanded(
          child: Text(
            text,
            style: const TextStyle(
              color: MobileColors.textSecondary,
              fontSize: 14,
              height: 1.5,
            ),
          ),
        ),
      ],
    );
  }
}
