import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import '../../theme/mobile_theme.dart';
import '../../crypto/bip39.dart';
import '../../services/keri_service.dart';
import '../../services/core_service.dart';
import '../../services/secure_key_store.dart';
import '../../services/backend_process_service.dart';
import '../../services/enclave_service.dart';
import '../../services/setup_task_service.dart';
import '../../config/agent_config.dart';
import '../../services/photo_picker_stub.dart'
    if (dart.library.html) '../../services/photo_picker_web.dart'
    as photo_picker;

enum _WizardStep {
  profile,
  seedDisplay,
  creatingIdentity,
  identityCreated,
}

class MobileSetupWizardScreen extends StatefulWidget {
  final VoidCallback onComplete;
  final KeriService keriService;
  final String? remoteBrainUrl;

  const MobileSetupWizardScreen({
    super.key,
    required this.onComplete,
    required this.keriService,
    this.remoteBrainUrl,
  });

  @override
  State<MobileSetupWizardScreen> createState() =>
      _MobileSetupWizardScreenState();
}

class _MobileSetupWizardScreenState extends State<MobileSetupWizardScreen> {
  _WizardStep _currentStep = _WizardStep.profile;
  List<String> _mnemonic = [];
  String? _aid;
  String? _errorMessage;

  // Profile
  final _displayNameController = TextEditingController();
  String? _photoBase64;
  String? _profileFormError;

  // Seed verify (inline)
  int _verifyWordIndex1 = 3;
  int _verifyWordIndex2 = 8;
  final _verifyController1 = TextEditingController();
  final _verifyController2 = TextEditingController();
  bool _verifyError = false;
  bool _backupVerified = false;

  // Processing
  int _processingStep = 0;
  EnclaveStatusResponse? _enclaveStatus;

  // Identity
  String _displayName = '';
  String? _oobiUrl;

  String get _coreBaseUrl =>
      widget.remoteBrainUrl ?? AgentConfig.coreBaseUrl;

  @override
  void initState() {
    super.initState();
    _generateSeedPhrase();
  }

  @override
  void dispose() {
    _displayNameController.dispose();
    _verifyController1.dispose();
    _verifyController2.dispose();
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

  // ── Profile ─────────────────────────────────────────────────────────────────

  void _submitProfile() {
    final name = _displayNameController.text.trim();
    if (name.isEmpty) {
      setState(() => _profileFormError = 'Display name is required.');
      return;
    }
    setState(() {
      _displayName = name;
      _profileFormError = null;
      _verifyController1.clear();
      _verifyController2.clear();
      _verifyError = false;
      _currentStep = _WizardStep.seedDisplay;
    });
  }

  // ── Seed verify ─────────────────────────────────────────────────────────────

  void _proceedFromSeed() {
    final word1 = _verifyController1.text.trim().toLowerCase();
    final word2 = _verifyController2.text.trim().toLowerCase();
    if (word1.isEmpty && word2.isEmpty) {
      _skipWithWarning();
      return;
    }
    if (word1 != _mnemonic[_verifyWordIndex1] ||
        word2 != _mnemonic[_verifyWordIndex2]) {
      setState(() => _verifyError = true);
      return;
    }
    setState(() {
      _backupVerified = true;
      _verifyError = false;
    });
    _startInception();
  }

  Future<void> _skipWithWarning() async {
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
                color: MobileColors.textSecondary,
                fontSize: 13,
                height: 1.6,
              ),
            ),
            SizedBox(height: 14),
            Text(
              'By proceeding, you accept full liability for any loss from an unverified backup.',
              style: TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 12,
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
              style: TextStyle(color: MobileColors.textMuted),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.warning,
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            child: const Text(
              'I Accept the Risk',
              style: TextStyle(fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      setState(() => _backupVerified = false);
      _startInception();
    }
  }

  // ── Inception ───────────────────────────────────────────────────────────────

  void _startInception() {
    setState(() {
      _processingStep = 1;
      _currentStep = _WizardStep.creatingIdentity;
      _errorMessage = null;
    });
    _performInception();
  }

  Future<void> _performInception() async {
    await Future.delayed(const Duration(milliseconds: 400));
    setState(() => _processingStep = 2);

    try {
      final result = await widget.keriService.inceptAid(
        name: 'default',
        code: _mnemonic.join(' '),
      );

      setState(() => _processingStep = 3);
      await SecureKeyStore.saveMnemonic(_mnemonic);

      try {
        final coreService = CoreService(baseUrl: _coreBaseUrl);
        await coreService.saveProfile(ProfileResponse(
          fullName: _displayName,
          givenName: _displayName,
          familyName: '',
          photo: _photoBase64 ?? '',
        ));
        coreService.dispose();
      } catch (_) {}

      setState(() => _processingStep = 4);
      await Future.delayed(const Duration(milliseconds: 700));

      // Step 5 — check hardware security enclave
      setState(() => _processingStep = 5);
      try {
        final enclaveService = EnclaveService(
          coreService: CoreService(baseUrl: _coreBaseUrl),
        );
        _enclaveStatus = await enclaveService.detect();
      } catch (_) {
        _enclaveStatus = EnclaveStatusResponse(
          hardwareBacked: false,
          backingType: 'software',
          backingLabel: 'Software (detection failed)',
        );
      }

      // Auto-complete secure key storage task if hardware-backed
      if (_enclaveStatus?.hardwareBacked == true) {
        await SetupTaskService.markComplete(SetupTask.secureKeyStorage);
      }
      await Future.delayed(const Duration(milliseconds: 600));

      setState(() {
        _aid = result.aid;
        _currentStep = _WizardStep.identityCreated;
      });

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
        errorMsg = 'The native KERI engine is not available in this build. '
            'Please rebuild using the Codemagic CI/CD pipeline.';
      } else if (errorMsg.contains('SocketException') ||
          errorMsg.contains('Connection refused') ||
          errorMsg.contains('Connection reset') ||
          errorMsg.contains('TimeoutException')) {
        if (!kIsWeb && BackendProcessService.isDesktopPlatform) {
          final backendError = BackendProcessService.instance.startupError;
          errorMsg = backendError ??
              'Cannot connect to the identity backend. '
                  'Please ensure the server is running and try again.';
        } else {
          errorMsg = 'Cannot reach the Identity Agent server. '
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
      final coreService = CoreService(baseUrl: _coreBaseUrl);
      final oobi = await coreService.getOobi();
      coreService.dispose();
      if (mounted) setState(() => _oobiUrl = oobi.oobiUrl);
    } catch (_) {}
  }

  // ── Build ───────────────────────────────────────────────────────────────────

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
      case _WizardStep.profile:
        return _buildProfile();
      case _WizardStep.seedDisplay:
        return _buildSeedDisplay();
      case _WizardStep.creatingIdentity:
        return _buildCreating();
      case _WizardStep.identityCreated:
        return _buildIdentityCreated();
    }
  }

  // ── Profile ─────────────────────────────────────────────────────────────────

  Widget _buildProfile() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 32),
        const Text(
          'Set up your profile',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 24,
            fontWeight: FontWeight.w700,
            height: 1.2,
          ),
        ),
        const SizedBox(height: 6),
        const Text(
          'This is how contacts will know you.',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 15,
            height: 1.4,
          ),
        ),
        const SizedBox(height: 28),
        // Photo
        Center(
          child: GestureDetector(
            onTap: () async {
              try {
                final base64 = await photo_picker.pickPhotoBase64();
                if (base64 != null && base64.isNotEmpty) {
                  setState(() => _photoBase64 = base64);
                }
              } catch (_) {}
            },
            child: Stack(
              alignment: Alignment.bottomRight,
              children: [
                Container(
                  width: 100,
                  height: 100,
                  decoration: BoxDecoration(
                    color: MobileColors.surface,
                    borderRadius: BorderRadius.circular(50),
                    border:
                        Border.all(color: MobileColors.border, width: 2),
                    boxShadow: [
                      BoxShadow(
                        color: MobileColors.cardShadow,
                        blurRadius: 8,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: _photoBase64 != null
                      ? ClipRRect(
                          borderRadius: BorderRadius.circular(50),
                          child: Image.memory(
                            base64Decode(_photoBase64!),
                            fit: BoxFit.cover,
                          ),
                        )
                      : const Icon(
                          Icons.person_outline,
                          color: MobileColors.textMuted,
                          size: 50,
                        ),
                ),
                Container(
                  width: 30,
                  height: 30,
                  decoration: BoxDecoration(
                    color: MobileColors.primary,
                    borderRadius: BorderRadius.circular(15),
                    border: Border.all(
                        color: MobileColors.background, width: 2),
                  ),
                  child: const Icon(
                    Icons.camera_alt,
                    color: Colors.white,
                    size: 15,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 8),
        const Center(
          child: Text(
            'Tap to add a photo (optional)',
            style: TextStyle(
              color: MobileColors.textMuted,
              fontSize: 12,
            ),
          ),
        ),
        const SizedBox(height: 24),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border),
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
              const Text(
                'Display name *',
                style: TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _displayNameController,
                style: const TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 16,
                ),
                decoration: InputDecoration(
                  hintText: 'What your contacts will see',
                  hintStyle: const TextStyle(
                    color: MobileColors.textMuted,
                    fontSize: 14,
                  ),
                  filled: true,
                  fillColor: MobileColors.background,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide:
                        const BorderSide(color: MobileColors.border),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide:
                        const BorderSide(color: MobileColors.border),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(
                        color: MobileColors.primary, width: 2),
                  ),
                  contentPadding: const EdgeInsets.symmetric(
                      horizontal: 14, vertical: 12),
                ),
                autocorrect: false,
              ),
            ],
          ),
        ),
        if (_profileFormError != null) ...[
          const SizedBox(height: 10),
          Text(
            _profileFormError!,
            style: const TextStyle(
              color: Colors.red,
              fontSize: 13,
            ),
          ),
        ],
        if (_errorMessage != null) ...[
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.08),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Text(
              _errorMessage!,
              style: const TextStyle(
                color: Colors.red,
                fontSize: 12,
                height: 1.4,
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
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
            ),
            child: const Text(
              'Continue',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
      ],
    );
  }

  // ── Seed Display (with inline verify) ──────────────────────────────────────

  Widget _buildSeedDisplay() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: MobileColors.warning.withOpacity(0.08),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: MobileColors.warning.withOpacity(0.4)),
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
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
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
        // Word grid
        Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border:
                Border.all(color: MobileColors.warning.withOpacity(0.3)),
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
                            padding:
                                EdgeInsets.only(left: col > 0 ? 8 : 0),
                            child: _buildWordCell(row * 3 + col),
                          ),
                        ),
                    ],
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        _buildTip(
          icon: '✍️',
          title: 'Write it on paper',
          subtitle:
              'Keep it somewhere physically safe — a fireproof safe, safety deposit box, etc.',
        ),
        const SizedBox(height: 8),
        GestureDetector(
          onTap: () {
            _generateSeedPhrase();
            setState(() {
              _verifyController1.clear();
              _verifyController2.clear();
              _verifyError = false;
            });
          },
          child: _buildTip(
            icon: '🔄',
            title: 'Generate a new phrase',
            subtitle: 'Start over with a different seed phrase.',
            isAction: true,
          ),
        ),
        const SizedBox(height: 24),
        // Inline verify
        Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border),
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
                'Confirm you saved it',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Enter word #${_verifyWordIndex1 + 1} and word #${_verifyWordIndex2 + 1} from your seed phrase.',
                style: const TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'Word #${_verifyWordIndex1 + 1}',
                style: const TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 6),
              _buildVerifyField(_verifyController1, _verifyWordIndex1 + 1),
              const SizedBox(height: 14),
              Text(
                'Word #${_verifyWordIndex2 + 1}',
                style: const TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 6),
              _buildVerifyField(_verifyController2, _verifyWordIndex2 + 1),
              if (_verifyError) ...[
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: Colors.red.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.close, color: Colors.red, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Words do not match. Check your backup and try again.',
                          style:
                              TextStyle(color: Colors.red, fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 20),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _proceedFromSeed,
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.primary,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
            ),
            child: const Text(
              "I've backed it up — continue",
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: _skipWithWarning,
            child: Text(
              'Skip backup verification (not recommended)',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: MobileColors.warning,
                fontSize: 13,
              ),
            ),
          ),
        ),
        const SizedBox(height: 8),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: () =>
                setState(() => _currentStep = _WizardStep.profile),
            child: const Text(
              'Go back',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 13,
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildWordCell(int index) {
    if (index >= _mnemonic.length) return const SizedBox.shrink();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
      decoration: BoxDecoration(
        color: MobileColors.background,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: MobileColors.border),
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

  Widget _buildTip({
    required String icon,
    required String title,
    required String subtitle,
    bool isAction = false,
  }) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
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
                    color: isAction
                        ? MobileColors.primary
                        : MobileColors.textPrimary,
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
        hintStyle: const TextStyle(
          color: MobileColors.textMuted,
          fontSize: 14,
        ),
        filled: true,
        fillColor: MobileColors.background,
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
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      ),
      autocorrect: false,
      enableSuggestions: false,
    );
  }

  // ── Creating Identity ────────────────────────────────────────────────────────

  Widget _buildCreating() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 48),
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: MobileColors.primary.withOpacity(0.1),
            borderRadius: BorderRadius.circular(20),
          ),
          child: Center(
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
        const SizedBox(height: 28),
        const Text(
          'Setting up your identity',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 20,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 28),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MobileColors.border),
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
              _buildProcessingRow(
                  2, 'Creating your identity on the network...'),
              const SizedBox(height: 14),
              _buildProcessingRow(3, 'Saving keys to secure storage...'),
              const SizedBox(height: 14),
              _buildProcessingRow(4, 'Enrolling in identity protection...'),
              const SizedBox(height: 14),
              _buildProcessingRow(5, 'Checking hardware security...'),
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
              ? CircularProgressIndicator(
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

  // ── Enclave badge ────────────────────────────────────────────────────────────

  Widget _buildEnclaveBadge() {
    final status = _enclaveStatus!;
    final isHardware = status.hardwareBacked;
    final badgeColor = isHardware ? MobileColors.success : const Color(0xFFFFB74D);
    final badgeIcon = isHardware ? Icons.shield : Icons.shield_outlined;

    return GestureDetector(
      onTap: isHardware ? null : _showEnclaveOptions,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: badgeColor.withOpacity(0.10),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: badgeColor.withOpacity(0.35), width: 1),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(badgeIcon, color: badgeColor, size: 18),
            const SizedBox(width: 8),
            Flexible(
              child: Text(
                status.backingLabel,
                style: TextStyle(
                  color: badgeColor,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            if (!isHardware) ...[
              const SizedBox(width: 6),
              Icon(Icons.chevron_right, color: badgeColor, size: 16),
            ],
          ],
        ),
      ),
    );
  }

  void _showEnclaveOptions() {
    final status = _enclaveStatus!;
    showModalBottomSheet(
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
              'KEY STORAGE OPTIONS',
              style: TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Current backing: ${status.backingLabel}',
              style: const TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
            if (status.tpmPresent == true && status.tpmEnabled == false) ...[
              const SizedBox(height: 8),
              Text(
                'A TPM chip was detected but is not enabled. Enable it in BIOS/UEFI settings for stronger protection.',
                style: TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
            ],
            const SizedBox(height: 20),
            _mobileOptionTile(
              icon: Icons.devices_other,
              title: 'Migrate to a different device',
              subtitle: 'Use a device with a hardware secure enclave. A reminder stays on your checklist.',
              onTap: () => Navigator.pop(ctx),
            ),
            const SizedBox(height: 10),
            _mobileOptionTile(
              icon: Icons.cloud_outlined,
              title: 'Cloud HSM — Coming Soon',
              subtitle: 'Delegate key ops to a hardware-backed cloud HSM.',
              disabled: true,
            ),
            const SizedBox(height: 10),
            _mobileOptionTile(
              icon: Icons.check_circle_outline,
              title: 'Continue with software storage',
              subtitle: 'Your keys are encrypted with the OS credential store.',
              onTap: () => Navigator.pop(ctx),
            ),
          ],
        ),
      ),
    );
  }

  Widget _mobileOptionTile({
    required IconData icon,
    required String title,
    required String subtitle,
    VoidCallback? onTap,
    bool disabled = false,
  }) {
    return InkWell(
      onTap: disabled ? null : onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: MobileColors.background,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: MobileColors.border),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              icon,
              color: disabled ? MobileColors.textSecondary : MobileColors.primary,
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
                        child: Text(
                          title,
                          style: TextStyle(
                            color: disabled
                                ? MobileColors.textSecondary
                                : MobileColors.textPrimary,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                      if (disabled)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
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
                        ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    subtitle,
                    style: TextStyle(
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
      ),
    );
  }

  // ── Identity Created (+ contacts) ───────────────────────────────────────────

  Widget _buildIdentityCreated() {
    return Column(
      children: [
        const SizedBox(height: 24),
        // Avatar
        Container(
          width: 96,
          height: 96,
          decoration: BoxDecoration(
            color: MobileColors.success.withOpacity(0.1),
            borderRadius: BorderRadius.circular(48),
            border:
                Border.all(color: MobileColors.success.withOpacity(0.3), width: 2),
            boxShadow: [
              BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 10,
                offset: const Offset(0, 3),
              ),
            ],
          ),
          child: _photoBase64 != null
              ? ClipRRect(
                  borderRadius: BorderRadius.circular(48),
                  child: Image.memory(
                    base64Decode(_photoBase64!),
                    fit: BoxFit.cover,
                  ),
                )
              : Icon(Icons.person,
                  color: MobileColors.success, size: 48),
        ),
        const SizedBox(height: 14),
        Text(
          _displayName.isNotEmpty ? _displayName : 'Your Identity',
          style: const TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          'Your identity is live and protected.',
          style: TextStyle(
            color: MobileColors.success,
            fontSize: 14,
          ),
        ),
        const SizedBox(height: 14),
        if (_enclaveStatus != null) _buildEnclaveBadge(),
        const SizedBox(height: 14),
        // AID
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: MobileColors.border),
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
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 6),
              SelectableText(
                _aid ?? '',
                style: const TextStyle(
                  color: MobileColors.primary,
                  fontSize: 11,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 4),
              const Text(
                'This is your permanent identifier. Share it as your digital address.',
                style: TextStyle(
                  color: MobileColors.textMuted,
                  fontSize: 11,
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        // Contacts
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: MobileColors.surface,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: MobileColors.border),
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
                'Invite trusted contacts',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Contacts help verify your identity and can help you recover access if you get locked out. We recommend at least 3 — 7 is ideal.',
                style: TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 10, vertical: 8),
                decoration: BoxDecoration(
                  color: MobileColors.success.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: MobileColors.success.withOpacity(0.2),
                  ),
                ),
                child: Row(
                  children: [
                    Icon(Icons.shield_outlined,
                        color: MobileColors.success, size: 16),
                    const SizedBox(width: 8),
                    const Expanded(
                      child: Text(
                        'Grape ID is already protecting your identity. Personal contacts make it even stronger.',
                        style: TextStyle(
                          color: MobileColors.textSecondary,
                          fontSize: 11,
                          height: 1.4,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _showInviteDialog,
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.primary,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
            ),
            child: const Text(
              'Invite your first contacts',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: TextButton(
            onPressed: widget.onComplete,
            child: const Text(
              'Skip — go to dashboard',
              style: TextStyle(
                color: MobileColors.textMuted,
                fontSize: 14,
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
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
            fontSize: 17,
            fontWeight: FontWeight.w700,
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Share your Identity Address with people you trust:',
              style: TextStyle(
                color: MobileColors.textSecondary,
                fontSize: 13,
              ),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: MobileColors.background,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: MobileColors.border),
              ),
              child: SelectableText(
                url,
                style: const TextStyle(
                  color: MobileColors.primary,
                  fontSize: 11,
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
              widget.onComplete();
            },
            child: const Text(
              'Done',
              style: TextStyle(color: MobileColors.textMuted),
            ),
          ),
        ],
      ),
    );
  }
}
