import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import '../../theme/mobile_theme.dart';
import '../../crypto/bip39.dart';
import '../../services/keri_service.dart';
import '../../services/backend_process_service.dart';

enum _WizardStep {
  welcome,
  generateSeed,
  verifySeed,
  creatingIdentity,
  complete,
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
  _WizardStep _currentStep = _WizardStep.welcome;
  List<String> _mnemonic = [];
  String? _aid;
  String? _errorMessage;

  int _verifyWordIndex1 = 0;
  int _verifyWordIndex2 = 0;
  final _verifyController1 = TextEditingController();
  final _verifyController2 = TextEditingController();
  bool _verifyError = false;

  @override
  void dispose() {
    _verifyController1.dispose();
    _verifyController2.dispose();
    super.dispose();
  }

  void _generateSeedPhrase() {
    final mnemonic = Bip39.generateMnemonic();
    final wordCount = mnemonic.length;

    int idx1 = 3;
    int idx2 = 8;
    if (wordCount > 4) {
      idx1 = 3;
      idx2 = wordCount > 8 ? 8 : wordCount - 1;
    }

    setState(() {
      _mnemonic = mnemonic;
      _verifyWordIndex1 = idx1;
      _verifyWordIndex2 = idx2;
      _currentStep = _WizardStep.generateSeed;
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

  Future<void> _verifyAndCreateIdentity() async {
    final word1 = _verifyController1.text.trim().toLowerCase();
    final word2 = _verifyController2.text.trim().toLowerCase();

    if (word1 != _mnemonic[_verifyWordIndex1] ||
        word2 != _mnemonic[_verifyWordIndex2]) {
      setState(() {
        _verifyError = true;
      });
      return;
    }

    await _performInception();
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
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'If you skip verification and lose your seed phrase, your identity cannot be recovered. This means:',
              style: TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 14,
                height: 1.6,
              ),
            ),
            const SizedBox(height: 12),
            const Text(
              '• All credentials tied to this identity will be permanently lost\n'
              '• All signed data will become unverifiable\n'
              '• No one, including you, can restore access',
              style: TextStyle(
                color: MobileColors.error,
                fontSize: 13,
                height: 1.6,
              ),
            ),
            const SizedBox(height: 16),
            const Text(
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
      await _performInception();
    }
  }

  Future<void> _performInception() async {
    setState(() {
      _verifyError = false;
      _currentStep = _WizardStep.creatingIdentity;
      _errorMessage = null;
    });

    try {
      final result = await widget.keriService.inceptAid(
        name: 'default',
        code: _mnemonic.join(' '),
      );

      setState(() {
        _aid = result.aid;
        _currentStep = _WizardStep.complete;
      });
    } catch (e) {
      String errorMsg = e.toString();

      if (errorMsg.contains('KERI_BRIDGE_NOT_AVAILABLE')) {
        final loadReason = RegExp(r'\((.+?)\)\. This is required')
                .firstMatch(errorMsg)
                ?.group(1) ??
            'unknown';
        errorMsg =
            'The native KERI engine could not be loaded on this device. '
            'Identity creation requires the Rust KERI library to be '
            'compiled and included in the app. Please rebuild the app '
            'using the Codemagic CI/CD pipeline, which compiles the '
            'Rust library for your device.\n\n'
            'Diagnostic: $loadReason';
      } else if (errorMsg.contains('UnimplementedError') ||
          errorMsg.contains('Placeholder')) {
        errorMsg =
            'The native KERI engine is not available in this build. '
            'The app was built without running the Rust bridge code '
            'generator. Please rebuild using the Codemagic CI/CD pipeline.';
      } else if (errorMsg.contains('SocketException') ||
          errorMsg.contains('Connection refused') ||
          errorMsg.contains('connection refused') ||
          errorMsg.contains('Connection reset') ||
          errorMsg.contains('TimeoutException')) {
        if (!kIsWeb && BackendProcessService.isDesktopPlatform) {
          final backendError = BackendProcessService.instance.startupError;
          if (backendError != null) {
            errorMsg = backendError;
          } else {
            errorMsg =
                'Cannot connect to the identity backend (localhost:5000). '
                'The backend service may not be running. '
                'Please ensure Python 3 is installed and try restarting the app.';
          }
        } else {
          errorMsg =
              'Cannot reach the Identity Agent server. '
              'Please make sure your server is running and accessible, '
              'then go back and re-enter the server URL.';
        }
      }

      setState(() {
        _errorMessage = errorMsg;
        _currentStep = _WizardStep.verifySeed;
      });
    }
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
      case _WizardStep.welcome:
        return _buildWelcome();
      case _WizardStep.generateSeed:
        return _buildSeedDisplay();
      case _WizardStep.verifySeed:
        return _buildSeedVerify();
      case _WizardStep.creatingIdentity:
        return _buildCreating();
      case _WizardStep.complete:
        return _buildComplete();
    }
  }

  Widget _buildWelcome() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: MobileColors.primary.withOpacity(0.1),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: MobileColors.primary.withOpacity(0.3),
              width: 1.5,
            ),
          ),
          child: const Icon(
            Icons.shield_outlined,
            color: MobileColors.primary,
            size: 40,
          ),
        ),
        const SizedBox(height: 32),
        const Text(
          'Identity Agent',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 26,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.5,
          ),
        ),
        const SizedBox(height: 6),
        const Text(
          'Inception',
          style: TextStyle(
            color: MobileColors.primary,
            fontSize: 15,
            fontWeight: FontWeight.w600,
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
          child: const Column(
            children: [
              Text(
                'Create your sovereign digital identity.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 17,
                  fontWeight: FontWeight.w500,
                  height: 1.5,
                ),
              ),
              SizedBox(height: 16),
              Text(
                'You will generate a 12-word seed phrase that serves as your root authority. This phrase is the master key to your identity and must be backed up securely.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: MobileColors.textSecondary,
                  fontSize: 14,
                  height: 1.6,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 32),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: _generateSeedPhrase,
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Begin Inception',
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSeedDisplay() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Seed Phrase Backup',
          style: TextStyle(
            color: MobileColors.textMuted,
            fontSize: 13,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.5,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Write down these 12 words in order. This is your root authority. Never share it. Never store it digitally.',
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 14,
            height: 1.5,
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
                            padding: EdgeInsets.only(
                              left: col > 0 ? 8 : 0,
                            ),
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
              Expanded(
                child: Text(
                  'Write these words down on paper. You will need to verify them in the next step.',
                  style: TextStyle(
                    color: MobileColors.textPrimary.withOpacity(0.8),
                    fontSize: 13,
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
              'I Have Written Them Down',
              style: TextStyle(
                fontSize: 14,
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

  Widget _buildSeedVerify() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
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
            fontSize: 14,
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
              TextField(
                controller: _verifyController1,
                style: const TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 16,
                ),
                decoration: InputDecoration(
                  hintText: 'Enter word #${_verifyWordIndex1 + 1}',
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
                    borderSide:
                        const BorderSide(color: MobileColors.primary, width: 2),
                  ),
                ),
                autocorrect: false,
                enableSuggestions: false,
              ),
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
              TextField(
                controller: _verifyController2,
                style: const TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 16,
                ),
                decoration: InputDecoration(
                  hintText: 'Enter word #${_verifyWordIndex2 + 1}',
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
                    borderSide:
                        const BorderSide(color: MobileColors.primary, width: 2),
                  ),
                ),
                autocorrect: false,
                enableSuggestions: false,
              ),
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
              border: Border.all(
                color: MobileColors.error.withOpacity(0.3),
                width: 1,
              ),
            ),
            child: const Row(
              children: [
                Icon(Icons.error_outline, color: MobileColors.error, size: 18),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'One or both words are incorrect. Please check your backup and try again.',
                    style: TextStyle(
                      color: MobileColors.error,
                      fontSize: 12,
                      height: 1.4,
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
              border: Border.all(
                color: MobileColors.error.withOpacity(0.3),
                width: 1,
              ),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.error_outline,
                    color: MobileColors.error, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _errorMessage!,
                    style: const TextStyle(
                      color: MobileColors.error,
                      fontSize: 12,
                      height: 1.4,
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
            onPressed: _verifyAndCreateIdentity,
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.primary,
              foregroundColor: MobileColors.textOnPrimary,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'Verify & Create Identity',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
        const SizedBox(height: 8),
        Center(
          child: TextButton(
            onPressed: _skipVerificationWithWarning,
            child: Text(
              'Skip Verification',
              style: TextStyle(
                color: MobileColors.warning.withOpacity(0.9),
                fontSize: 13,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildCreating() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
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
          'Creating Identity',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'Performing KERI inception event...\nThis may take a moment.',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 14,
            height: 1.6,
          ),
        ),
      ],
    );
  }

  Widget _buildComplete() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: MobileColors.success.withOpacity(0.1),
            borderRadius: BorderRadius.circular(20),
          ),
          child: const Icon(
            Icons.check_circle_outline,
            color: MobileColors.success,
            size: 44,
          ),
        ),
        const SizedBox(height: 32),
        const Text(
          'Identity Created',
          style: TextStyle(
            color: MobileColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'Your sovereign digital identity has been successfully created.',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: MobileColors.textSecondary,
            fontSize: 15,
            height: 1.5,
          ),
        ),
        if (_aid != null) ...[
          const SizedBox(height: 20),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: MobileColors.surface,
              borderRadius: BorderRadius.circular(10),
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
                Text(
                  'Your AID',
                  style: TextStyle(
                    color: MobileColors.textMuted,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  _aid!,
                  style: const TextStyle(
                    color: MobileColors.textPrimary,
                    fontSize: 12,
                    fontFamily: 'monospace',
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
        ],
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
              'Continue to Dashboard',
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ),
      ],
    );
  }
}
