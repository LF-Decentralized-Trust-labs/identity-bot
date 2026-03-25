import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import '../theme/app_theme.dart';
import '../crypto/bip39.dart';
import '../services/keri_service.dart';
import '../services/core_service.dart';
import '../services/preferences_service.dart' show EntityType;
import '../services/secure_key_store.dart';
import '../services/backend_process_service.dart';
import '../services/enclave_service.dart';
import '../services/setup_task_service.dart';
import '../config/agent_config.dart';
import '../services/photo_picker_stub.dart'
    if (dart.library.html) '../services/photo_picker_web.dart' as photo_picker;

enum WizardStep {
  creatingIdentity,
  enclaveWarning,
  profile,
  identityCreated,
}

class SetupWizardScreen extends StatefulWidget {
  final VoidCallback onComplete;
  final KeriService keriService;
  final String? remoteBrainUrl;
  final EntityType? entityType;

  const SetupWizardScreen({
    super.key,
    required this.onComplete,
    required this.keriService,
    this.remoteBrainUrl,
    this.entityType,
  });

  @override
  State<SetupWizardScreen> createState() => _SetupWizardScreenState();
}

class _SetupWizardScreenState extends State<SetupWizardScreen> {
  WizardStep _currentStep = WizardStep.creatingIdentity;
  List<String> _mnemonic = [];
  String? _aid;
  String? _errorMessage;

  // Profile step
  final _displayNameController = TextEditingController();
  String? _photoBase64;
  String? _profileFormError;

  // Org-specific profile fields (only used when entityType == organization)
  final _orgNameController = TextEditingController();
  final _orgTypeController = TextEditingController();
  final _jurisdictionController = TextEditingController();

  // Processing
  int _processingStep = 0;
  EnclaveStatusResponse? _enclaveStatus;

  // Identity created
  String _displayName = '';

  String get _coreBaseUrl =>
      widget.remoteBrainUrl ?? AgentConfig.coreBaseUrl;

  @override
  void initState() {
    super.initState();
    _generateAndStartInception();
  }

  @override
  void dispose() {
    _displayNameController.dispose();
    _orgNameController.dispose();
    _orgTypeController.dispose();
    _jurisdictionController.dispose();
    super.dispose();
  }

  void _generateAndStartInception() {
    final mnemonic = Bip39.generateMnemonic();
    _mnemonic = mnemonic;
    _startInception();
  }

  // ── Profile submit ──────────────────────────────────────────────────────────

  bool get _isOrg => widget.entityType == EntityType.organization;

  Future<void> _submitProfile() async {
    final name = _displayNameController.text.trim();
    if (name.isEmpty) {
      setState(() => _profileFormError = _isOrg ? 'Organization name is required.' : 'Display name is required.');
      return;
    }
    if (_isOrg && _orgTypeController.text.trim().isEmpty) {
      setState(() => _profileFormError = 'Organization type is required.');
      return;
    }
    setState(() {
      _displayName = name;
      _profileFormError = null;
    });
    // Save profile to server
    try {
      final coreService = CoreService(baseUrl: _coreBaseUrl);
      await coreService.saveProfile(ProfileResponse(
        fullName: _displayName,
        givenName: _isOrg ? '' : _displayName,
        familyName: '',
        photo: _photoBase64 ?? '',
        entityType: _isOrg ? 'organization' : 'individual',
        orgName: _isOrg ? _orgNameController.text.trim() : '',
        orgType: _isOrg ? _orgTypeController.text.trim() : '',
        jurisdiction: _isOrg ? _jurisdictionController.text.trim() : '',
      ));
      coreService.dispose();
    } catch (_) {}

    setState(() {
      _currentStep = WizardStep.identityCreated;
    });
  }

  // ── Inception ───────────────────────────────────────────────────────────────

  void _startInception() {
    setState(() {
      _processingStep = 1;
      _currentStep = WizardStep.creatingIdentity;
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

      // Profile is saved in _submitProfile() after the user fills it in
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
        // Show enclave warning if no hardware security, otherwise go to profile
        _currentStep = (_enclaveStatus?.hardwareBacked == true)
            ? WizardStep.profile
            : WizardStep.enclaveWarning;
      });

    } catch (e) {
      String errorMsg = e.toString();
      if (errorMsg.contains('KERI_BRIDGE_NOT_AVAILABLE')) {
        final loadReason = RegExp(r'\((.+?)\)\. This is required')
                .firstMatch(errorMsg)
                ?.group(1) ??
            'unknown';
        errorMsg = 'The native KERI engine could not be loaded on this device. '
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
              'Cannot connect to the identity backend (127.0.0.1:5000). '
                  'Please ensure Python 3.10+ is installed and try restarting the app.';
        } else {
          errorMsg = 'Cannot reach the Identity Agent server. '
              'Please make sure your server is running and try again.';
        }
      }
      setState(() {
        _errorMessage = errorMsg;
        _processingStep = 0;
        _currentStep = WizardStep.creatingIdentity;
      });
    }
  }

  // ── Build ───────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
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
      case WizardStep.creatingIdentity:
        return _buildCreating();
      case WizardStep.enclaveWarning:
        return _buildEnclaveWarning();
      case WizardStep.profile:
        return _buildProfile();
      case WizardStep.identityCreated:
        return _buildIdentityCreated();
    }
  }

  // ── Screen: Profile ─────────────────────────────────────────────────────────

  Widget _buildProfile() {
    final isOrg = _isOrg;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 32),
        Text(
          isOrg ? 'Set up your organization.' : 'Set up your profile.',
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 20,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 8),
        Text(
          isOrg ? 'Enter your organization details.' : 'This is how others will see your profile.',
          style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 13,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 28),
        // Photo picker
        Center(
          child: MouseRegion(
            cursor: SystemMouseCursors.click,
            child: GestureDetector(
              onTap: () async {
                try {
                  final base64 = await photo_picker.pickAndCropPhotoBase64(context);
                  if (base64 != null && base64.isNotEmpty) {
                    setState(() => _photoBase64 = base64);
                  }
                } catch (_) {}
              },
              child: Stack(
              alignment: Alignment.bottomRight,
              children: [
                Container(
                  width: 96,
                  height: 96,
                  decoration: BoxDecoration(
                    color: AppColors.surface,
                    borderRadius: BorderRadius.circular(48),
                    border: Border.all(color: AppColors.border, width: 2),
                  ),
                  child: _photoBase64 != null
                      ? ClipRRect(
                          borderRadius: BorderRadius.circular(48),
                          child: Image.memory(
                            base64Decode(_photoBase64!),
                            fit: BoxFit.cover,
                          ),
                        )
                      : const Icon(
                          Icons.person_outline,
                          color: AppColors.textMuted,
                          size: 48,
                        ),
                ),
                Container(
                  width: 28,
                  height: 28,
                  decoration: BoxDecoration(
                    color: AppColors.surface,
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: AppColors.border, width: 1.5),
                  ),
                  child: const Icon(
                    Icons.camera_alt,
                    color: AppColors.textSecondary,
                    size: 14,
                  ),
                ),
              ],
            ),
          ),
          ),
        ),
        const SizedBox(height: 8),
        const Center(
          child: Text(
            'Tap to add a photo (optional)',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
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
              Row(
                children: [
                  Text(
                    isOrg ? 'ORGANIZATION NAME' : 'DISPLAY NAME',
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 1.2,
                      fontFamily: 'monospace',
                    ),
                  ),
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
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _displayNameController,
                style: const TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 15,
                  fontFamily: 'monospace',
                ),
                decoration: InputDecoration(
                  hintText: isOrg ? 'e.g. Riverside Elementary School' : 'A name others will see when they interact with you',
                  hintStyle: TextStyle(
                    color: AppColors.textMuted.withOpacity(0.5),
                    fontFamily: 'monospace',
                    fontSize: 13,
                  ),
                  filled: true,
                  fillColor: AppColors.surfaceLight,
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
                  contentPadding:
                      const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                ),
                autocorrect: false,
              ),
              // Org-specific fields shown when entity_type = organization
              if (isOrg) ...[
                const SizedBox(height: 16),
                _buildOrgField('ORG TYPE *', _orgTypeController,
                    hint: 'e.g. school, business, healthcare, government'),
                const SizedBox(height: 12),
                _buildOrgField('JURISDICTION', _jurisdictionController,
                    hint: 'e.g. Texas, USA  (free text — optional)'),
              ],
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
                const Icon(Icons.error_outline,
                    color: AppColors.coreInactive, size: 18),
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
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'CONTINUE',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildOrgField(String label, TextEditingController ctrl, {String hint = ''}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.2,
              fontFamily: 'monospace',
            )),
        const SizedBox(height: 8),
        TextField(
          controller: ctrl,
          style: const TextStyle(color: AppColors.textPrimary, fontSize: 14, fontFamily: 'monospace'),
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: TextStyle(color: AppColors.textMuted.withOpacity(0.5), fontFamily: 'monospace', fontSize: 12),
            filled: true,
            fillColor: AppColors.surfaceLight,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: AppColors.border)),
            enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: AppColors.border)),
            focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: const BorderSide(color: AppColors.accent)),
            contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          ),
          autocorrect: false,
        ),
      ],
    );
  }

  // ── Screen: Creating Identity ───────────────────────────────────────────────

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
          'Setting up your identity',
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
              color: done || active ? AppColors.textPrimary : AppColors.textMuted,
              fontSize: 13,
              fontFamily: 'monospace',
              fontWeight: done || active ? FontWeight.w600 : FontWeight.w400,
            ),
          ),
        ),
      ],
    );
  }

  // ── Screen: Enclave Warning ─────────────────────────────────────────────────

  bool _technicalExpanded = false;

  Widget _buildEnclaveWarning() {
    const warningRed = Color(0xFFE53935);

    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 32),
        // Shield icon
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: warningRed.withOpacity(0.10),
            borderRadius: BorderRadius.circular(20),
          ),
          child: const Icon(
            Icons.shield_outlined,
            color: warningRed,
            size: 40,
          ),
        ),
        const SizedBox(height: 24),
        const Text(
          'Your device lacks a secure enclave.',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: warningRed,
            fontSize: 18,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'Without hardware security, other people and organizations cannot verify that you — and only you — control your keys. Most Identity Agents will not trust yours.',
          textAlign: TextAlign.center,
          style: TextStyle(
            color: AppColors.textPrimary,
            fontSize: 13,
            height: 1.6,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 24),
        // Recommended action
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
                'RECOMMENDED ACTION',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 10),
              const Text(
                'Use a different device. Install the Identity Agent on a device with hardware security (most modern devices):',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 12,
                  height: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 8),
              _buildDeviceRow('iPhone (with a Secure Enclave)'),
              _buildDeviceRow('Modern Android (with StrongBox / TEE)'),
              _buildDeviceRow('Apple Silicon Mac (with a Secure Enclave)'),
              _buildDeviceRow('PC with TPM 2.0 enabled in BIOS'),
            ],
          ),
        ),
        const SizedBox(height: 12),
        // Collapsible technical explanation
        GestureDetector(
          onTap: () => setState(() => _technicalExpanded = !_technicalExpanded),
          child: Container(
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
                Row(
                  children: [
                    const Expanded(
                      child: Text(
                        'TECHNICAL DETAILS',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 1.5,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                    Icon(
                      _technicalExpanded ? Icons.expand_less : Icons.expand_more,
                      color: AppColors.textMuted,
                      size: 20,
                    ),
                  ],
                ),
                if (_technicalExpanded) ...[
                  const SizedBox(height: 10),
                  Text(
                    'Current: ${_enclaveStatus?.backingLabel ?? "Software"}',
                    style: TextStyle(
                      color: warningRed.withOpacity(0.8),
                      fontSize: 12,
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Without a hardware secure enclave (TPM, Secure Enclave, or StrongBox), '
                    'your private signing keys are stored in software only. This means:',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 11,
                      height: 1.6,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    '- Your signing keys can be extracted and used without your knowledge\n'
                    '- There is no hardware-level protection against key theft\n'
                    '- Malware with device access can silently impersonate you',
                    style: TextStyle(
                      color: warningRed,
                      fontSize: 11,
                      height: 1.6,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        const SizedBox(height: 24),
        // Accept risk button — red themed
        SizedBox(
          width: double.infinity,
          child: OutlinedButton(
            onPressed: () {
              setState(() => _currentStep = WizardStep.profile);
            },
            style: OutlinedButton.styleFrom(
              foregroundColor: warningRed,
              side: const BorderSide(color: warningRed, width: 1.5),
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'CONTINUE — OTHERS WON\'T TRUST ME',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.0,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildDeviceRow(String text) {
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Row(
        children: [
          const Text('- ', style: TextStyle(
            color: AppColors.textSecondary,
            fontSize: 12,
            fontFamily: 'monospace',
          )),
          Expanded(
            child: Text(
              text,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ── Enclave badge ────────────────────────────────────────────────────────────

  Widget _buildEnclaveBadge() {
    final status = _enclaveStatus!;
    final isHardware = status.hardwareBacked;
    final badgeColor = isHardware ? AppColors.coreActive : const Color(0xFFFFB74D);
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
                  fontSize: 12,
                  fontFamily: 'monospace',
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
          color: AppColors.surface,
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
                  color: AppColors.border,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 20),
            const Text(
              'KEY STORAGE OPTIONS',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Current backing: ${status.backingLabel}',
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontSize: 14,
                fontFamily: 'monospace',
              ),
            ),
            if (status.tpmPresent == true && status.tpmEnabled == false) ...[
              const SizedBox(height: 8),
              const Text(
                'A TPM chip was detected but is not enabled in your OS. Enable it in your BIOS/UEFI settings for stronger protection.',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  height: 1.5,
                ),
              ),
            ],
            const SizedBox(height: 20),
            _buildOptionTile(
              icon: Icons.devices_other,
              title: 'Migrate to a different device',
              subtitle: 'Use a device with a hardware secure enclave (iPhone, modern Android, or Apple Silicon Mac). A reminder will stay on your checklist.',
              onTap: () {
                Navigator.pop(ctx);
                // Task stays open in checklist — no action needed here
              },
            ),
            const SizedBox(height: 10),
            _buildOptionTile(
              icon: Icons.cloud_outlined,
              title: 'Cloud HSM — Coming Soon',
              subtitle: 'Delegate key operations to a hardware-backed cloud HSM (Grape ID, AWS KMS, Azure). Available in a future release.',
              onTap: null,
              disabled: true,
            ),
            const SizedBox(height: 10),
            _buildOptionTile(
              icon: Icons.usb,
              title: 'YubiKey — Coming Soon',
              subtitle: 'Use a YubiKey hardware token for multi-factor signing. Available in a future release.',
              onTap: null,
              disabled: true,
            ),
            const SizedBox(height: 10),
            _buildOptionTile(
              icon: Icons.check_circle_outline,
              title: 'Continue with software storage',
              subtitle: 'Your keys are encrypted with your OS credential store. Secure for most users.',
              onTap: () {
                Navigator.pop(ctx);
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildOptionTile({
    required IconData icon,
    required String title,
    required String subtitle,
    required VoidCallback? onTap,
    bool disabled = false,
  }) {
    final color = disabled ? AppColors.textMuted : AppColors.textPrimary;
    final subColor = AppColors.textMuted;
    return InkWell(
      onTap: disabled ? null : onTap,
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.background,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppColors.border, width: 1),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: disabled ? AppColors.textMuted : AppColors.accent, size: 20),
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
                            color: color,
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ),
                      if (disabled)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: AppColors.border,
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text(
                            'SOON',
                            style: TextStyle(
                              color: AppColors.textMuted,
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
                      color: subColor,
                      fontSize: 11,
                      fontFamily: 'monospace',
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

  // ── Screen: Identity Created (+ contacts) ───────────────────────────────────

  Widget _buildIdentityCreated() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const SizedBox(height: 32),
        // Avatar
        Container(
          width: 88,
          height: 88,
          decoration: BoxDecoration(
            color: AppColors.coreActive.withOpacity(0.12),
            borderRadius: BorderRadius.circular(44),
            border: Border.all(
              color: AppColors.coreActive.withOpacity(0.3),
              width: 2,
            ),
          ),
          child: _photoBase64 != null
              ? ClipRRect(
                  borderRadius: BorderRadius.circular(44),
                  child: Image.memory(
                    base64Decode(_photoBase64!),
                    fit: BoxFit.cover,
                  ),
                )
              : const Icon(Icons.person, color: AppColors.coreActive, size: 44),
        ),
        const SizedBox(height: 16),
        Text(
          _displayName.isNotEmpty ? _displayName : 'Your Identity',
          style: const TextStyle(
            color: AppColors.textPrimary,
            fontSize: 22,
            fontWeight: FontWeight.w700,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 6),
        const Text(
          'Your identity is live and protected.',
          style: TextStyle(
            color: AppColors.coreActive,
            fontSize: 13,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 20),
        // AID display
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(14),
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
              const SizedBox(height: 6),
              SelectableText(
                _aid ?? '',
                style: const TextStyle(
                  color: AppColors.accent,
                  fontSize: 11,
                  fontFamily: 'monospace',
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 6),
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
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: ElevatedButton(
            onPressed: widget.onComplete,
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.accent,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: const Text(
              'GO TO DASHBOARD',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.2,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ),
        const SizedBox(height: 32),
      ],
    );
  }

}
