import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:agent_client/services/local_auth_service.dart';
import '../services/pin_password_service.dart';
import 'package:agent_client/services/identity_level_service.dart';
import '../theme/app_theme.dart';

/// Full-screen lock overlay shown when the app resumes after being backgrounded.
///
/// Tries biometric first (if enrolled), then falls back to PIN/password entry.
/// Cannot be dismissed by back navigation.
class LockScreen extends StatefulWidget {
  final VoidCallback onUnlocked;

  const LockScreen({super.key, required this.onUnlocked});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _inputController = TextEditingController();
  bool _showManualEntry = false;
  bool _error = false;
  bool _obscure = true;
  bool _loading = false;
  bool _biometricSupported = false;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    _biometricSupported = await LocalAuthService.isSupported();
    await _tryBiometric();
  }

  @override
  void dispose() {
    _inputController.dispose();
    super.dispose();
  }

  Future<void> _tryBiometric() async {
    if (!_biometricSupported) {
      if (mounted) setState(() => _showManualEntry = true);
      return;
    }

    final hasBiometric =
        await LocalAuthService.fingerprintAvailability() == BiometricAvailability.available ||
        await LocalAuthService.faceAvailability() == BiometricAvailability.available;

    if (!hasBiometric) {
      if (mounted) setState(() => _showManualEntry = true);
      return;
    }

    final success = await LocalAuthService.authenticate(
      reason: 'Unlock Identity Agent',
    );

    if (success) {
      await IdentityLevelService.recordAuthEvent();
      widget.onUnlocked();
    } else {
      if (mounted) setState(() => _showManualEntry = true);
    }
  }

  Future<void> _submitManual() async {
    final value = _inputController.text.trim();
    if (value.isEmpty) return;

    setState(() { _loading = true; _error = false; });

    final ok = await PinPasswordService.verifyAny(value);

    if (!mounted) return;

    if (ok) {
      await IdentityLevelService.recordAuthEvent();
      widget.onUnlocked();
    } else {
      setState(() { _loading = false; _error = true; });
      _inputController.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false, // cannot dismiss with back button
      child: Scaffold(
        backgroundColor: AppColors.background,
        body: SafeArea(
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 360),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 32),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Container(
                      width: 72,
                      height: 72,
                      decoration: BoxDecoration(
                        color: AppColors.accent.withOpacity(0.12),
                        borderRadius: BorderRadius.circular(36),
                      ),
                      child: const Icon(
                        Icons.lock_outline,
                        color: AppColors.accent,
                        size: 36,
                      ),
                    ),
                    const SizedBox(height: 24),
                    const Text(
                      'Identity Agent is locked',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 18,
                        fontWeight: FontWeight.w700,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Authenticate to continue.',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 13,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(height: 40),

                    if (!_showManualEntry) ...[
                      const CircularProgressIndicator(color: AppColors.accent),
                      const SizedBox(height: 20),
                      TextButton(
                        onPressed: () => setState(() => _showManualEntry = true),
                        child: const Text(
                          'Use PIN or password instead',
                          style: TextStyle(color: AppColors.accent, fontSize: 13),
                        ),
                      ),
                    ] else ...[
                      TextField(
                        controller: _inputController,
                        obscureText: _obscure,
                        keyboardType: TextInputType.visiblePassword,
                        autofocus: true,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontFamily: 'monospace',
                        ),
                        decoration: InputDecoration(
                          hintText: 'PIN or password',
                          hintStyle: TextStyle(color: AppColors.textMuted),
                          filled: true,
                          fillColor: AppColors.surface,
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(10),
                            borderSide: BorderSide(color: AppColors.border),
                          ),
                          enabledBorder: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(10),
                            borderSide: BorderSide(color: AppColors.border),
                          ),
                          focusedBorder: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(10),
                            borderSide: BorderSide(color: AppColors.accent),
                          ),
                          errorText: _error ? 'Incorrect PIN or password' : null,
                          errorStyle: const TextStyle(color: Color(0xFFDA1E28)),
                          suffixIcon: IconButton(
                            icon: Icon(
                              _obscure ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                              color: AppColors.textMuted,
                              size: 20,
                            ),
                            onPressed: () => setState(() => _obscure = !_obscure),
                          ),
                        ),
                        onSubmitted: (_) => _submitManual(),
                        inputFormatters: [
                          // Allow numeric PIN (digits only short) or full password
                          FilteringTextInputFormatter.singleLineFormatter,
                        ],
                      ),
                      const SizedBox(height: 16),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: _loading ? null : _submitManual,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppColors.accent,
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(vertical: 14),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10),
                            ),
                          ),
                          child: _loading
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Colors.white,
                                  ),
                                )
                              : const Text(
                                  'Unlock',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontWeight: FontWeight.w700,
                                    fontFamily: 'monospace',
                                  ),
                                ),
                        ),
                      ),
                      if (_biometricSupported) ...[
                        const SizedBox(height: 12),
                        TextButton.icon(
                          onPressed: () {
                            setState(() => _showManualEntry = false);
                            _tryBiometric();
                          },
                          icon: const Icon(Icons.fingerprint, color: AppColors.accent, size: 18),
                          label: const Text(
                            'Use biometrics',
                            style: TextStyle(color: AppColors.accent, fontSize: 13),
                          ),
                        ),
                      ],
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
