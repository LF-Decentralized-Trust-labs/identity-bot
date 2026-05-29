import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/pin_password_service.dart';
import '../../services/local_auth_service.dart';
import '../../services/identity_level_service.dart';
import '../../widgets/identity_level_badge.dart';
import '../auth_setup_screen.dart';

/// Settings → Authentication
///
/// Shows all established auth factors, lets the user remove / change them,
/// and displays the current Identity Level tier.
class AuthManagementScreen extends StatefulWidget {
  const AuthManagementScreen({super.key});

  @override
  State<AuthManagementScreen> createState() => _AuthManagementScreenState();
}

class _AuthManagementScreenState extends State<AuthManagementScreen> {
  bool _loading = true;
  bool _hasPin = false;
  bool _hasPassword = false;
  BiometricAvailability _fingerprint = BiometricAvailability.unavailable;
  BiometricAvailability _face = BiometricAvailability.unavailable;
  DateTime? _lastAuth;
  ActiveFactors? _factors;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final hasPin = await PinPasswordService.hasPin();
    final hasPassword = await PinPasswordService.hasPassword();
    final fp = await LocalAuthService.fingerprintAvailability();
    final face = await LocalAuthService.faceAvailability();
    final lastAuth = await IdentityLevelService.lastAuthTime();
    final factors = await IdentityLevelService.loadFactors();
    if (mounted) {
      setState(() {
        _hasPin = hasPin;
        _hasPassword = hasPassword;
        _fingerprint = fp;
        _face = face;
        _lastAuth = lastAuth;
        _factors = factors;
        _loading = false;
      });
    }
  }

  Future<void> _removePin() async {
    final confirmed = await _confirm('Remove PIN?',
        'Your PIN will be removed. You can set a new one at any time.');
    if (!confirmed) return;
    await PinPasswordService.clearPin();
    await IdentityLevelService.refresh();
    _load();
  }

  Future<void> _removePassword() async {
    final confirmed = await _confirm('Remove Password?',
        'Your password will be removed. You can set a new one at any time.');
    if (!confirmed) return;
    await PinPasswordService.clearPassword();
    await IdentityLevelService.refresh();
    _load();
  }

  Future<void> _changePin() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
    );
    _load();
  }

  Future<void> _changePassword() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
    );
    _load();
  }

  Future<bool> _confirm(String title, String message) async {
    return await showDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
            backgroundColor: AppColors.surface,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
              side: BorderSide(color: AppColors.border),
            ),
            title: Text(title,
                style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                    fontFamily: 'monospace')),
            content: Text(message,
                style: const TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 12,
                    fontFamily: 'monospace')),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(ctx).pop(false),
                child: const Text('CANCEL',
                    style: TextStyle(
                        color: AppColors.textMuted, fontFamily: 'monospace')),
              ),
              ElevatedButton(
                onPressed: () => Navigator.of(ctx).pop(true),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFFDA1E28),
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8)),
                ),
                child: const Text('REMOVE',
                    style: TextStyle(fontFamily: 'monospace')),
              ),
            ],
          ),
        ) ??
        false;
  }

  String _formatLastAuth(DateTime? dt) {
    if (dt == null) return 'Never';
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: _loading
          ? const Center(
              child: CircularProgressIndicator(color: AppColors.accent))
          : SingleChildScrollView(
              padding: const EdgeInsets.all(32),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 720),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (!AppLayout.isMobile(context)) ...[
                      _buildPageHeader(),
                      const SizedBox(height: 32),
                    ],
                    _buildStatusCard(),
                    const SizedBox(height: 24),
                    _buildFactorSection(),
                  ],
                ),
              ),
            ),
    );
  }

  Widget _buildPageHeader() {
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'AUTHENTICATION',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 6),
              const Text(
                'Manage the methods used to unlock this device and verify your identity.',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  height: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
        ),
        FilledButton.icon(
          onPressed: () async {
            await Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
            );
            _load();
          },
          icon: const Icon(Icons.add, size: 16),
          label: const Text('Add Method',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, letterSpacing: 0.2)),
          style: FilledButton.styleFrom(
            backgroundColor: AppColors.accent,
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            minimumSize: const Size(0, 36),
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            elevation: 0,
          ),
        ),
      ],
    );
  }

  Widget _buildStatusCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Identity Level',
                  style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.8,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 8),
                LiveIdentityLevelBadge(),
                const SizedBox(height: 16),
                Row(
                  children: [
                    const Icon(Icons.access_time,
                        color: AppColors.textMuted, size: 13),
                    const SizedBox(width: 6),
                    Text(
                      'Last authenticated: ${_formatLastAuth(_lastAuth)}',
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFactorSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'AUTHENTICATION METHODS',
          style: TextStyle(
            color: AppColors.textMuted,
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 2.0,
            fontFamily: 'monospace',
          ),
        ),
        const SizedBox(height: 12),
        _buildFactorRow(
          icon: Icons.password_outlined,
          label: 'Password',
          status: _hasPassword ? 'Active' : 'Not set',
          active: _hasPassword,
          onManage: _hasPassword ? _changePassword : null,
          onRemove: _hasPassword ? _removePassword : null,
        ),
        const SizedBox(height: 8),
        _buildFactorRow(
          icon: Icons.dialpad_outlined,
          label: 'PIN',
          status: _hasPin ? 'Active' : 'Not set',
          active: _hasPin,
          onManage: _hasPin ? _changePin : null,
          onRemove: _hasPin ? _removePin : null,
        ),
        const SizedBox(height: 8),
        _buildFactorRow(
          icon: Icons.fingerprint,
          label: 'Fingerprint',
          status: _biometricStatus(_fingerprint),
          active: _fingerprint == BiometricAvailability.available,
          systemManaged: true,
        ),
        const SizedBox(height: 8),
        _buildFactorRow(
          icon: Icons.face_outlined,
          label: 'Face ID',
          status: _biometricStatus(_face),
          active: _face == BiometricAvailability.available,
          systemManaged: true,
        ),
        const SizedBox(height: 8),
        _buildFactorRow(
          icon: Icons.people_outline,
          label: 'Witnesses',
          status: '${_factors?.witnessCount ?? 0} / 3 confirmed',
          active: (_factors?.witnessCount ?? 0) >= 3,
          systemManaged: true,
        ),
        const SizedBox(height: 8),
        _buildFactorRow(
          icon: Icons.verified_outlined,
          label: 'Gov ID Credential',
          status: (_factors?.hasCredential ?? false)
              ? 'Credential on file'
              : 'Not provided',
          active: _factors?.hasCredential ?? false,
          systemManaged: true,
        ),
      ],
    );
  }

  String _biometricStatus(BiometricAvailability avail) {
    switch (avail) {
      case BiometricAvailability.available:
        return 'Active';
      case BiometricAvailability.availableNotEnrolled:
        return 'Not enrolled (enroll in device settings)';
      case BiometricAvailability.unavailable:
        return 'Not available on this device';
    }
  }

  Widget _buildFactorRow({
    required IconData icon,
    required String label,
    required String status,
    required bool active,
    bool systemManaged = false,
    VoidCallback? onManage,
    VoidCallback? onRemove,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: active
            ? AppColors.coreActive.withOpacity(0.04)
            : AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: active
              ? AppColors.coreActive.withOpacity(0.2)
              : AppColors.border,
        ),
      ),
      child: Row(
        children: [
          Icon(
            icon,
            color: active ? AppColors.coreActive : AppColors.textMuted,
            size: 20,
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: TextStyle(
                    color: active
                        ? AppColors.textPrimary
                        : AppColors.textSecondary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  status,
                  style: TextStyle(
                    color: active ? AppColors.coreActive : AppColors.textMuted,
                    fontSize: 11,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
          ),
          if (systemManaged && active)
            const Icon(Icons.check_circle,
                color: AppColors.coreActive, size: 18),
          if (!systemManaged && onManage != null) ...[
            TextButton(
              onPressed: onManage,
              style: TextButton.styleFrom(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                minimumSize: Size.zero,
              ),
              child: const Text(
                'Change',
                style: TextStyle(
                  color: AppColors.accent,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            TextButton(
              onPressed: onRemove,
              style: TextButton.styleFrom(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                minimumSize: Size.zero,
              ),
              child: const Text(
                'Remove',
                style: TextStyle(
                  color: Color(0xFFDA1E28),
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildAddMethodButton() {
    return Align(
      alignment: Alignment.centerLeft,
      child: OutlinedButton.icon(
        onPressed: () async {
          await Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => const AuthSetupScreen()),
          );
          _load();
        },
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.accent,
          side: const BorderSide(color: AppColors.accent),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
        icon: const Icon(Icons.add, size: 14),
        label: const Text(
          'Add / Improve Authentication',
          style: TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.w600, fontSize: 12),
        ),
      ),
    );
  }
}
