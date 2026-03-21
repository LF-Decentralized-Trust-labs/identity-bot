import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/pin_password_service.dart';
import '../../services/local_auth_service.dart';
import '../../services/identity_level_service.dart';
import '../../widgets/identity_level_badge.dart';
import 'mobile_auth_setup_screen.dart';

/// Settings → Authentication (mobile)
///
/// Shows established auth factors, allows removal/change, shows current tier.
class MobileAuthManagementScreen extends StatefulWidget {
  const MobileAuthManagementScreen({super.key});

  @override
  State<MobileAuthManagementScreen> createState() =>
      _MobileAuthManagementScreenState();
}

class _MobileAuthManagementScreenState
    extends State<MobileAuthManagementScreen> {
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

  Future<bool> _confirm(String title, String body) async {
    return await showModalBottomSheet<bool>(
          context: context,
          backgroundColor: MobileColors.surface,
          shape: const RoundedRectangleBorder(
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          builder: (ctx) => Padding(
            padding: const EdgeInsets.fromLTRB(24, 24, 24, 36),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title,
                    style: const TextStyle(
                        color: MobileColors.textPrimary,
                        fontSize: 18,
                        fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                Text(body,
                    style: const TextStyle(
                        color: MobileColors.textSecondary, fontSize: 14)),
                const SizedBox(height: 24),
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton(
                        onPressed: () => Navigator.of(ctx).pop(false),
                        style: OutlinedButton.styleFrom(
                          side:
                              const BorderSide(color: MobileColors.border),
                          padding:
                              const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10)),
                        ),
                        child: const Text('Cancel',
                            style:
                                TextStyle(color: MobileColors.textPrimary)),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: ElevatedButton(
                        onPressed: () => Navigator.of(ctx).pop(true),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFDA1E28),
                          foregroundColor: Colors.white,
                          padding:
                              const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10)),
                        ),
                        child: const Text('Remove'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ) ??
        false;
  }

  Future<void> _removePin() async {
    if (!await _confirm('Remove PIN?',
        'Your PIN will be removed. You can set a new one at any time.')) return;
    await PinPasswordService.clearPin();
    await IdentityLevelService.refresh();
    _load();
  }

  Future<void> _removePassword() async {
    if (!await _confirm('Remove Password?',
        'Your password will be removed. You can set a new one at any time.'))
      return;
    await PinPasswordService.clearPassword();
    await IdentityLevelService.refresh();
    _load();
  }

  String _formatLastAuth(DateTime? dt) {
    if (dt == null) return 'Never';
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  String _biometricStatus(BiometricAvailability avail) {
    switch (avail) {
      case BiometricAvailability.available:
        return 'Active';
      case BiometricAvailability.availableNotEnrolled:
        return 'Not enrolled — enroll in device Settings';
      case BiometricAvailability.unavailable:
        return 'Not available on this device';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          backgroundColor: MobileColors.surface,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back,
                color: MobileColors.textPrimary),
            onPressed: () => Navigator.of(context).pop(),
          ),
          title: const Text(
            'Authentication',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
        body: _loading
            ? const Center(
                child: CircularProgressIndicator(
                    color: MobileColors.primary))
            : ListView(
                padding: const EdgeInsets.fromLTRB(16, 20, 16, 32),
                children: [
                  _buildStatusCard(),
                  const SizedBox(height: 24),
                  _buildSectionLabel('AUTHENTICATION METHODS'),
                  const SizedBox(height: 10),
                  _buildFactorTile(
                    icon: Icons.password_outlined,
                    label: 'Password',
                    status: _hasPassword ? 'Active' : 'Not set',
                    active: _hasPassword,
                    onTap: _hasPassword
                        ? () => _showManageSheet('Password',
                            onManage: _navigateToSetup,
                            onRemove: _removePassword)
                        : null,
                  ),
                  _buildFactorTile(
                    icon: Icons.dialpad_outlined,
                    label: 'PIN',
                    status: _hasPin ? 'Active' : 'Not set',
                    active: _hasPin,
                    onTap: _hasPin
                        ? () => _showManageSheet('PIN',
                            onManage: _navigateToSetup,
                            onRemove: _removePin)
                        : null,
                  ),
                  _buildFactorTile(
                    icon: Icons.fingerprint,
                    label: 'Fingerprint',
                    status: _biometricStatus(_fingerprint),
                    active: _fingerprint == BiometricAvailability.available,
                    systemManaged: true,
                  ),
                  _buildFactorTile(
                    icon: Icons.face_outlined,
                    label: 'Face ID',
                    status: _biometricStatus(_face),
                    active: _face == BiometricAvailability.available,
                    systemManaged: true,
                  ),
                  _buildFactorTile(
                    icon: Icons.people_outline,
                    label: 'Witnesses',
                    status: '${_factors?.witnessCount ?? 0} / 3 confirmed',
                    active: (_factors?.witnessCount ?? 0) >= 3,
                    systemManaged: true,
                  ),
                  _buildFactorTile(
                    icon: Icons.verified_outlined,
                    label: 'Gov ID Credential',
                    status: (_factors?.hasCredential ?? false)
                        ? 'Credential on file'
                        : 'Not provided',
                    active: _factors?.hasCredential ?? false,
                    systemManaged: true,
                  ),
                  const SizedBox(height: 24),
                  ElevatedButton.icon(
                    onPressed: _navigateToSetup,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: MobileColors.primary,
                      foregroundColor: MobileColors.textOnPrimary,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10)),
                    ),
                    icon: const Icon(Icons.add, size: 18),
                    label: const Text(
                      'Add / Improve Authentication',
                      style: TextStyle(fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildStatusCard() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
        boxShadow: [
          BoxShadow(
              color: MobileColors.cardShadow,
              blurRadius: 6,
              offset: const Offset(0, 2)),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Identity Level',
            style: TextStyle(
              color: MobileColors.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5,
            ),
          ),
          const SizedBox(height: 10),
          LiveIdentityLevelBadge(),
          const SizedBox(height: 12),
          Row(
            children: [
              const Icon(Icons.access_time,
                  color: MobileColors.textMuted, size: 13),
              const SizedBox(width: 6),
              Text(
                'Last authenticated: ${_formatLastAuth(_lastAuth)}',
                style: const TextStyle(
                    color: MobileColors.textMuted, fontSize: 12),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSectionLabel(String label) {
    return Text(
      label,
      style: const TextStyle(
        color: MobileColors.textMuted,
        fontSize: 11,
        fontWeight: FontWeight.w600,
        letterSpacing: 1.0,
      ),
    );
  }

  Widget _buildFactorTile({
    required IconData icon,
    required String label,
    required String status,
    required bool active,
    bool systemManaged = false,
    VoidCallback? onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: active
              ? MobileColors.success.withOpacity(0.04)
              : MobileColors.surface,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: active
                ? MobileColors.success.withOpacity(0.25)
                : MobileColors.border,
          ),
          boxShadow: [
            BoxShadow(
                color: MobileColors.cardShadow,
                blurRadius: 3,
                offset: const Offset(0, 1)),
          ],
        ),
        child: Row(
          children: [
            Icon(
              icon,
              color: active ? MobileColors.success : MobileColors.textMuted,
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
                          ? MobileColors.textPrimary
                          : MobileColors.textSecondary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    status,
                    style: TextStyle(
                      color: active
                          ? MobileColors.success
                          : MobileColors.textMuted,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
            if (systemManaged && active)
              const Icon(Icons.check_circle,
                  color: MobileColors.success, size: 18)
            else if (!systemManaged && onTap != null)
              const Icon(Icons.chevron_right,
                  color: MobileColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }

  void _showManageSheet(String method,
      {required VoidCallback onManage, required VoidCallback onRemove}) {
    showModalBottomSheet(
      context: context,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 36),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Manage $method',
              style: const TextStyle(
                color: MobileColors.textPrimary,
                fontSize: 18,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 20),
            _sheetButton(
              icon: Icons.edit_outlined,
              label: 'Change $method',
              color: MobileColors.primary,
              onTap: () {
                Navigator.of(ctx).pop();
                onManage();
              },
            ),
            const SizedBox(height: 10),
            _sheetButton(
              icon: Icons.delete_outline,
              label: 'Remove $method',
              color: const Color(0xFFDA1E28),
              onTap: () {
                Navigator.of(ctx).pop();
                onRemove();
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _sheetButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: color.withOpacity(0.08),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withOpacity(0.25)),
        ),
        child: Row(
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(width: 12),
            Text(
              label,
              style: TextStyle(
                  color: color, fontSize: 15, fontWeight: FontWeight.w600),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _navigateToSetup() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const MobileAuthSetupScreen()),
    );
    _load();
  }
}
