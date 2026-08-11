import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/app_theme.dart';
import 'package:agent_client/services/identity_level_service.dart';
import '../services/pin_password_service.dart';
import 'package:agent_client/services/local_auth_service.dart';
import 'package:agent_client/services/setup_task_service.dart';

/// Desktop authentication setup screen.
///
/// Shows a tile grid of available authentication methods.
/// Each tile reflects the device's runtime capability:
///   Active (green check)  → method is enrolled and working
///   Caution (amber ⚠)    → supported but not enrolled (e.g. fingerprint reader exists but not set up in OS)
///   Unavailable (gray)    → hardware not present on this device
class AuthSetupScreen extends StatefulWidget {
  final VoidCallback? onComplete;

  const AuthSetupScreen({super.key, this.onComplete});

  @override
  State<AuthSetupScreen> createState() => _AuthSetupScreenState();
}

class _AuthSetupScreenState extends State<AuthSetupScreen> {
  bool _loading = true;
  ActiveFactors? _factors;
  BiometricAvailability _fingerprintState = BiometricAvailability.unavailable;
  BiometricAvailability _faceState = BiometricAvailability.unavailable;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final factors = await IdentityLevelService.loadFactors();
    final fp = await LocalAuthService.fingerprintAvailability();
    final face = await LocalAuthService.faceAvailability();
    if (mounted) {
      setState(() {
        _factors = factors;
        _fingerprintState = fp;
        _faceState = face;
        _loading = false;
      });
    }
  }

  IdentityTier get _tier =>
      _factors != null ? IdentityLevelService.computeTier(_factors!) : IdentityTier.notVerified;

  // ── PIN / Password dialogs ────────────────────────────────────────────────

  Future<void> _setupPin() async {
    final ctrl = TextEditingController();
    final confirmCtrl = TextEditingController();
    String? error;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: AppColors.accent.withOpacity(0.3)),
          ),
          title: const Text('Set up PIN',
              style: TextStyle(color: AppColors.textPrimary, fontSize: 15,
                  fontWeight: FontWeight.w700, fontFamily: 'monospace')),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('Enter a 4–6 digit PIN to lock the app.',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 13, fontFamily: 'monospace')),
              const SizedBox(height: 12),
              _pinField(ctrl, 'PIN', error),
              const SizedBox(height: 10),
              _pinField(confirmCtrl, 'Confirm PIN', null),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx),
                child: const Text('Cancel', style: TextStyle(color: AppColors.textMuted))),
            TextButton(
              onPressed: () async {
                final pin = ctrl.text.trim();
                final confirm = confirmCtrl.text.trim();
                if (pin.length < 4 || pin.length > 6) {
                  setS(() => error = 'PIN must be 4–6 digits');
                  return;
                }
                if (pin != confirm) {
                  setS(() => error = 'PINs do not match');
                  return;
                }
                await PinPasswordService.setPin(pin);
                await IdentityLevelService.refresh();
                if (ctx.mounted) Navigator.pop(ctx);
              },
              child: const Text('Save', style: TextStyle(color: AppColors.accent, fontWeight: FontWeight.w700)),
            ),
          ],
        ),
      ),
    );
    await _load();
    await _maybeComplete();
  }

  Future<void> _setupPassword() async {
    final ctrl = TextEditingController();
    final confirmCtrl = TextEditingController();
    bool obscure = true;
    String? error;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: AppColors.accent.withOpacity(0.3)),
          ),
          title: const Text('Set up password',
              style: TextStyle(color: AppColors.textPrimary, fontSize: 15,
                  fontWeight: FontWeight.w700, fontFamily: 'monospace')),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('Minimum 8 characters.',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 13, fontFamily: 'monospace')),
              const SizedBox(height: 12),
              TextField(
                controller: ctrl,
                obscureText: obscure,
                decoration: InputDecoration(
                  labelText: 'Password',
                  errorText: error,
                  suffixIcon: IconButton(
                    icon: Icon(obscure ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                        color: AppColors.textMuted, size: 18),
                    onPressed: () => setS(() => obscure = !obscure),
                  ),
                ),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: confirmCtrl,
                obscureText: true,
                decoration: const InputDecoration(labelText: 'Confirm password'),
              ),
            ],
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx),
                child: const Text('Cancel', style: TextStyle(color: AppColors.textMuted))),
            TextButton(
              onPressed: () async {
                final pw = ctrl.text;
                if (pw.length < 8) { setS(() => error = 'Minimum 8 characters'); return; }
                if (pw != confirmCtrl.text) { setS(() => error = 'Passwords do not match'); return; }
                await PinPasswordService.setPassword(pw);
                await IdentityLevelService.refresh();
                if (ctx.mounted) Navigator.pop(ctx);
              },
              child: const Text('Save', style: TextStyle(color: AppColors.accent, fontWeight: FontWeight.w700)),
            ),
          ],
        ),
      ),
    );
    await _load();
    await _maybeComplete();
  }

  Future<void> _maybeComplete() async {
    if (widget.onComplete == null) return;
    final tier = await IdentityLevelService.currentTier();
    if (tier.level >= IdentityTier.authenticated.level) {
      await SetupTaskService.markComplete(SetupTask.setupAuthentication);
      widget.onComplete!();
    }
  }

  // ── Build ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      appBar: AppBar(
        backgroundColor: AppColors.surface,
        elevation: 0,
        title: const Text('Authentication Setup',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 16,
                fontWeight: FontWeight.w700, fontFamily: 'monospace')),
        iconTheme: const IconThemeData(color: AppColors.textPrimary),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: AppColors.accent))
          : SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 680),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildTierProgress(),
                      const SizedBox(height: 28),
                      const Text('Authentication Methods',
                          style: TextStyle(color: AppColors.textMuted, fontSize: 11,
                              fontWeight: FontWeight.w700, letterSpacing: 1.5,
                              fontFamily: 'monospace')),
                      const SizedBox(height: 12),
                      _buildGrid(),
                    ],
                  ),
                ),
              ),
            ),
    );
  }

  Widget _buildTierProgress() {
    final tiers = IdentityTier.values;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text('Identity Level',
                  style: TextStyle(color: AppColors.textPrimary, fontSize: 14,
                      fontWeight: FontWeight.w700, fontFamily: 'monospace')),
              const Spacer(),
              Text(_tier.label,
                  style: TextStyle(
                    color: _tier.isGreen ? const Color(0xFF24A148)
                        : _tier.isAmber ? const Color(0xFFFF832B)
                        : const Color(0xFFDA1E28),
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    fontFamily: 'monospace',
                  )),
            ],
          ),
          if (_tier.nistLabel.isNotEmpty) ...[
            const SizedBox(height: 2),
            Text(_tier.nistLabel,
                style: const TextStyle(color: AppColors.textMuted, fontSize: 10,
                    fontFamily: 'monospace')),
          ],
          const SizedBox(height: 12),
          Row(
            children: tiers.map((t) {
              final active = t.level <= _tier.level;
              final isCurrent = t == _tier;
              Color dotColor = active
                  ? (t.isGreen ? const Color(0xFF24A148)
                      : t.isAmber ? const Color(0xFFFF832B)
                      : const Color(0xFFDA1E28))
                  : AppColors.border;
              return Expanded(
                child: Column(
                  children: [
                    Row(
                      children: [
                        if (t.index > 0)
                          Expanded(child: Container(height: 2,
                              color: active ? dotColor : AppColors.border)),
                        Container(
                          width: 12, height: 12,
                          decoration: BoxDecoration(
                            color: active ? dotColor : AppColors.background,
                            shape: BoxShape.circle,
                            border: Border.all(color: active ? dotColor : AppColors.border, width: 2),
                          ),
                        ),
                        if (t.index < tiers.length - 1)
                          Expanded(child: Container(height: 2,
                              color: (t.level < _tier.level) ? dotColor : AppColors.border)),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(t.label,
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          color: isCurrent ? AppColors.textPrimary : AppColors.textMuted,
                          fontSize: 8,
                          fontWeight: isCurrent ? FontWeight.w700 : FontWeight.w400,
                          fontFamily: 'monospace',
                        )),
                  ],
                ),
              );
            }).toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildGrid() {
    final f = _factors!;
    final tiles = <_TileData>[
      _TileData(
        icon: Icons.password_outlined,
        label: 'Password',
        state: f.hasPassword ? _TileState.active : _TileState.inactive,
        onTap: f.hasPassword ? null : _setupPassword,
      ),
      _TileData(
        icon: Icons.pin_outlined,
        label: 'PIN',
        state: f.hasPin ? _TileState.active : _TileState.inactive,
        onTap: f.hasPin ? null : _setupPin,
      ),
      _TileData(
        icon: Icons.fingerprint,
        label: 'Fingerprint',
        state: _biometricTileState(_fingerprintState),
        subtitle: _fingerprintState == BiometricAvailability.availableNotEnrolled
            ? 'Enable in OS settings' : null,
        onTap: null, // OS-managed
      ),
      _TileData(
        icon: Icons.face_outlined,
        label: 'Face Scan',
        state: _biometricTileState(_faceState),
        subtitle: _faceState == BiometricAvailability.availableNotEnrolled
            ? 'Enable in OS settings' : null,
        onTap: null,
      ),
      _TileData(
        icon: Icons.people_outline,
        label: 'Witnesses',
        state: f.witnessCount >= 3 ? _TileState.active : _TileState.inactive,
        subtitle: f.witnessCount >= 3 ? null : '${f.witnessCount} / 3',
        onTap: null, // managed via contacts flow
      ),
      _TileData(
        icon: Icons.badge_outlined,
        label: 'Gov ID Credential',
        state: f.hasCredential ? _TileState.active : _TileState.inactive,
        subtitle: f.hasCredential ? null : 'Request from provider →',
        onTap: f.hasCredential ? null : _showCredentialInfo,
      ),
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        childAspectRatio: 1.1,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
      ),
      itemCount: tiles.length,
      itemBuilder: (_, i) => _buildTile(tiles[i]),
    );
  }

  _TileState _biometricTileState(BiometricAvailability avail) {
    switch (avail) {
      case BiometricAvailability.available:          return _TileState.active;
      case BiometricAvailability.availableNotEnrolled: return _TileState.caution;
      case BiometricAvailability.unavailable:        return _TileState.unavailable;
    }
  }

  Widget _buildTile(_TileData tile) {
    Color iconColor;
    Color borderColor;
    Color bg;
    Widget statusIcon;

    switch (tile.state) {
      case _TileState.active:
        iconColor = const Color(0xFF24A148);
        borderColor = const Color(0xFF24A148).withOpacity(0.3);
        bg = const Color(0xFF24A148).withOpacity(0.05);
        statusIcon = const Icon(Icons.check_circle, color: Color(0xFF24A148), size: 16);
      case _TileState.caution:
        iconColor = const Color(0xFFFF832B);
        borderColor = const Color(0xFFFF832B).withOpacity(0.3);
        bg = const Color(0xFFFF832B).withOpacity(0.05);
        statusIcon = const Icon(Icons.warning_amber_outlined, color: Color(0xFFFF832B), size: 16);
      case _TileState.inactive:
        iconColor = AppColors.accent;
        borderColor = AppColors.border;
        bg = AppColors.surface;
        statusIcon = const SizedBox.shrink();
      case _TileState.unavailable:
        iconColor = AppColors.textMuted;
        borderColor = AppColors.border;
        bg = AppColors.surfaceVariant;
        statusIcon = const SizedBox.shrink();
    }

    return GestureDetector(
      onTap: tile.state == _TileState.unavailable ? null : tile.onTap,
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: borderColor),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(tile.icon, color: iconColor, size: 26),
                if (tile.state != _TileState.inactive && tile.state != _TileState.unavailable) ...[
                  const SizedBox(width: 4),
                  statusIcon,
                ],
              ],
            ),
            const SizedBox(height: 8),
            Text(tile.label,
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: tile.state == _TileState.unavailable
                      ? AppColors.textMuted : AppColors.textPrimary,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  fontFamily: 'monospace',
                )),
            if (tile.subtitle != null) ...[
              const SizedBox(height: 3),
              Text(tile.subtitle!,
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: AppColors.textMuted,
                      fontSize: 10, fontFamily: 'monospace')),
            ],
          ],
        ),
      ),
    );
  }

  void _showCredentialInfo() {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: AppColors.border)),
        title: const Text('Verified Credential',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 14,
                fontWeight: FontWeight.w700, fontFamily: 'monospace')),
        content: const Text(
          'To reach Highly Verified status, you need a verifiable credential '
          'issued by a trusted identity verification provider.\n\n'
          'Contact a compatible identity agent provider to request one. '
          'The credential will appear here automatically once issued.',
          style: TextStyle(color: AppColors.textSecondary, fontSize: 13,
              fontFamily: 'monospace', height: 1.5),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx),
              child: const Text('Got it', style: TextStyle(color: AppColors.accent))),
        ],
      ),
    );
  }

  Widget _pinField(TextEditingController ctrl, String label, String? error) {
    return TextField(
      controller: ctrl,
      obscureText: true,
      keyboardType: TextInputType.number,
      inputFormatters: [
        FilteringTextInputFormatter.digitsOnly,
        LengthLimitingTextInputFormatter(6),
      ],
      decoration: InputDecoration(labelText: label, errorText: error),
    );
  }
}

enum _TileState { active, caution, inactive, unavailable }

class _TileData {
  final IconData icon;
  final String label;
  final _TileState state;
  final String? subtitle;
  final VoidCallback? onTap;

  const _TileData({
    required this.icon,
    required this.label,
    required this.state,
    this.subtitle,
    this.onTap,
  });
}
