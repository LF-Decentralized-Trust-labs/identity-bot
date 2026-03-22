import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../theme/mobile_theme.dart';
import '../../services/identity_level_service.dart';
import '../../services/pin_password_service.dart';
import '../../services/local_auth_service.dart';
import '../../services/setup_task_service.dart';

/// Mobile authentication setup screen — same logic as desktop, mobile styling.
class MobileAuthSetupScreen extends StatefulWidget {
  final VoidCallback? onComplete;

  const MobileAuthSetupScreen({super.key, this.onComplete});

  @override
  State<MobileAuthSetupScreen> createState() => _MobileAuthSetupScreenState();
}

class _MobileAuthSetupScreenState extends State<MobileAuthSetupScreen> {
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

  // ── PIN / Password bottom sheets ──────────────────────────────────────────

  Future<void> _setupPin() async {
    final ctrl = TextEditingController();
    final confirmCtrl = TextEditingController();
    String? error;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(ctx).viewInsets.bottom),
        child: StatefulBuilder(
          builder: (ctx, setS) => Container(
            decoration: const BoxDecoration(
              color: MobileColors.surface,
              borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
            ),
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _handle(),
                const SizedBox(height: 16),
                const Text('Set up PIN',
                    style: TextStyle(color: MobileColors.textPrimary, fontSize: 17,
                        fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Text('Enter a 4–6 digit PIN.',
                    style: TextStyle(color: MobileColors.textSecondary, fontSize: 13)),
                const SizedBox(height: 16),
                _mobilePinField(ctrl, 'PIN', error),
                const SizedBox(height: 10),
                _mobilePinField(confirmCtrl, 'Confirm PIN', null),
                const SizedBox(height: 20),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: MobileColors.primary,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                    onPressed: () async {
                      final pin = ctrl.text.trim();
                      final confirm = confirmCtrl.text.trim();
                      if (pin.length < 4 || pin.length > 6) {
                        setS(() => error = 'PIN must be 4–6 digits'); return;
                      }
                      if (pin != confirm) {
                        setS(() => error = 'PINs do not match'); return;
                      }
                      await PinPasswordService.setPin(pin);
                      await IdentityLevelService.refresh();
                      if (ctx.mounted) Navigator.pop(ctx);
                    },
                    child: const Text('Save PIN', style: TextStyle(fontWeight: FontWeight.w700)),
                  ),
                ),
              ],
            ),
          ),
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

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(ctx).viewInsets.bottom),
        child: StatefulBuilder(
          builder: (ctx, setS) => Container(
            decoration: const BoxDecoration(
              color: MobileColors.surface,
              borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
            ),
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _handle(),
                const SizedBox(height: 16),
                const Text('Set up password',
                    style: TextStyle(color: MobileColors.textPrimary, fontSize: 17,
                        fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Text('Minimum 8 characters.',
                    style: TextStyle(color: MobileColors.textSecondary, fontSize: 13)),
                const SizedBox(height: 16),
                TextField(
                  controller: ctrl,
                  obscureText: obscure,
                  decoration: InputDecoration(
                    labelText: 'Password',
                    errorText: error,
                    suffixIcon: IconButton(
                      icon: Icon(obscure ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                          color: MobileColors.textSecondary, size: 18),
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
                const SizedBox(height: 20),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: MobileColors.primary,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                    onPressed: () async {
                      final pw = ctrl.text;
                      if (pw.length < 8) { setS(() => error = 'Minimum 8 characters'); return; }
                      if (pw != confirmCtrl.text) { setS(() => error = 'Do not match'); return; }
                      await PinPasswordService.setPassword(pw);
                      await IdentityLevelService.refresh();
                      if (ctx.mounted) Navigator.pop(ctx);
                    },
                    child: const Text('Save password', style: TextStyle(fontWeight: FontWeight.w700)),
                  ),
                ),
              ],
            ),
          ),
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
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          backgroundColor: MobileColors.surface,
          elevation: 0,
          title: const Text('Authentication Setup',
              style: TextStyle(color: MobileColors.textPrimary, fontSize: 16,
                  fontWeight: FontWeight.w700)),
          iconTheme: const IconThemeData(color: MobileColors.textPrimary),
        ),
        body: _loading
            ? Center(child: CircularProgressIndicator(color: MobileColors.primary))
            : SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildTierCard(),
                    const SizedBox(height: 20),
                    Text('Authentication Methods',
                        style: TextStyle(color: MobileColors.textSecondary,
                            fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 1.5)),
                    const SizedBox(height: 10),
                    _buildGrid(),
                  ],
                ),
              ),
      ),
    );
  }

  Widget _buildTierCard() {
    Color tierColor = _tier.isGreen
        ? const Color(0xFF24A148)
        : _tier.isAmber ? const Color(0xFFFF832B) : const Color(0xFFDA1E28);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: MobileColors.border),
        boxShadow: [BoxShadow(color: MobileColors.cardShadow, blurRadius: 6, offset: const Offset(0, 2))],
      ),
      child: Row(
        children: [
          Icon(
            _tier.isGreen ? Icons.shield : Icons.shield_outlined,
            color: tierColor, size: 28,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(_tier.label,
                    style: TextStyle(color: tierColor, fontSize: 15,
                        fontWeight: FontWeight.w700)),
                if (_tier.nistLabel.isNotEmpty)
                  Text(_tier.nistLabel,
                      style: TextStyle(color: MobileColors.textSecondary, fontSize: 11)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildGrid() {
    final f = _factors!;
    final tiles = <_TileData>[
      _TileData(icon: Icons.password_outlined, label: 'Password',
          state: f.hasPassword ? _TileState.active : _TileState.inactive,
          onTap: f.hasPassword ? null : _setupPassword),
      _TileData(icon: Icons.pin_outlined, label: 'PIN',
          state: f.hasPin ? _TileState.active : _TileState.inactive,
          onTap: f.hasPin ? null : _setupPin),
      _TileData(icon: Icons.fingerprint, label: 'Fingerprint',
          state: _biometricState(_fingerprintState),
          subtitle: _fingerprintState == BiometricAvailability.availableNotEnrolled
              ? 'Enable in Settings' : null),
      _TileData(icon: Icons.face_outlined, label: 'Face Scan',
          state: _biometricState(_faceState),
          subtitle: _faceState == BiometricAvailability.availableNotEnrolled
              ? 'Enable in Settings' : null),
      _TileData(icon: Icons.people_outline, label: 'Witnesses',
          state: f.witnessCount >= 3 ? _TileState.active : _TileState.inactive,
          subtitle: f.witnessCount >= 3 ? null : '${f.witnessCount} / 3'),
      _TileData(icon: Icons.badge_outlined, label: 'Gov ID',
          state: f.hasCredential ? _TileState.active : _TileState.inactive,
          subtitle: f.hasCredential ? null : 'Request →',
          onTap: f.hasCredential ? null : _showCredentialInfo),
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        childAspectRatio: 0.95,
        crossAxisSpacing: 10,
        mainAxisSpacing: 10,
      ),
      itemCount: tiles.length,
      itemBuilder: (_, i) => _buildTile(tiles[i]),
    );
  }

  _TileState _biometricState(BiometricAvailability a) {
    switch (a) {
      case BiometricAvailability.available:           return _TileState.active;
      case BiometricAvailability.availableNotEnrolled: return _TileState.caution;
      case BiometricAvailability.unavailable:         return _TileState.unavailable;
    }
  }

  Widget _buildTile(_TileData tile) {
    Color iconColor;
    Color borderColor;
    Color bg;

    switch (tile.state) {
      case _TileState.active:
        iconColor = const Color(0xFF24A148);
        borderColor = const Color(0xFF24A148).withOpacity(0.3);
        bg = const Color(0xFF24A148).withOpacity(0.05);
      case _TileState.caution:
        iconColor = const Color(0xFFFF832B);
        borderColor = const Color(0xFFFF832B).withOpacity(0.3);
        bg = const Color(0xFFFF832B).withOpacity(0.05);
      case _TileState.inactive:
        iconColor = MobileColors.primary;
        borderColor = MobileColors.border;
        bg = MobileColors.surface;
      case _TileState.unavailable:
        iconColor = MobileColors.textSecondary;
        borderColor = MobileColors.border;
        bg = MobileColors.background;
    }

    return GestureDetector(
      onTap: tile.state == _TileState.unavailable ? null : tile.onTap,
      child: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: borderColor),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Stack(
              alignment: Alignment.topRight,
              children: [
                Padding(
                  padding: const EdgeInsets.only(right: 4, top: 4),
                  child: Icon(tile.icon, color: iconColor, size: 28),
                ),
                if (tile.state == _TileState.active)
                  const Icon(Icons.check_circle, color: Color(0xFF24A148), size: 14),
                if (tile.state == _TileState.caution)
                  const Icon(Icons.warning_amber_rounded, color: Color(0xFFFF832B), size: 14),
              ],
            ),
            const SizedBox(height: 6),
            Text(tile.label,
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: tile.state == _TileState.unavailable
                      ? MobileColors.textSecondary : MobileColors.textPrimary,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                )),
            if (tile.subtitle != null) ...[
              const SizedBox(height: 2),
              Text(tile.subtitle!,
                  textAlign: TextAlign.center,
                  style: TextStyle(color: MobileColors.textSecondary, fontSize: 9)),
            ],
          ],
        ),
      ),
    );
  }

  void _showCredentialInfo() {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
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
            _handle(),
            const SizedBox(height: 16),
            const Text('Verified Credential',
                style: TextStyle(color: MobileColors.textPrimary, fontSize: 17,
                    fontWeight: FontWeight.w700)),
            const SizedBox(height: 12),
            Text(
              'To reach Highly Verified status, you need a verifiable credential '
              'issued by a trusted identity verification provider.\n\n'
              'Contact a compatible identity agent provider to request one. '
              'The credential will appear here automatically once issued.',
              style: TextStyle(color: MobileColors.textSecondary, fontSize: 14, height: 1.5),
            ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: MobileColors.primary,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                ),
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Got it'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _handle() => Center(
        child: Container(
          width: 36, height: 4,
          decoration: BoxDecoration(
            color: MobileColors.border,
            borderRadius: BorderRadius.circular(2),
          ),
        ),
      );

  Widget _mobilePinField(TextEditingController ctrl, String label, String? error) {
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
