import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/preferences_service.dart';
import '../../services/core_service.dart';

class MobileHostingChoiceScreen extends StatefulWidget {
  final void Function(HostingChoice choice, {String? remoteBrainUrl})
      onHostingChosen;

  const MobileHostingChoiceScreen({super.key, required this.onHostingChosen});

  @override
  State<MobileHostingChoiceScreen> createState() =>
      _MobileHostingChoiceScreenState();
}

class _MobileHostingChoiceScreenState
    extends State<MobileHostingChoiceScreen> {
  HostingChoice? _selected;
  final _urlController = TextEditingController();
  bool _connecting = false;
  String? _connectError;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _connectRemoteBrain() async {
    final url = _urlController.text.trim();
    if (url.isEmpty) {
      setState(() => _connectError = 'Invalid URL.');
      return;
    }
    setState(() {
      _connecting = true;
      _connectError = null;
    });
    try {
      final svc = CoreService(baseUrl: url);
      await svc.getHealth();
      svc.dispose();
      widget.onHostingChosen(
        HostingChoice.keysHereBrainRemote,
        remoteBrainUrl: url,
      );
    } catch (_) {
      setState(() {
        _connecting = false;
        _connectError = 'Invalid URL. Could not reach a server at that address.';
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
                child: Column(
                  children: [
                    const SizedBox(height: 32),
                    const Text(
                      'Your keys will live on this device. Now, where do you want the heavy processing done?',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: MobileColors.textPrimary,
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                        height: 1.3,
                      ),
                    ),
                    const SizedBox(height: 10),
                    const Text(
                      'This app will manage your keys. The heavy processing \u2014 your agent\'s brain \u2014 can run right here, or on a more powerful remote server for better performance.',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: MobileColors.textSecondary,
                        fontSize: 13,
                        height: 1.5,
                      ),
                    ),
                    const SizedBox(height: 28),
                    _buildOptionCard(
                      choice: HostingChoice.keysHereBrainRemote,
                      icon: Icons.cloud_outlined,
                      title: 'On a remote server',
                      subtitle:
                          'This device manages your keys. A server handles the heavy processing.',
                      badge: 'RECOMMENDED',
                      disabledBadge: 'COMING SOON',
                      enabled: false,
                    ),
                    const SizedBox(height: 12),
                    _buildOptionCard(
                      choice: HostingChoice.keysHereBrainHere,
                      icon: Icons.phone_android,
                      title: 'Right here on this phone',
                      subtitle:
                          'Everything runs on this phone. No server needed.',
                      warningBadge: 'LIMITED FEATURES',
                    ),
                    if (_selected == HostingChoice.keysHereBrainRemote) ...[
                      const SizedBox(height: 16),
                      _buildRemoteUrlPanel(),
                    ],
                    if (_selected == HostingChoice.keysHereBrainHere) ...[
                      const SizedBox(height: 24),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: () =>
                              widget.onHostingChosen(_selected!),
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
                    ],
                    const SizedBox(height: 32),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildOptionCard({
    required HostingChoice choice,
    required IconData icon,
    required String title,
    required String subtitle,
    String? badge,
    String? warningBadge,
    String? disabledBadge,
    bool enabled = true,
  }) {
    final selected = _selected == choice;
    final isDisabled = !enabled;
    return GestureDetector(
      onTap: isDisabled
          ? null
          : () => setState(() {
              _selected = choice;
              _connectError = null;
            }),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        width: double.infinity,
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          color: isDisabled
              ? MobileColors.surface.withOpacity(0.5)
              : MobileColors.surface,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isDisabled
                ? MobileColors.border.withOpacity(0.5)
                : selected
                    ? MobileColors.primary
                    : MobileColors.border,
            width: selected && !isDisabled ? 2 : 1,
          ),
          boxShadow: isDisabled
              ? []
              : [
                  BoxShadow(
                    color: MobileColors.cardShadow,
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ],
        ),
        child: Opacity(
          opacity: isDisabled ? 0.5 : 1.0,
          child: Row(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: (selected && !isDisabled ? MobileColors.primary : MobileColors.textMuted)
                    .withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(
                icon,
                color: selected && !isDisabled ? MobileColors.primary : MobileColors.textMuted,
                size: 24,
              ),
            ),
            const SizedBox(width: 14),
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
                            color: selected && !isDisabled
                                ? MobileColors.textPrimary
                                : MobileColors.textSecondary,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                      if (badge != null && !isDisabled)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: MobileColors.primary.withOpacity(0.12),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            badge,
                            style: const TextStyle(
                              color: MobileColors.primary,
                              fontSize: 9,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                      if (disabledBadge != null && isDisabled)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: MobileColors.textMuted.withOpacity(0.12),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            disabledBadge,
                            style: const TextStyle(
                              color: MobileColors.textMuted,
                              fontSize: 9,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                      if (warningBadge != null)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: Colors.amber.withOpacity(0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            warningBadge,
                            style: TextStyle(
                              color: Colors.amber.shade700,
                              fontSize: 9,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 4),
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
            const SizedBox(width: 8),
            Icon(
              selected ? Icons.radio_button_checked : Icons.radio_button_off,
              color: selected ? MobileColors.primary : MobileColors.textMuted,
              size: 22,
            ),
          ],
        ),
        ),
      ),
    );
  }

  Widget _buildRemoteUrlPanel() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: MobileColors.primary.withOpacity(0.3)),
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
            'Remote server URL',
            style: TextStyle(
              color: MobileColors.textSecondary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _urlController,
            style: const TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 14,
            ),
            decoration: InputDecoration(
              hintText: 'https://my-server.example.com',
              hintStyle: const TextStyle(
                color: MobileColors.textMuted,
                fontSize: 13,
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
            keyboardType: TextInputType.url,
          ),
          if (_connectError != null) ...[
            const SizedBox(height: 8),
            Text(
              _connectError!,
              style: const TextStyle(
                color: Colors.red,
                fontSize: 12,
              ),
            ),
          ],
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: _connecting ? null : _connectRemoteBrain,
              style: ElevatedButton.styleFrom(
                backgroundColor: MobileColors.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              child: _connecting
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(
                        color: Colors.white,
                        strokeWidth: 2,
                      ),
                    )
                  : const Text(
                      'Connect',
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
            ),
          ),
        ],
      ),
    );
  }
}
