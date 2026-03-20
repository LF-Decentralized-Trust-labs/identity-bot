import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
import '../services/preferences_service.dart';
import '../services/core_service.dart';

class HostingChoiceScreen extends StatefulWidget {
  final void Function(HostingChoice choice, {String? remoteBrainUrl})
      onHostingChosen;

  const HostingChoiceScreen({super.key, required this.onHostingChosen});

  @override
  State<HostingChoiceScreen> createState() => _HostingChoiceScreenState();
}

class _HostingChoiceScreenState extends State<HostingChoiceScreen> {
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
      setState(() => _connectError = 'Enter a server URL.');
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
        _connectError =
            'Could not reach that server. Check the URL and try again.';
      });
    }
  }

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
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const SizedBox(height: 32),
                  const Text(
                    'WHERE DO YOU WANT YOUR KEYS AND BRAIN?',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 18,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Your keys (Identity) are your secret seed — whoever holds them is you.\n'
                    'Your brain (Agent) is the software that runs your identity.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 12,
                      height: 1.6,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 32),
                  _buildOptionCard(
                    choice: HostingChoice.keysHereBrainHere,
                    icon: Icons.computer,
                    title: 'Keys here · Brain here',
                    subtitle:
                        'Both on this computer. Fully self-contained. Full features.',
                  ),
                  const SizedBox(height: 12),
                  _buildOptionCard(
                    choice: HostingChoice.keysHereBrainRemote,
                    icon: Icons.cloud_outlined,
                    title: 'Keys here · Brain on a remote server',
                    subtitle:
                        'Your keys stay on this computer. A cloud server or VPS runs the agent.',
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
                        onPressed: () => widget.onHostingChosen(
                          HostingChoice.keysHereBrainHere,
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.accent,
                          foregroundColor: AppColors.primary,
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                        ),
                        child: const Text(
                          'CONTINUE',
                          style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1.5,
                            fontFamily: 'monospace',
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
    );
  }

  Widget _buildOptionCard({
    required HostingChoice choice,
    required IconData icon,
    required String title,
    required String subtitle,
  }) {
    final selected = _selected == choice;
    return GestureDetector(
      onTap: () => setState(() {
        _selected = choice;
        _connectError = null;
      }),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        width: double.infinity,
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: selected
                ? AppColors.accent
                : AppColors.border,
            width: selected ? 2 : 1,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: (selected ? AppColors.accent : AppColors.textMuted)
                    .withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(
                icon,
                color: selected ? AppColors.accent : AppColors.textMuted,
                size: 24,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: TextStyle(
                      color: selected
                          ? AppColors.textPrimary
                          : AppColors.textSecondary,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    subtitle,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 11,
                      height: 1.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            Icon(
              selected ? Icons.radio_button_checked : Icons.radio_button_off,
              color: selected ? AppColors.accent : AppColors.textMuted,
              size: 22,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRemoteUrlPanel() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.accent.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'REMOTE SERVER URL',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _urlController,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontFamily: 'monospace',
            ),
            decoration: InputDecoration(
              hintText: 'https://my-server.example.com',
              hintStyle: TextStyle(
                color: AppColors.textMuted.withOpacity(0.5),
                fontFamily: 'monospace',
                fontSize: 12,
              ),
              filled: true,
              fillColor: AppColors.primary,
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
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            ),
            autocorrect: false,
            keyboardType: TextInputType.url,
          ),
          if (_connectError != null) ...[
            const SizedBox(height: 8),
            Text(
              _connectError!,
              style: const TextStyle(
                color: AppColors.coreInactive,
                fontSize: 11,
                fontFamily: 'monospace',
              ),
            ),
          ],
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: _connecting ? null : _connectRemoteBrain,
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: AppColors.primary,
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
                        color: AppColors.primary,
                        strokeWidth: 2,
                      ),
                    )
                  : const Text(
                      'CONNECT',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.5,
                        fontFamily: 'monospace',
                      ),
                    ),
            ),
          ),
          const SizedBox(height: 8),
          SizedBox(
            width: double.infinity,
            child: TextButton(
              onPressed: () => widget.onHostingChosen(
                HostingChoice.keysHereBrainLater,
              ),
              child: const Text(
                'Connect later — start standalone for now',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
