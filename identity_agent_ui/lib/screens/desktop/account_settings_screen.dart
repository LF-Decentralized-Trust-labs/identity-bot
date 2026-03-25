import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/preferences_service.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

class AccountSettingsScreen extends StatefulWidget {
  final AgentMode? mode;
  final EntityType? entityType;
  final String? serverUrl;
  // onResetIdentity kept for backwards-compat; Reset Identity has moved to Developer Tools.
  final VoidCallback? onResetIdentity;

  const AccountSettingsScreen({
    super.key,
    this.mode,
    this.entityType,
    this.serverUrl,
    this.onResetIdentity,
  });

  @override
  State<AccountSettingsScreen> createState() => _AccountSettingsScreenState();
}

class _AccountSettingsScreenState extends State<AccountSettingsScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  IdentityResponse? _identity;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final id = await _coreService.getIdentity();
      setState(() { _identity = id; _loading = false; });
    } catch (_) {
      setState(() { _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 720),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Account', style: Theme.of(context).textTheme.headlineMedium),
                  const SizedBox(height: 4),
                  Text('Identity and agent configuration.', style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
                  const SizedBox(height: 32),
                  _buildInfoCard(context),
                  const SizedBox(height: 24),
                  // Reset Identity has moved to Settings → Developer Tools.
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLight,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: AppColors.border),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.info_outline, color: AppColors.textMuted, size: 16),
                        const SizedBox(width: 10),
                        const Expanded(
                          child: Text(
                            'To reset your identity, go to Settings → Developer Tools.',
                            style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              ),
            ),
    );
  }

  Widget _buildInfoCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.border),
        borderRadius: BorderRadius.circular(12),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Identity Info', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
          const SizedBox(height: 16),
          _row('Agent Mode', widget.mode != null ? PreferencesService.modeDisplayName(widget.mode!) : '—'),
          const Divider(height: 24),
          _row('Identity Type', widget.entityType != null ? PreferencesService.entityTypeDisplayName(widget.entityType!) : '—'),
          const Divider(height: 24),
          _row('AID', _identity?.aid ?? '—'),
          const Divider(height: 24),
          _row('Events', '${_identity?.eventCount ?? 0}'),
          const Divider(height: 24),
          _row('Status', _identity?.initialized == true ? 'Initialized' : 'Not initialized'),
        ],
      ),
    );
  }

  Widget _row(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 140,
          child: Text(label, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: AppColors.textSecondary)),
        ),
        Expanded(
          child: Text(
            value.length > 72 ? '${value.substring(0, 72)}…' : value,
            style: const TextStyle(fontSize: 13, color: AppColors.textPrimary, fontFamily: 'monospace'),
          ),
        ),
      ],
    );
  }

}
