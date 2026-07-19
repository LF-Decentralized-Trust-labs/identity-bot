import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import 'package:agent_client/services/update_service.dart';
import 'package:agent_client/config/agent_config.dart';

class UpdateSettingsScreen extends StatefulWidget {
  final String? serverUrl;

  const UpdateSettingsScreen({super.key, this.serverUrl});

  @override
  State<UpdateSettingsScreen> createState() => _UpdateSettingsScreenState();
}

class _UpdateSettingsScreenState extends State<UpdateSettingsScreen> {
  late final UpdateService _updateService =
      UpdateService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  UpdateStatus? _status;
  bool _loading = true;
  bool _saving = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _updateService.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final status = await _updateService.getStatus();
      if (mounted) setState(() { _status = status; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _checkNow() async {
    try {
      await _updateService.checkNow();
      await Future.delayed(const Duration(seconds: 1));
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Update check scheduled')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Check failed: $e')),
        );
      }
    }
  }

  Future<void> _toggleAutoApply(bool value) async {
    if (_status == null) return;
    if (!value && !_status!.settings.optOutWarningShown) {
      final proceed = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Disable critical auto-updates?'),
          content: const Text(
            'Critical security patches normally install automatically after '
            'signature and checksum verification. Disabling this leaves you '
            'responsible for applying critical updates manually.',
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Keep enabled')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Disable')),
          ],
        ),
      );
      if (proceed != true) return;
    }
    setState(() => _saving = true);
    try {
      final next = UpdateSettings(
        channel: _status!.settings.channel,
        autoApplyCritical: value,
        optOutWarningShown: !value ? true : _status!.settings.optOutWarningShown,
      );
      await _updateService.updateSettings(next);
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Save failed: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _applyUpdate(AvailableUpdate update) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Apply ${update.component}?'),
        content: Text(
          'Install ${update.available} (currently ${update.installed}). '
          'Updates are verified against the signed manifest before apply.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Apply')),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      final result = await _updateService.apply(
        component: update.component,
        version: update.available,
        userConfirmed: true,
      );
      await _load();
      if (!mounted) return;
      final msg = result.applied
          ? 'Applied ${result.component} ${result.version}'
          : result.message ?? 'Apply did not complete';
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Apply failed: $e')),
        );
      }
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
                    if (!AppLayout.isMobile(context)) ...[
                      Text('Updates', style: Theme.of(context).textTheme.headlineMedium),
                      const SizedBox(height: 4),
                      Text(
                        'Signed release manifest polling, verification, and apply.',
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 14),
                      ),
                      const SizedBox(height: 32),
                    ],
                    if (_error != null) ...[
                      AlertCard(
                        title: 'Could not load update status',
                        message: _error!,
                        icon: Icons.error_outline,
                        color: cs.error,
                      ),
                      const SizedBox(height: 16),
                    ],
                    _buildGenuinenessCard(context),
                    const SizedBox(height: 16),
                    _buildSettingsCard(context),
                    const SizedBox(height: 16),
                    _buildAvailableCard(context),
                  ],
                ),
              ),
            ),
    );
  }

  Widget _buildGenuinenessCard(BuildContext context) {
    final g = _status?.genuineness;
    final color = switch (g?.status) {
      'verified' => Colors.green,
      'mismatch' => Colors.red,
      _ => AppColors.textSecondary,
    };
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.verified_user_outlined, color: color),
                const SizedBox(width: 8),
                Text('Binary genuineness', style: Theme.of(context).textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 8),
            Text('Status: ${g?.status ?? 'unknown'}', style: TextStyle(color: color)),
            if (g?.message != null) ...[
              const SizedBox(height: 4),
              Text(g!.message!, style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSettingsCard(BuildContext context) {
    final settings = _status?.settings;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Preferences', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Auto-apply critical updates'),
              subtitle: const Text(
                'ON by default. Signature and checksum verification are never bypassed.',
              ),
              value: settings?.autoApplyCritical ?? true,
              onChanged: _saving ? null : _toggleAutoApply,
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Text('Channel: ${settings?.channel ?? 'stable'}',
                    style: TextStyle(color: AppColors.textSecondary)),
                const Spacer(),
                OutlinedButton.icon(
                  onPressed: _checkNow,
                  icon: const Icon(Icons.refresh, size: 18),
                  label: const Text('Check now'),
                ),
              ],
            ),
            if (_status?.lastChecked != null) ...[
              const SizedBox(height: 8),
              Text(
                'Last checked: ${_status!.lastChecked}',
                style: TextStyle(color: AppColors.textSecondary, fontSize: 12),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildAvailableCard(BuildContext context) {
    final updates = _status?.available ?? [];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Available updates', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            if (_status == null || !_status!.manifestPresent)
              Text(
                'No verified manifest cached yet. The agent polls anonymously every 6 hours.',
                style: TextStyle(color: AppColors.textSecondary),
              )
            else if (updates.isEmpty)
              Text('All components are up to date.', style: TextStyle(color: AppColors.textSecondary))
            else
              ...updates.map((u) => ListTile(
                    contentPadding: EdgeInsets.zero,
                    title: Text(u.component),
                    subtitle: Text(
                      u.belowMinimum
                          ? '${u.installed} → ${u.available} (requires intermediate step)'
                          : '${u.installed} → ${u.available}${u.critical ? ' · CRITICAL' : ''}',
                    ),
                    trailing: u.belowMinimum
                        ? null
                        : TextButton(
                            onPressed: () => _applyUpdate(u),
                            child: const Text('Apply'),
                          ),
                  )),
          ],
        ),
      ),
    );
  }
}

class AlertCard extends StatelessWidget {
  final String title;
  final String message;
  final IconData icon;
  final Color color;

  const AlertCard({
    super.key,
    required this.title,
    required this.message,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: color),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: Theme.of(context).textTheme.titleSmall),
                  const SizedBox(height: 4),
                  Text(message, style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}