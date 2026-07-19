import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/config/agent_config.dart';
import 'desktop_sidebar.dart';

class GuardianshipScreen extends StatefulWidget {
  final String? serverUrl;
  final ValueChanged<DesktopRoute>? onNavigate;

  const GuardianshipScreen({super.key, this.serverUrl, this.onNavigate});

  @override
  State<GuardianshipScreen> createState() => _GuardianshipScreenState();
}

class _GuardianshipScreenState extends State<GuardianshipScreen> {
  late final CoreService _coreService;
  int _dependentCount = 0;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadData();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadData() async {
    try {
      final resp = await _coreService.getGuardianships();
      if (mounted) {
        setState(() {
          _dependentCount = resp.guardianships.where((g) => g.isActive).length;
          _loading = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Guardianship', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 8),
            Text(
              'Manage guardianship relationships for dependents, succession planning, and estate management.',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: AppColors.textSecondary),
            ),
            const SizedBox(height: 32),
            if (_loading)
              const Center(child: CircularProgressIndicator())
            else
              Wrap(
                spacing: 20,
                runSpacing: 20,
                children: [
                  _buildTile(
                    icon: Icons.people_outline,
                    title: 'My Dependents',
                    subtitle: '$_dependentCount active',
                    onTap: () => widget.onNavigate?.call(DesktopRoute.guardianshipDependents),
                  ),
                  _buildTile(
                    icon: Icons.shield_outlined,
                    title: 'My Guardians',
                    subtitle: 'Coming Soon',
                    comingSoon: true,
                    onTap: () => widget.onNavigate?.call(DesktopRoute.guardianshipGuardians),
                  ),
                  _buildTile(
                    icon: Icons.article_outlined,
                    title: 'Digital Will',
                    subtitle: 'Designate who inherits your digital identity',
                    comingSoon: true,
                    onTap: () => widget.onNavigate?.call(DesktopRoute.guardianshipSuccession),
                  ),
                  _buildTile(
                    icon: Icons.account_balance_outlined,
                    title: 'Estate Planning',
                    subtitle: 'Plan the long-term management of your digital estate',
                    comingSoon: true,
                    onTap: () => widget.onNavigate?.call(DesktopRoute.guardianshipEstate),
                  ),
                ],
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildTile({
    required IconData icon,
    required String title,
    required String subtitle,
    bool comingSoon = false,
    VoidCallback? onTap,
  }) {
    final cs = Theme.of(context).colorScheme;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        width: 240,
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: cs.surface,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppColors.border),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: AppColors.primary.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(icon, size: 24, color: AppColors.primary),
                ),
                const Spacer(),
                if (comingSoon)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: AppColors.primary.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Text(
                      'Soon',
                      style: TextStyle(fontSize: 10, color: AppColors.primary, fontWeight: FontWeight.w600),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            Text(title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              subtitle,
              style: TextStyle(fontSize: 13, color: AppColors.textMuted),
            ),
          ],
        ),
      ),
    );
  }
}
