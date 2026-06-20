import 'dart:convert';
import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

// ── Route enum ───────────────────────────────────────────────────────────────
enum DesktopRoute {
  dashboard,

  // Identity
  identityProfile,

  // Top-level
  contacts,
  credentials,
  passwords,
  wallet,
  dataVault,
  myDevices,
  apps,

  // My Data
  dataVaultOverview,
  dataVaultIdentity,
  dataVaultCommunications,
  dataVaultHealth,
  dataVaultFitness,
  dataVaultFinance,
  dataVaultMedia,
  dataVaultSocial,
  dataVaultVehicles,
  dataVaultHousing,

  // Guardianship
  guardianship,
  guardianshipDependents,
  guardianshipGuardians,
  guardianshipSuccession,
  guardianshipEstate,

  // Hubs
  hubsCommunications,
  hubsAi,
  hubsHealth,
  hubsFinance,
  hubsSocialMedia,
  hubsLegal,
  hubsSecurity,

  // Settings
  settingsTunneling,
  settingsAuthentication,
  settingsKeri,
  settingsEndpoints,
  settingsServiceProviders,
  settingsApiKeys,
  settingsGovernance,
  settingsPrivacy,
  settingsNotifications,
  settingsBackup,
  settingsUpdates,
  settingsDeveloperTools,
  settingsTheme,
  settingsAccount,

  // History
  activityLog,

}

// ── Sidebar widget ────────────────────────────────────────────────────────────
class DesktopSidebar extends StatefulWidget {
  final DesktopRoute currentRoute;
  final ValueChanged<DesktopRoute> onRouteSelected;
  final String? serverUrl;

  const DesktopSidebar({
    super.key,
    required this.currentRoute,
    required this.onRouteSelected,
    this.serverUrl,
  });

  @override
  State<DesktopSidebar> createState() => _DesktopSidebarState();
}

class _DesktopSidebarState extends State<DesktopSidebar> {
  // Section expand state — only one section open at a time
  String? _openSection; // 'myData' | 'guardianship' | 'hubs' | 'settings' | null

  // Profile
  String _displayName = '';
  String? _photoBase64;

  late final CoreService _coreService;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadProfile();
    _expandForRoute(widget.currentRoute);
  }

  @override
  void didUpdateWidget(DesktopSidebar old) {
    super.didUpdateWidget(old);
    if (old.currentRoute != widget.currentRoute) {
      _expandForRoute(widget.currentRoute);
    }
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  void _expandForRoute(DesktopRoute r) {
    if (_isDataVaultRoute(r))          setState(() => _openSection = 'myData');
    else if (_isGuardianshipRoute(r)) setState(() => _openSection = 'guardianship');
    else if (_isHubRoute(r))          setState(() => _openSection = 'hubs');
    else if (_isSettingsRoute(r))     setState(() => _openSection = 'settings');
  }

  void _toggleSection(String section) {
    setState(() => _openSection = _openSection == section ? null : section);
  }

  bool _isDataVaultRoute(DesktopRoute r)    => r.name.startsWith('dataVault');
  bool _isGuardianshipRoute(DesktopRoute r) => r.name.startsWith('guardianship');
  bool _isHubRoute(DesktopRoute r)          => r.name.startsWith('hubs');
  bool _isSettingsRoute(DesktopRoute r)     => r.name.startsWith('settings');

  Future<void> _loadProfile() async {
    try {
      final profile = await _coreService.getProfile();
      if (mounted) {
        setState(() {
          _displayName = profile.fullName.isNotEmpty ? profile.fullName : 'Identity Agent';
          _photoBase64 = profile.photo.isNotEmpty ? profile.photo : null;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _displayName = 'Identity Agent');
    }
  }

  void _select(DesktopRoute r) => widget.onRouteSelected(r);

  @override
  Widget build(BuildContext context) {
    final cs     = Theme.of(context).colorScheme;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final sidebarBg = isDark ? cs.surface : Colors.white;

    return Container(
      width: 220,
      color: sidebarBg,
      child: Column(
        children: [
          _buildProfileHeader(context),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(vertical: 8),
              children: [
                // ── Dashboard ──────────────────────────────────────────────
                _NavItem(
                  icon: Icons.dashboard_outlined,
                  label: 'Dashboard',
                  route: DesktopRoute.dashboard,
                  current: widget.currentRoute,
                  onTap: _select,
                ),
                _sectionDivider(),

                // ── My Profile ─────────────────────────────────────────────
                _NavItem(icon: Icons.person_outline, label: 'My Profile', route: DesktopRoute.identityProfile, current: widget.currentRoute, onTap: _select),
                _sectionDivider(),

                // ── Core items ─────────────────────────────────────────────
                _NavItem(icon: Icons.people_outline,                  label: 'Contacts',    route: DesktopRoute.contacts,    current: widget.currentRoute, onTap: _select),
                _NavItem(icon: Icons.verified_user_outlined,          label: 'Credentials', route: DesktopRoute.credentials, current: widget.currentRoute, onTap: _select),
                _NavItem(icon: Icons.password_outlined,               label: 'Passwords',   route: DesktopRoute.passwords,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                _NavItem(icon: Icons.account_balance_wallet_outlined, label: 'Wallet',      route: DesktopRoute.wallet,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                _NavItem(icon: Icons.devices,                         label: 'My Devices',  route: DesktopRoute.myDevices,   current: widget.currentRoute, onTap: _select),
                _NavItem(icon: Icons.apps,                            label: 'Apps',        route: DesktopRoute.apps,        current: widget.currentRoute, onTap: _select),
                _sectionDivider(),

                // ── My Data ──────────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.storage_outlined,
                  label: 'My Data',
                  expanded: _openSection == 'myData',
                  onToggle: () => _toggleSection('myData'),
                ),
                if (_openSection == 'myData') ...[
                  _SubItem(icon: Icons.dashboard_outlined,     label: 'Overview',         route: DesktopRoute.dataVaultOverview,        current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.person_outline,         label: 'Identity & Profile', route: DesktopRoute.dataVaultIdentity,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.chat_bubble_outline,    label: 'Communications',   route: DesktopRoute.dataVaultCommunications,  current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.favorite_border,        label: 'Health',           route: DesktopRoute.dataVaultHealth,          current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.fitness_center_outlined, label: 'Fitness',          route: DesktopRoute.dataVaultFitness,         current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.account_balance_wallet_outlined, label: 'Finance',  route: DesktopRoute.dataVaultFinance,         current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.photo_library_outlined, label: 'Media',            route: DesktopRoute.dataVaultMedia,           current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.tag,                    label: 'Social',           route: DesktopRoute.dataVaultSocial,          current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.directions_car_outlined, label: 'Vehicles',        route: DesktopRoute.dataVaultVehicles,        current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.home_outlined,          label: 'Housing',          route: DesktopRoute.dataVaultHousing,         current: widget.currentRoute, onTap: _select, comingSoon: true),
                ],
                _sectionDivider(),

                // ── Guardianship ─────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.family_restroom_outlined,
                  label: 'Guardianship',
                  expanded: _openSection == 'guardianship',
                  onToggle: () => _toggleSection('guardianship'),
                ),
                if (_openSection == 'guardianship') ...[
                  _SubItem(icon: Icons.people_outline,                label: 'My Dependents',  route: DesktopRoute.guardianshipDependents, current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.shield_outlined,               label: 'My Guardians',   route: DesktopRoute.guardianshipGuardians,  current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.article_outlined,              label: 'Digital Will',     route: DesktopRoute.guardianshipSuccession, current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.account_balance_outlined,      label: 'Estate Planning', route: DesktopRoute.guardianshipEstate,     current: widget.currentRoute, onTap: _select, comingSoon: true),
                ],
                _sectionDivider(),

                // ── Hubs ───────────────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.hub_outlined,
                  label: 'Hubs',
                  expanded: _openSection == 'hubs',
                  onToggle: () => _toggleSection('hubs'),
                ),
                if (_openSection == 'hubs') ...[
                  _SubItem(icon: Icons.chat_bubble_outline, label: 'Communications', route: DesktopRoute.hubsCommunications, current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.auto_awesome,        label: 'AI',             route: DesktopRoute.hubsAi,            current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.favorite_border,     label: 'Health',         route: DesktopRoute.hubsHealth,        current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.bar_chart,           label: 'Finance',        route: DesktopRoute.hubsFinance,       current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.tag,                 label: 'Social Media',   route: DesktopRoute.hubsSocialMedia,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.gavel,               label: 'Legal',          route: DesktopRoute.hubsLegal,         current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.security,            label: 'Security',       route: DesktopRoute.hubsSecurity,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                ],
                _sectionDivider(),

                // ── History ────────────────────────────────────────────────
                _NavItem(icon: Icons.history, label: 'History', route: DesktopRoute.activityLog, current: widget.currentRoute, onTap: _select),
                _sectionDivider(),

                // ── Settings ───────────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.settings_outlined,
                  label: 'Settings',
                  expanded: _openSection == 'settings',
                  onToggle: () => _toggleSection('settings'),
                ),
                if (_openSection == 'settings') ...[
                  _SubItem(icon: Icons.manage_accounts_outlined, label: 'Identity Agent',    route: DesktopRoute.settingsAccount,         current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.fingerprint,              label: 'Authentication',    route: DesktopRoute.settingsAuthentication,  current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.privacy_tip_outlined,     label: 'Privacy & Data',    route: DesktopRoute.settingsPrivacy,         current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.palette_outlined,         label: 'Appearance',        route: DesktopRoute.settingsTheme,           current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.notifications_outlined,   label: 'Notifications',     route: DesktopRoute.settingsNotifications,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.api_outlined,             label: 'API Keys',          route: DesktopRoute.settingsApiKeys,         current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.vpn_lock_outlined,        label: 'Tunneling',         route: DesktopRoute.settingsTunneling,       current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.hub_outlined,             label: 'Endpoints',         route: DesktopRoute.settingsEndpoints,       current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.cloud_outlined,           label: 'Service Providers', route: DesktopRoute.settingsServiceProviders, current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.gavel,                    label: 'Governance',        route: DesktopRoute.settingsGovernance,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.key,                      label: 'KERI Protocol',     route: DesktopRoute.settingsKeri,            current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.system_update_alt,        label: 'Updates',           route: DesktopRoute.settingsUpdates,         current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.backup_outlined,          label: 'Backup & Recovery', route: DesktopRoute.settingsBackup,          current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.terminal,                 label: 'Developer Tools',   route: DesktopRoute.settingsDeveloperTools,  current: widget.currentRoute, onTap: _select),
                ],

                const SizedBox(height: 16),
              ],
            ),
          ),

          // ── Footer ────────────────────────────────────────────────────────
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            decoration: BoxDecoration(
              border: Border(top: BorderSide(color: AppColors.border)),
            ),
            child: Row(
              children: [
                Icon(Icons.circle, size: 8, color: AppColors.success),
                const SizedBox(width: 6),
                Text(
                  'Identity Agent · Desktop',
                  style: TextStyle(fontSize: 11, color: AppColors.textMuted),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildProfileHeader(BuildContext context) {
    Widget avatar;
    if (_photoBase64 != null && _photoBase64!.isNotEmpty) {
      try {
        final bytes = base64Decode(_photoBase64!);
        avatar = CircleAvatar(radius: 18, backgroundImage: MemoryImage(bytes));
      } catch (_) {
        avatar = _initialsAvatar();
      }
    } else {
      avatar = _initialsAvatar();
    }

    return Container(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 16),
      child: Row(
        children: [
          avatar,
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              _displayName,
              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textPrimary),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _initialsAvatar() {
    final initials = _displayName
        .split(' ')
        .take(2)
        .map((w) => w.isNotEmpty ? w[0].toUpperCase() : '')
        .join();
    return CircleAvatar(
      radius: 18,
      backgroundColor: AppColors.primary,
      child: Text(
        initials.isNotEmpty ? initials : 'IA',
        style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }

  Widget _sectionDivider() => Divider(height: 1, indent: 16, endIndent: 16, color: AppColors.border.withOpacity(0.7));
}

// ── Section header (collapsible) ─────────────────────────────────────────────
class _SectionHeader extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool expanded;
  final VoidCallback onToggle;
  final bool comingSoon;

  const _SectionHeader({
    required this.icon,
    required this.label,
    required this.expanded,
    required this.onToggle,
    this.comingSoon = false,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onToggle,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        child: Row(
          children: [
            Icon(icon, size: 18, color: AppColors.textSecondary),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                label,
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textPrimary),
              ),
            ),
            if (comingSoon) _SoonBadge(),
            Icon(
              expanded ? Icons.keyboard_arrow_down : Icons.keyboard_arrow_right,
              size: 16,
              color: AppColors.textMuted,
            ),
          ],
        ),
      ),
    );
  }
}

// ── Top-level nav item ────────────────────────────────────────────────────────
class _NavItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final DesktopRoute route;
  final DesktopRoute current;
  final ValueChanged<DesktopRoute> onTap;
  final bool comingSoon;

  const _NavItem({
    required this.icon,
    required this.label,
    required this.route,
    required this.current,
    required this.onTap,
    this.comingSoon = false,
  });

  @override
  Widget build(BuildContext context) {
    final isActive = current == route;
    return _SidebarTile(
      icon: icon,
      label: label,
      isActive: isActive,
      comingSoon: comingSoon,
      indent: 0,
      onTap: () => onTap(route),
    );
  }
}

// ── Sub-item (indented) ───────────────────────────────────────────────────────
class _SubItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final DesktopRoute route;
  final DesktopRoute current;
  final ValueChanged<DesktopRoute> onTap;
  final bool comingSoon;

  const _SubItem({
    required this.icon,
    required this.label,
    required this.route,
    required this.current,
    required this.onTap,
    this.comingSoon = false,
  });

  @override
  Widget build(BuildContext context) {
    final isActive = current == route;
    return _SidebarTile(
      icon: icon,
      label: label,
      isActive: isActive,
      comingSoon: comingSoon,
      indent: 16,
      onTap: () => onTap(route),
    );
  }
}

// ── Shared tile renderer ──────────────────────────────────────────────────────
class _SidebarTile extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool isActive;
  final bool comingSoon;
  final double indent;
  final VoidCallback onTap;

  const _SidebarTile({
    required this.icon,
    required this.label,
    required this.isActive,
    required this.comingSoon,
    required this.indent,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final textColor = isActive
        ? AppColors.primary
        : comingSoon
            ? AppColors.textMuted
            : AppColors.textPrimary;
    final iconColor = isActive
        ? AppColors.primary
        : comingSoon
            ? AppColors.textMuted
            : AppColors.textSecondary;
    final bgColor = isActive ? AppColors.primary.withOpacity(0.08) : Colors.transparent;

    return InkWell(
      onTap: comingSoon ? null : onTap,
      child: Container(
        decoration: BoxDecoration(
          color: bgColor,
          border: Border(
            left: BorderSide(
              color: isActive ? AppColors.primary : Colors.transparent,
              width: 3,
            ),
          ),
        ),
        padding: EdgeInsets.only(left: 16 + indent - (isActive ? 3 : 0), right: 12, top: 9, bottom: 9),
        child: Row(
          children: [
            Icon(icon, size: indent > 0 ? 16 : 18, color: iconColor),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                label,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: isActive ? FontWeight.w600 : FontWeight.w400,
                  color: textColor,
                ),
              ),
            ),
            if (comingSoon) _SoonBadge(),
          ],
        ),
      ),
    );
  }
}

// ── "Soon" badge ──────────────────────────────────────────────────────────────
class _SoonBadge extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: AppColors.surfaceVariant,
        borderRadius: BorderRadius.circular(4),
      ),
      child: const Text(
        'Soon',
        style: TextStyle(fontSize: 9, fontWeight: FontWeight.w600, color: AppColors.textMuted),
      ),
    );
  }
}
