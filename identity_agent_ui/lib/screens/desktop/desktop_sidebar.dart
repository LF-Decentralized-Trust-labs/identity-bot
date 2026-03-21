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
  apps,
  wallet,
  assets,
  dataVault,
  myDevices,

  // Hubs
  hubsCommunications,
  hubsAi,
  hubsHealthcare,
  hubsFinancial,

  // Settings
  settingsTunneling,
  settingsAuthentication,
  settingsKeri,
  settingsKeyManagement,
  settingsApiKeys,
  settingsEndpoints,
  settingsServiceProviders,
  settingsConnectedApps,
  settingsGovernance,
  settingsPrivacy,
  settingsNotifications,
  settingsBackup,
  settingsDeveloperTools,
  settingsTheme,
  settingsAccount,

  // Top-level
  activityLog,

  // Organization
  orgOverview,
  orgEmployees,
  orgCredentials,
  orgSettings,
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
  // Section expand state
  bool _identityOpen  = true;
  bool _hubsOpen      = false;
  bool _settingsOpen  = false;
  bool _orgOpen       = false;

  // Profile
  String _displayName  = '';
  String? _photoBase64;

  late final CoreService _coreService;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadProfile();
    // Auto-expand the section containing the current route
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
    if (_isIdentityRoute(r)) setState(() => _identityOpen  = true);
    if (_isHubRoute(r))      setState(() => _hubsOpen      = true);
    if (_isSettingsRoute(r)) setState(() => _settingsOpen  = true);
    if (_isOrgRoute(r))      setState(() => _orgOpen       = true);
  }

  bool _isIdentityRoute(DesktopRoute r)  => r.name.startsWith('identity');
  bool _isHubRoute(DesktopRoute r)       => r.name.startsWith('hubs');
  bool _isSettingsRoute(DesktopRoute r)  => r.name.startsWith('settings');
  bool _isOrgRoute(DesktopRoute r)       => r.name.startsWith('org');

  Future<void> _loadProfile() async {
    try {
      final profile = await _coreService.getProfile();
      if (mounted) {
        setState(() {
          _displayName  = profile.fullName.isNotEmpty ? profile.fullName : 'Identity Agent';
          _photoBase64  = profile.photo.isNotEmpty ? profile.photo : null;
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

                // ── Identity ───────────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.fingerprint,
                  label: 'Identity',
                  expanded: _identityOpen,
                  onToggle: () => setState(() => _identityOpen = !_identityOpen),
                ),
                if (_identityOpen) ...[
                  _SubItem(icon: Icons.person_outline, label: 'My Profile', route: DesktopRoute.identityProfile, current: widget.currentRoute, onTap: _select),
                ],
                _sectionDivider(),

                // ── Top-level items ────────────────────────────────────────
                _NavItem(icon: Icons.people_outline,                   label: 'Contacts',   route: DesktopRoute.contacts,   current: widget.currentRoute, onTap: _select),
                _NavItem(icon: Icons.verified_user_outlined,           label: 'Credentials',route: DesktopRoute.credentials, current: widget.currentRoute, onTap: _select, comingSoon: true),
                _NavItem(icon: Icons.apps,                             label: 'Apps',       route: DesktopRoute.apps,        current: widget.currentRoute, onTap: _select),
                _NavItem(icon: Icons.account_balance_wallet_outlined,  label: 'Wallet',     route: DesktopRoute.wallet,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                _NavItem(icon: Icons.diamond_outlined,                 label: 'Assets',     route: DesktopRoute.assets,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                _NavItem(icon: Icons.storage_outlined,                 label: 'Data Vault', route: DesktopRoute.dataVault,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                _NavItem(icon: Icons.devices,                          label: 'My Devices', route: DesktopRoute.myDevices,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                _sectionDivider(),

                // ── Hubs ───────────────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.hub_outlined,
                  label: 'Hubs',
                  expanded: _hubsOpen,
                  onToggle: () => setState(() => _hubsOpen = !_hubsOpen),
                  comingSoon: true,
                ),
                if (_hubsOpen) ...[
                  _SubItem(icon: Icons.chat_bubble_outline, label: 'Communications', route: DesktopRoute.hubsCommunications, current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.auto_awesome,        label: 'AI Hub',         route: DesktopRoute.hubsAi,            current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.local_hospital_outlined, label: 'Healthcare', route: DesktopRoute.hubsHealthcare,    current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.bar_chart,           label: 'Financial',      route: DesktopRoute.hubsFinancial,     current: widget.currentRoute, onTap: _select, comingSoon: true),
                ],
                _sectionDivider(),

                // ── Settings ───────────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.settings_outlined,
                  label: 'Settings',
                  expanded: _settingsOpen,
                  onToggle: () => setState(() => _settingsOpen = !_settingsOpen),
                ),
                if (_settingsOpen) ...[
                  _SubItem(icon: Icons.vpn_lock_outlined,         label: 'Tunneling',                route: DesktopRoute.settingsTunneling,        current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.lock_outlined,             label: 'Authentication',            route: DesktopRoute.settingsAuthentication,  current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.key,                       label: 'KERI Protocol',            route: DesktopRoute.settingsKeri,            current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.lock_outlined,             label: 'Key Management',           route: DesktopRoute.settingsKeyManagement,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.api_outlined,              label: 'API Keys',                 route: DesktopRoute.settingsApiKeys,         current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.hub_outlined,              label: 'Endpoints',                route: DesktopRoute.settingsEndpoints,       current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.cloud_outlined,            label: 'Service Providers',        route: DesktopRoute.settingsServiceProviders, current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.link,                      label: 'Connected Apps',           route: DesktopRoute.settingsConnectedApps,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.gavel,                     label: 'Governance Gateway',       route: DesktopRoute.settingsGovernance,      current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.privacy_tip_outlined,      label: 'Privacy & Data',           route: DesktopRoute.settingsPrivacy,         current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.notifications_outlined,    label: 'Notifications',            route: DesktopRoute.settingsNotifications,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.backup_outlined,           label: 'Backup & Recovery',        route: DesktopRoute.settingsBackup,          current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.terminal,                  label: 'Developer Tools',          route: DesktopRoute.settingsDeveloperTools,  current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.palette_outlined,          label: 'Theme',                    route: DesktopRoute.settingsTheme,           current: widget.currentRoute, onTap: _select),
                  _SubItem(icon: Icons.manage_accounts_outlined,  label: 'Account',                  route: DesktopRoute.settingsAccount,         current: widget.currentRoute, onTap: _select),
                ],
                _sectionDivider(),

                // ── Activity Log ───────────────────────────────────────────
                _NavItem(icon: Icons.receipt_long_outlined, label: 'Activity Log', route: DesktopRoute.activityLog, current: widget.currentRoute, onTap: _select, comingSoon: true),
                _sectionDivider(),

                // ── Organization ───────────────────────────────────────────
                _SectionHeader(
                  icon: Icons.business,
                  label: 'Organization',
                  expanded: _orgOpen,
                  onToggle: () => setState(() => _orgOpen = !_orgOpen),
                  comingSoon: true,
                ),
                if (_orgOpen) ...[
                  _SubItem(icon: Icons.space_dashboard_outlined, label: 'Overview',          route: DesktopRoute.orgOverview,   current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.group_outlined,           label: 'Employees & Roles', route: DesktopRoute.orgEmployees,  current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.verified_user_outlined,   label: 'Credentials',       route: DesktopRoute.orgCredentials,current: widget.currentRoute, onTap: _select, comingSoon: true),
                  _SubItem(icon: Icons.settings_outlined,        label: 'Settings',          route: DesktopRoute.orgSettings,   current: widget.currentRoute, onTap: _select, comingSoon: true),
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
                  fontSize: indent > 0 ? 13 : 13,
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
