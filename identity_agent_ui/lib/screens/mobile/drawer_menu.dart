import 'dart:convert';
import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/config/agent_config.dart';

/// Callback type for navigating to a named screen.
typedef DrawerNavCallback = void Function(String screenKey);

class DrawerMenu extends StatefulWidget {
  final String? serverUrl;
  final VoidCallback onClose;
  final DrawerNavCallback onNavigate;

  const DrawerMenu({
    super.key,
    this.serverUrl,
    required this.onClose,
    required this.onNavigate,
  });

  @override
  State<DrawerMenu> createState() => _DrawerMenuState();
}

class _DrawerMenuState extends State<DrawerMenu> {
  late final CoreService _coreService;
  String _displayName = 'Identity Agent';
  String _email = '';
  String? _photoBase64;
  String? _expandedSection;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadProfile();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadProfile() async {
    try {
      final profile = await _coreService.getProfile();
      if (mounted) {
        setState(() {
          _displayName = profile.fullName.isNotEmpty ? profile.fullName : 'Identity Agent';
          _email = profile.email;
          _photoBase64 = profile.photo.isNotEmpty ? profile.photo : null;
        });
      }
    } catch (_) {}
  }

  void _toggleSection(String section) {
    setState(() {
      _expandedSection = _expandedSection == section ? null : section;
    });
  }

  void _nav(String key) => widget.onNavigate(key);

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.centerLeft,
      child: Material(
        elevation: 8,
        child: Container(
          width: MediaQuery.of(context).size.width * 0.8,
          height: double.infinity,
          color: MobileColors.drawerBackground,
          child: SafeArea(
            child: Column(
              children: [
                _buildHeader(),
                const Divider(height: 1),
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    children: [
                      // ── Core items ──────────────────────────────────────
                      _MenuItem(icon: Icons.person_outline, label: 'My Profile', onTap: () => _nav('profile')),
                      _MenuItem(icon: Icons.people_outline, label: 'Contacts', onTap: () => _nav('contacts')),
                      _MenuItem(icon: Icons.verified_user_outlined, label: 'Credentials', onTap: () => _nav('credentials')),
                      // Passwords requires a server (Bitwarden self-hosted) — only show on mobile if remote server is connected
                      if (widget.serverUrl != null)
                        _MenuItem(icon: Icons.password_outlined, label: 'Passwords', onTap: () => _nav('passwords'), trailing: _comingSoonBadge()),
                      _MenuItem(icon: Icons.account_balance_wallet_outlined, label: 'Wallet', onTap: () => _nav('wallet'), trailing: _comingSoonBadge()),
                      _MenuItem(icon: Icons.devices_outlined, label: 'My Devices', onTap: () => _nav('myDevices')),
                      const _SectionDivider(),

                      // ── Guardianship ────────────────────────────────────
                      _buildExpandableSection(
                        key: 'guardianship',
                        icon: Icons.family_restroom_outlined,
                        label: 'Guardianship',
                        children: [
                          _SubMenuItem(icon: Icons.people_outline, label: 'My Dependents', onTap: () => _nav('guardianshipDependents')),
                          _SubMenuItem(icon: Icons.shield_outlined, label: 'My Guardians', onTap: () => _nav('guardianshipGuardians'), comingSoon: true),
                          _SubMenuItem(icon: Icons.article_outlined, label: 'Digital Will', onTap: () => _nav('guardianshipSuccession'), comingSoon: true),
                          _SubMenuItem(icon: Icons.account_balance_outlined, label: 'Estate Planning', onTap: () => _nav('guardianshipEstate'), comingSoon: true),
                        ],
                      ),
                      const _SectionDivider(),

                      // ── Hubs ────────────────────────────────────────────
                      _buildExpandableSection(
                        key: 'hubs',
                        icon: Icons.hub_outlined,
                        label: 'Hubs',
                        children: [
                          _SubMenuItem(icon: Icons.chat_bubble_outline, label: 'Communications', onTap: () => _nav('hubsCommunications'), comingSoon: true),
                          _SubMenuItem(icon: Icons.auto_awesome, label: 'AI', onTap: () => _nav('hubsAi'), comingSoon: true),
                          _SubMenuItem(icon: Icons.favorite_border, label: 'Health', onTap: () => _nav('hubsHealth'), comingSoon: true),
                          _SubMenuItem(icon: Icons.bar_chart, label: 'Finance', onTap: () => _nav('hubsFinance'), comingSoon: true),
                          _SubMenuItem(icon: Icons.tag, label: 'Social Media', onTap: () => _nav('hubsSocialMedia'), comingSoon: true),
                          _SubMenuItem(icon: Icons.gavel, label: 'Legal', onTap: () => _nav('hubsLegal'), comingSoon: true),
                          _SubMenuItem(icon: Icons.security, label: 'Security', onTap: () => _nav('hubsSecurity'), comingSoon: true),
                        ],
                      ),
                      const _SectionDivider(),

                      // ── History ─────────────────────────────────────────
                      _MenuItem(icon: Icons.history, label: 'History', onTap: () => _nav('history')),
                      const _SectionDivider(),

                      // ── Settings ────────────────────────────────────────
                      _buildExpandableSection(
                        key: 'settings',
                        icon: Icons.settings_outlined,
                        label: 'Settings',
                        children: [
                          _SubMenuItem(icon: Icons.manage_accounts_outlined, label: 'Identity Agent', onTap: () => _nav('settingsAccount')),
                          _SubMenuItem(icon: Icons.fingerprint, label: 'Authentication', onTap: () => _nav('settingsAuthentication')),
                          _SubMenuItem(icon: Icons.privacy_tip_outlined, label: 'Privacy & Data', onTap: () => _nav('settingsPrivacy'), comingSoon: true),
                          _SubMenuItem(icon: Icons.palette_outlined, label: 'Appearance', onTap: () => _nav('settingsTheme')),
                          _SubMenuItem(icon: Icons.notifications_outlined, label: 'Notifications', onTap: () => _nav('settingsNotifications'), comingSoon: true),
                          _SubMenuItem(icon: Icons.vpn_lock_outlined, label: 'Tunneling', onTap: () => _nav('settingsTunneling')),
                          _SubMenuItem(icon: Icons.hub_outlined, label: 'Endpoints', onTap: () => _nav('settingsEndpoints')),
                          _SubMenuItem(icon: Icons.cloud_outlined, label: 'Service Providers', onTap: () => _nav('settingsServiceProviders')),
                          _SubMenuItem(icon: Icons.gavel, label: 'Governance', onTap: () => _nav('settingsGovernance'), comingSoon: true),
                          _SubMenuItem(icon: Icons.key, label: 'KERI Protocol', onTap: () => _nav('settingsKeri')),
                          _SubMenuItem(icon: Icons.backup_outlined, label: 'Backup & Recovery', onTap: () => _nav('settingsBackup'), comingSoon: true),
                          _SubMenuItem(icon: Icons.terminal, label: 'Developer Tools', onTap: () => _nav('settingsDeveloperTools')),
                        ],
                      ),

                      const SizedBox(height: 16),
                    ],
                  ),
                ),
                const Divider(height: 1),
                const Padding(
                  padding: EdgeInsets.all(16),
                  child: Text(
                    'Identity Agent',
                    style: TextStyle(
                      fontSize: 11,
                      color: MobileColors.textMuted,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildExpandableSection({
    required String key,
    required IconData icon,
    required String label,
    required List<Widget> children,
  }) {
    final expanded = _expandedSection == key;
    return Column(
      children: [
        ListTile(
          leading: Icon(icon, color: MobileColors.textSecondary, size: 22),
          title: Text(
            label,
            style: const TextStyle(
              fontSize: 15,
              fontWeight: FontWeight.w500,
              color: MobileColors.textPrimary,
            ),
          ),
          trailing: AnimatedRotation(
            turns: expanded ? 0.5 : 0.0,
            duration: const Duration(milliseconds: 200),
            child: const Icon(Icons.expand_more, color: MobileColors.textMuted, size: 22),
          ),
          onTap: () => _toggleSection(key),
          contentPadding: const EdgeInsets.symmetric(horizontal: 20),
        ),
        AnimatedCrossFade(
          firstChild: const SizedBox(width: double.infinity, height: 0),
          secondChild: Column(children: children),
          crossFadeState: expanded ? CrossFadeState.showSecond : CrossFadeState.showFirst,
          duration: const Duration(milliseconds: 200),
        ),
      ],
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.all(20),
      child: Row(
        children: [
          _buildAvatar(),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _displayName,
                  style: const TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    color: MobileColors.textPrimary,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                if (_email.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(
                    _maskEmail(_email),
                    style: const TextStyle(
                      fontSize: 13,
                      color: MobileColors.textMuted,
                    ),
                  ),
                ],
              ],
            ),
          ),
          IconButton(
            onPressed: widget.onClose,
            icon: const Icon(Icons.close, color: MobileColors.textSecondary),
          ),
        ],
      ),
    );
  }

  Widget _buildAvatar() {
    if (_photoBase64 != null && _photoBase64!.isNotEmpty) {
      try {
        final bytes = base64Decode(_photoBase64!);
        return CircleAvatar(
          radius: 24,
          backgroundImage: MemoryImage(bytes),
        );
      } catch (_) {}
    }

    final initials = _displayName.split(' ').take(2).map((w) => w.isNotEmpty ? w[0].toUpperCase() : '').join();
    return CircleAvatar(
      radius: 24,
      backgroundColor: MobileColors.primary,
      child: Text(
        initials.isNotEmpty ? initials : 'IA',
        style: const TextStyle(
          color: MobileColors.textOnPrimary,
          fontWeight: FontWeight.w600,
          fontSize: 14,
        ),
      ),
    );
  }

  String _maskEmail(String email) {
    final parts = email.split('@');
    if (parts.length != 2) return email;
    final local = parts[0];
    if (local.length <= 2) return email;
    return '${local[0]}${'*' * (local.length - 2)}${local[local.length - 1]}@${parts[1]}';
  }

  Widget _comingSoonBadge() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: MobileColors.surfaceTertiary,
        borderRadius: BorderRadius.circular(4),
      ),
      child: const Text(
        'Soon',
        style: TextStyle(
          fontSize: 10,
          color: MobileColors.textMuted,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

// ── Reusable menu widgets ─────────────────────────────────────────────────────

class _SectionDivider extends StatelessWidget {
  const _SectionDivider();
  @override
  Widget build(BuildContext context) => const Divider(indent: 16, endIndent: 16);
}

class _MenuItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final Widget? trailing;

  const _MenuItem({
    required this.icon,
    required this.label,
    required this.onTap,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Icon(icon, color: MobileColors.textSecondary, size: 22),
      title: Text(
        label,
        style: const TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w500,
          color: MobileColors.textPrimary,
        ),
      ),
      trailing: trailing,
      onTap: onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: 20),
    );
  }
}

class _SubMenuItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final bool comingSoon;

  const _SubMenuItem({
    required this.icon,
    required this.label,
    required this.onTap,
    this.comingSoon = false,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Padding(
        padding: const EdgeInsets.only(left: 12),
        child: Icon(icon, color: MobileColors.textMuted, size: 20),
      ),
      title: Text(
        label,
        style: TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.w400,
          color: comingSoon ? MobileColors.textMuted : MobileColors.textSecondary,
        ),
      ),
      trailing: comingSoon
          ? Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: MobileColors.surfaceTertiary,
                borderRadius: BorderRadius.circular(4),
              ),
              child: const Text(
                'Soon',
                style: TextStyle(fontSize: 9, color: MobileColors.textMuted, fontWeight: FontWeight.w600),
              ),
            )
          : null,
      onTap: onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: 20),
      dense: true,
      visualDensity: VisualDensity.compact,
    );
  }
}
