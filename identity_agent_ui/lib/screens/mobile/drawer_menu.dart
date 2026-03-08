import 'dart:convert';
import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

class DrawerMenu extends StatefulWidget {
  final String? serverUrl;
  final VoidCallback onClose;
  final VoidCallback onProfileTap;
  final VoidCallback onContactsTap;
  final VoidCallback onSettingsTap;

  const DrawerMenu({
    super.key,
    this.serverUrl,
    required this.onClose,
    required this.onProfileTap,
    required this.onContactsTap,
    required this.onSettingsTap,
  });

  @override
  State<DrawerMenu> createState() => _DrawerMenuState();
}

class _DrawerMenuState extends State<DrawerMenu> {
  late final CoreService _coreService;
  String _displayName = 'Identity Agent';
  String _email = '';
  String? _photoBase64;
  bool _settingsExpanded = false;

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

  void _showComingSoon(String feature) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Coming Soon'),
        content: Text('$feature will be available in a future update.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

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
                      _MenuItem(
                        icon: Icons.person_outline,
                        label: 'My Profile',
                        onTap: widget.onProfileTap,
                      ),
                      _MenuItem(
                        icon: Icons.people_outline,
                        label: 'Contacts',
                        onTap: widget.onContactsTap,
                      ),
                      _buildSettingsSection(),
                      const Divider(indent: 16, endIndent: 16),
                      _MenuItem(
                        icon: Icons.account_balance_wallet_outlined,
                        label: 'Wallet',
                        onTap: () => _showComingSoon('Wallet'),
                        trailing: _comingSoonBadge(),
                      ),
                      _MenuItem(
                        icon: Icons.storage_outlined,
                        label: 'Data Vault',
                        onTap: () => _showComingSoon('Data Vault'),
                        trailing: _comingSoonBadge(),
                      ),
                      _MenuItem(
                        icon: Icons.devices_outlined,
                        label: 'My Devices',
                        onTap: () => _showComingSoon('My Devices'),
                        trailing: _comingSoonBadge(),
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1),
                const Padding(
                  padding: EdgeInsets.all(16),
                  child: Text(
                    'Powered by IdentityBot',
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

  Widget _buildSettingsSection() {
    return Column(
      children: [
        ListTile(
          leading: const Icon(Icons.settings_outlined, color: MobileColors.textSecondary, size: 22),
          title: const Text(
            'Settings',
            style: TextStyle(
              fontSize: 15,
              fontWeight: FontWeight.w500,
              color: MobileColors.textPrimary,
            ),
          ),
          trailing: AnimatedRotation(
            turns: _settingsExpanded ? 0.5 : 0.0,
            duration: const Duration(milliseconds: 200),
            child: const Icon(Icons.expand_more, color: MobileColors.textMuted, size: 22),
          ),
          onTap: () => setState(() => _settingsExpanded = !_settingsExpanded),
          contentPadding: const EdgeInsets.symmetric(horizontal: 20),
        ),
        AnimatedCrossFade(
          firstChild: const SizedBox(width: double.infinity, height: 0),
          secondChild: Column(
            children: [
              _SubMenuItem(
                icon: Icons.dns_outlined,
                label: 'Tunneling',
                onTap: widget.onSettingsTap,
              ),
            ],
          ),
          crossFadeState: _settingsExpanded ? CrossFadeState.showSecond : CrossFadeState.showFirst,
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

  const _SubMenuItem({
    required this.icon,
    required this.label,
    required this.onTap,
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
        style: const TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.w400,
          color: MobileColors.textSecondary,
        ),
      ),
      onTap: onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: 20),
      dense: true,
      visualDensity: VisualDensity.compact,
    );
  }
}
