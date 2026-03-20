import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/keri_service.dart';
import '../../services/preferences_service.dart';
import '../../screens/dashboard_screen.dart';
import '../../screens/contacts_screen.dart';
import '../../screens/profile_screen.dart';
import '../../screens/oobi_screen.dart';
import '../../screens/settings_screen.dart';
import '../../screens/marketplace_screen.dart';
import 'desktop_sidebar.dart';
import 'coming_soon_screen.dart';
import 'key_event_log_screen.dart';
import 'key_rotation_screen.dart';
import 'developer_tools_screen.dart';
import 'theme_settings_screen.dart';
import 'account_settings_screen.dart';

class DesktopApp extends StatefulWidget {
  final KeriService keriService;
  final AgentMode? mode;
  final EntityType? entityType;
  final String? serverUrl;
  final VoidCallback? onResetIdentity;

  const DesktopApp({
    super.key,
    required this.keriService,
    this.mode,
    this.entityType,
    this.serverUrl,
    this.onResetIdentity,
  });

  @override
  State<DesktopApp> createState() => _DesktopAppState();
}

class _DesktopAppState extends State<DesktopApp> {
  DesktopRoute _route = DesktopRoute.dashboard;
  bool _aiPanelOpen = false;

  void _navigate(DesktopRoute route) {
    setState(() => _route = route);
  }

  Widget _buildContent() {
    final url = widget.serverUrl;
    final keri = widget.keriService;

    switch (_route) {
      // ── Identity ───────────────────────────────────────────────────────────
      case DesktopRoute.dashboard:
        return DashboardScreen(keriService: keri, serverUrl: url);

      case DesktopRoute.identityProfile:
        return ProfileScreen(keriService: keri, serverUrl: url);

      case DesktopRoute.identityKel:
        return KeyEventLogScreen(serverUrl: url);

      case DesktopRoute.identityRotation:
        return KeyRotationScreen(keriService: keri, serverUrl: url);

      case DesktopRoute.identityOobi:
        return OobiScreen(keriService: keri, serverUrl: url);

      // ── Contacts / Apps ────────────────────────────────────────────────────
      case DesktopRoute.contacts:
        return ContactsScreen(keriService: keri, serverUrl: url);

      case DesktopRoute.apps:
        return MarketplaceScreen(serverUrl: url);

      // ── Settings ───────────────────────────────────────────────────────────
      case DesktopRoute.settingsNetwork:
      case DesktopRoute.settingsAiKeys:
        // Existing SettingsScreen handles both tunneling and AI keys.
        // Route both here until the split is done in a future sprint.
        return SettingsScreen(
          keriService: keri,
          mode: widget.mode,
          entityType: widget.entityType,
          serverUrl: url,
        );

      case DesktopRoute.settingsDeveloperTools:
        return DeveloperToolsScreen(serverUrl: url);

      case DesktopRoute.settingsTheme:
        return const ThemeSettingsScreen();

      case DesktopRoute.settingsAccount:
        return AccountSettingsScreen(
          mode: widget.mode,
          entityType: widget.entityType,
          serverUrl: url,
          onResetIdentity: widget.onResetIdentity,
        );

      // ── Coming Soon stubs ──────────────────────────────────────────────────
      case DesktopRoute.credentials:
        return const ComingSoonScreen(title: 'Credentials', icon: Icons.verified_user_outlined);
      case DesktopRoute.wallet:
        return const ComingSoonScreen(title: 'Wallet', icon: Icons.account_balance_wallet_outlined);
      case DesktopRoute.assets:
        return const ComingSoonScreen(title: 'Assets', icon: Icons.diamond_outlined);
      case DesktopRoute.dataVault:
        return const ComingSoonScreen(title: 'Data Vault', icon: Icons.storage_outlined);
      case DesktopRoute.myDevices:
        return const ComingSoonScreen(title: 'My Devices', icon: Icons.devices);
      case DesktopRoute.hubsCommunications:
        return const ComingSoonScreen(title: 'Communications Gateway', icon: Icons.chat_bubble_outline);
      case DesktopRoute.hubsAi:
        return const ComingSoonScreen(title: 'AI Hub', icon: Icons.auto_awesome);
      case DesktopRoute.hubsHealthcare:
        return const ComingSoonScreen(title: 'Healthcare Hub', icon: Icons.local_hospital_outlined);
      case DesktopRoute.hubsFinancial:
        return const ComingSoonScreen(title: 'Financial Hub', icon: Icons.bar_chart);
      case DesktopRoute.settingsKeri:
        return const ComingSoonScreen(title: 'KERI Settings', icon: Icons.key,
            description: 'Witness, mailbox, and watcher configuration coming soon.');
      case DesktopRoute.settingsKeyManagement:
        return const ComingSoonScreen(title: 'Key Management', icon: Icons.lock_outlined);
      case DesktopRoute.settingsServiceProviders:
        return const ComingSoonScreen(title: 'Service Providers', icon: Icons.cloud_outlined);
      case DesktopRoute.settingsConnectedApps:
        return const ComingSoonScreen(title: 'Connected Apps & Integrations', icon: Icons.link);
      case DesktopRoute.settingsGovernance:
        return const ComingSoonScreen(title: 'Governance Gateway', icon: Icons.gavel);
      case DesktopRoute.settingsPrivacy:
        return const ComingSoonScreen(title: 'Privacy & Data', icon: Icons.privacy_tip_outlined);
      case DesktopRoute.settingsNotifications:
        return const ComingSoonScreen(title: 'Notifications', icon: Icons.notifications_outlined);
      case DesktopRoute.settingsBackup:
        return const ComingSoonScreen(title: 'Backup & Recovery', icon: Icons.backup_outlined);
      case DesktopRoute.activityLog:
        return const ComingSoonScreen(title: 'Activity Log', icon: Icons.receipt_long_outlined);
      case DesktopRoute.orgOverview:
        return const ComingSoonScreen(title: 'Organization Overview', icon: Icons.business);
      case DesktopRoute.orgEmployees:
        return const ComingSoonScreen(title: 'Employees & Roles', icon: Icons.group_outlined);
      case DesktopRoute.orgCredentials:
        return const ComingSoonScreen(title: 'Organization Credentials', icon: Icons.verified_user_outlined);
      case DesktopRoute.orgSettings:
        return const ComingSoonScreen(title: 'Organization Settings', icon: Icons.settings_outlined);
    }
  }

  Widget _buildAiPanel() {
    return Container(
      width: 320,
      height: 400,
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.08),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.fromLTRB(16, 12, 8, 12),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AppColors.border)),
            ),
            child: Row(
              children: [
                const Icon(Icons.auto_awesome, color: AppColors.accent, size: 16),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'AI Assistant',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 16),
                  color: AppColors.textSecondary,
                  onPressed: () => setState(() => _aiPanelOpen = false),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                ),
              ],
            ),
          ),
          const Expanded(
            child: Center(
              child: Padding(
                padding: EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.auto_awesome, color: AppColors.textMuted, size: 40),
                    SizedBox(height: 16),
                    Text(
                      'AI Assistant',
                      style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    SizedBox(height: 8),
                    Text(
                      'Intelligent identity management assistant. Coming soon.',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 12,
                        height: 1.5,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: Row(
        children: [
          // ── Left sidebar ─────────────────────────────────────────────────
          DesktopSidebar(
            currentRoute: _route,
            onRouteSelected: _navigate,
            serverUrl: widget.serverUrl,
          ),
          // ── Vertical divider ─────────────────────────────────────────────
          VerticalDivider(width: 1, thickness: 1, color: AppColors.border),
          // ── Content area ─────────────────────────────────────────────────
          Expanded(
            child: Stack(
              children: [
                _buildContent(),
                Positioned(
                  bottom: 24,
                  right: 24,
                  child: _aiPanelOpen
                      ? _buildAiPanel()
                      : FloatingActionButton(
                          onPressed: () => setState(() => _aiPanelOpen = true),
                          backgroundColor: AppColors.accent,
                          foregroundColor: Colors.white,
                          tooltip: 'AI Assistant (coming soon)',
                          mini: true,
                          child: const Icon(Icons.auto_awesome, size: 18),
                        ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
