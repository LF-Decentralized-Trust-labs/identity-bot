import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/keri_service.dart';
import '../../services/preferences_service.dart';
import '../profile_screen.dart';
import '../contacts_screen.dart';
import '../settings_screen.dart';
import '../desktop/coming_soon_screen.dart';
import '../desktop/developer_tools_screen.dart';
import '../desktop/keri_protocol_screen.dart';
import '../desktop/endpoints_screen.dart';
import '../desktop/theme_settings_screen.dart';
import '../desktop/account_settings_screen.dart';
import '../desktop/auth_management_screen.dart';
import '../desktop/history_screen.dart';
import '../desktop/my_devices_screen.dart';
import '../desktop/guardianship_dependents_screen.dart';
import '../desktop/credentials_screen.dart';
import '../desktop/service_providers_screen.dart';
import 'mobile_dashboard.dart';
import 'bottom_nav.dart';
import 'drawer_menu.dart';
import 'share_menu.dart';
import 'chatbot_panel.dart';
import 'mobile_qr_scanner.dart';

class MobileApp extends StatefulWidget {
  final KeriService keriService;
  final AgentMode? mode;
  final EntityType? entityType;
  final String? serverUrl;
  const MobileApp({
    super.key,
    required this.keriService,
    this.mode,
    this.entityType,
    this.serverUrl,
  });

  @override
  State<MobileApp> createState() => _MobileAppState();
}

class _MobileAppState extends State<MobileApp> {
  final _dashboardKey = GlobalKey<MobileDashboardState>();
  bool _drawerOpen = false;

  void _toggleDrawer() {
    setState(() => _drawerOpen = !_drawerOpen);
  }

  void _closeDrawer() {
    setState(() => _drawerOpen = false);
  }

  void _openShare() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (_) => ShareMenu(
        serverUrl: widget.serverUrl,
        onAddContactComplete: () {
          _dashboardKey.currentState?.refreshAlerts();
        },
      ),
    ).then((_) {
      _dashboardKey.currentState?.refreshAlerts();
    });
  }

  void _openScanner() {
    Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => MobileQrScanner(serverUrl: widget.serverUrl),
      ),
    ).then((added) {
      _dashboardKey.currentState?.refreshAlerts();
    });
  }

  void _openChatbot() {
    showDialog(
      context: context,
      barrierColor: Colors.black54,
      builder: (_) => const ChatbotPanel(),
    );
  }

  /// Central navigation handler — maps screen keys from the drawer to actual screens.
  void _handleNavigate(String screenKey) {
    _closeDrawer();
    final url = widget.serverUrl;
    final keri = widget.keriService;

    Widget screen;
    switch (screenKey) {
      // ── Core items ────────────────────────────────────────────────────────
      case 'profile':
        screen = ProfileScreen(keriService: keri, serverUrl: url);
        break;
      case 'contacts':
        _pushAndRefresh(ContactsScreen(keriService: keri, serverUrl: url));
        return;
      case 'credentials':
        screen = CredentialsScreen(serverUrl: url);
        break;
      case 'passwords':
        screen = const ComingSoonScreen(title: 'Passwords', icon: Icons.password_outlined);
        break;
      case 'wallet':
        screen = const ComingSoonScreen(title: 'Wallet', icon: Icons.account_balance_wallet_outlined);
        break;
      case 'myDevices':
        screen = MyDevicesScreen(keriService: keri, serverUrl: url);
        break;

      // ── Guardianship ──────────────────────────────────────────────────────
      case 'guardianshipDependents':
        screen = GuardianshipDependentsScreen(serverUrl: url);
        break;
      case 'guardianshipGuardians':
        screen = const ComingSoonScreen(title: 'My Guardians', icon: Icons.shield_outlined);
        break;
      case 'guardianshipSuccession':
        screen = const ComingSoonScreen(
          title: 'Digital Will',
          icon: Icons.article_outlined,
          description: 'Designate who inherits control of your digital identity if you pass away or become incapacitated.',
        );
        break;
      case 'guardianshipEstate':
        screen = const ComingSoonScreen(
          title: 'Estate Planning',
          icon: Icons.account_balance_outlined,
          description: 'Plan the long-term management and transfer of your digital estate.',
        );
        break;

      // ── Hubs ──────────────────────────────────────────────────────────────
      case 'hubsCommunications':
        screen = const ComingSoonScreen(title: 'Communications', icon: Icons.chat_bubble_outline);
        break;
      case 'hubsAi':
        screen = const ComingSoonScreen(title: 'AI', icon: Icons.auto_awesome);
        break;
      case 'hubsHealth':
        screen = const ComingSoonScreen(title: 'Health', icon: Icons.favorite_border);
        break;
      case 'hubsFinance':
        screen = const ComingSoonScreen(title: 'Finance', icon: Icons.bar_chart);
        break;
      case 'hubsSocialMedia':
        screen = const ComingSoonScreen(title: 'Social Media', icon: Icons.tag);
        break;
      case 'hubsLegal':
        screen = const ComingSoonScreen(title: 'Legal', icon: Icons.gavel);
        break;
      case 'hubsSecurity':
        screen = const ComingSoonScreen(title: 'Security', icon: Icons.security);
        break;

      // ── History ───────────────────────────────────────────────────────────
      case 'history':
        screen = HistoryScreen(serverUrl: url);
        break;

      // ── Settings ──────────────────────────────────────────────────────────
      case 'settingsAccount':
        screen = AccountSettingsScreen(
          mode: widget.mode,
          entityType: widget.entityType,
          serverUrl: url,
        );
        break;
      case 'settingsAuthentication':
        screen = const AuthManagementScreen();
        break;
      case 'settingsPrivacy':
        screen = const ComingSoonScreen(title: 'Privacy & Data', icon: Icons.privacy_tip_outlined);
        break;
      case 'settingsTheme':
        screen = const ThemeSettingsScreen();
        break;
      case 'settingsNotifications':
        screen = const ComingSoonScreen(title: 'Notifications', icon: Icons.notifications_outlined);
        break;
      case 'settingsTunneling':
        screen = SettingsScreen(
          keriService: keri,
          mode: widget.mode,
          entityType: widget.entityType,
          serverUrl: url,
        );
        break;
      case 'settingsEndpoints':
        screen = EndpointsScreen(serverUrl: url);
        break;
      case 'settingsServiceProviders':
        screen = ServiceProvidersScreen(serverUrl: url);
        break;
      case 'settingsGovernance':
        screen = const ComingSoonScreen(title: 'Governance', icon: Icons.gavel);
        break;
      case 'settingsKeri':
        screen = KeriProtocolScreen(keriService: keri, serverUrl: url);
        break;
      case 'settingsBackup':
        screen = const ComingSoonScreen(title: 'Backup & Recovery', icon: Icons.backup_outlined);
        break;
      case 'settingsDeveloperTools':
        screen = DeveloperToolsScreen(serverUrl: url);
        break;

      default:
        screen = const ComingSoonScreen(title: 'Coming Soon', icon: Icons.construction);
    }

    Navigator.of(context).push(MaterialPageRoute(builder: (_) => screen));
  }

  void _pushAndRefresh(Widget screen) {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => screen),
    ).then((_) {
      _dashboardKey.currentState?.refreshAlerts();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        body: Stack(
          children: [
            Column(
              children: [
                Expanded(
                  child: MobileDashboard(
                    key: _dashboardKey,
                    serverUrl: widget.serverUrl,
                    onMenuTap: _toggleDrawer,
                    keriService: widget.keriService,
                  ),
                ),
                MobileBottomNav(
                  onShare: _openShare,
                  onScan: _openScanner,
                  onChatbot: _openChatbot,
                ),
              ],
            ),
            if (_drawerOpen) ...[
              GestureDetector(
                onTap: _closeDrawer,
                child: AnimatedOpacity(
                  opacity: _drawerOpen ? 1.0 : 0.0,
                  duration: const Duration(milliseconds: 200),
                  child: Container(color: Colors.black54),
                ),
              ),
              DrawerMenu(
                serverUrl: widget.serverUrl,
                onClose: _closeDrawer,
                onNavigate: _handleNavigate,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
