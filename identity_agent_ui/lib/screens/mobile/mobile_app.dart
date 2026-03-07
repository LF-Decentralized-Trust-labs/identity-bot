import 'package:flutter/material.dart';
import '../../theme/mobile_theme.dart';
import '../../services/keri_service.dart';
import '../../services/preferences_service.dart';
import 'mobile_dashboard.dart';
import 'bottom_nav.dart';
import 'drawer_menu.dart';
import 'share_menu.dart';
import 'chatbot_panel.dart';
import 'mobile_qr_scanner.dart';
import 'mobile_profile_screen.dart';
import 'mobile_contacts_screen.dart';
import 'mobile_settings_screen.dart';

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
      builder: (_) => ShareMenu(serverUrl: widget.serverUrl),
    );
  }

  void _openScanner() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => MobileQrScanner(serverUrl: widget.serverUrl),
      ),
    );
  }

  void _openChatbot() {
    showDialog(
      context: context,
      barrierColor: Colors.black54,
      builder: (_) => const ChatbotPanel(),
    );
  }

  void _navigateToProfile() {
    _closeDrawer();
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => MobileProfileScreen(serverUrl: widget.serverUrl),
      ),
    );
  }

  void _navigateToContacts() {
    _closeDrawer();
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => MobileContactsScreen(serverUrl: widget.serverUrl),
      ),
    );
  }

  void _navigateToSettings() {
    _closeDrawer();
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => MobileSettingsScreen(serverUrl: widget.serverUrl),
      ),
    );
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
                    serverUrl: widget.serverUrl,
                    onMenuTap: _toggleDrawer,
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
                onProfileTap: _navigateToProfile,
                onContactsTap: _navigateToContacts,
                onSettingsTap: _navigateToSettings,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
