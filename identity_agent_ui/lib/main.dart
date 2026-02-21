import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show debugPrint;
import 'theme/app_theme.dart';
import 'screens/dashboard_screen.dart';
import 'screens/contacts_screen.dart';
import 'screens/oobi_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/setup_wizard_screen.dart';
import 'services/core_service.dart';
import 'services/keri_service.dart';
import 'services/desktop_keri_service.dart';
import 'services/remote_server_keri_service.dart';
import 'services/mobile_standalone_keri_service.dart';
import 'services/keri_helper_client.dart';
import 'config/agent_config.dart';
import 'bridge/keri_bridge.dart';

void main() {
  runApp(const IdentityAgentApp());
}

class IdentityAgentApp extends StatelessWidget {
  const IdentityAgentApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Identity Agent',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      home: const AgentRouter(),
    );
  }
}

class AgentRouter extends StatefulWidget {
  const AgentRouter({super.key});

  @override
  State<AgentRouter> createState() => _AgentRouterState();
}

class _AgentRouterState extends State<AgentRouter> {
  bool _loading = true;
  bool _identityExists = false;
  String? _error;
  late KeriService _keriService;
  late AgentEnvironment _environment;

  @override
  void initState() {
    super.initState();
    _initializeAsync();
  }

  Future<void> _initializeAsync() async {
    await _initializeServices();
    await _checkIdentity();
  }

  Future<void> _initializeServices() async {
    final primaryUrl = AgentConfig.primaryServerUrl;
    _environment = KeriService.detectEnvironment(
      primaryServerUrl: primaryUrl,
    );

    if (_environment == AgentEnvironment.mobileStandalone) {
      await KeriBridge.ensureInitialized();

      if (KeriBridge.isAvailable) {
        debugPrint('[Agent] Mobile Standalone mode — Rust bridge loaded');
        _keriService = MobileStandaloneKeriService(
          helper: KeriHelperClient(),
        );
      } else {
        debugPrint('[Agent] Rust bridge unavailable (${KeriBridge.loadError}), falling back to Desktop/Remote mode');
        _environment = AgentEnvironment.desktop;
        _keriService = DesktopKeriService();
      }
    } else if (_environment == AgentEnvironment.mobileRemote) {
      _keriService = RemoteServerKeriService(serverUrl: primaryUrl);
    } else {
      _keriService = DesktopKeriService();
    }
  }

  Future<void> _checkIdentity() async {
    if (_environment == AgentEnvironment.mobileStandalone) {
      setState(() {
        _identityExists = false;
        _loading = false;
      });
      return;
    }

    try {
      final coreService = CoreService();
      final identity = await coreService.getIdentity();
      coreService.dispose();

      setState(() {
        _identityExists = identity.initialized;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _identityExists = false;
        _loading = false;
        _error = e.toString();
      });
    }
  }

  void _onSetupComplete() {
    setState(() {
      _identityExists = true;
    });
  }

  @override
  void dispose() {
    _keriService.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return Scaffold(
        backgroundColor: AppColors.primary,
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 40,
                height: 40,
                child: CircularProgressIndicator(
                  color: AppColors.accent,
                  strokeWidth: 3,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                _environment == AgentEnvironment.mobileStandalone
                    ? 'INITIALIZING RUST BRIDGE...'
                    : 'CONNECTING TO CORE...',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 12,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
        ),
      );
    }

    if (_identityExists) {
      return AgentMainScreen(keriService: _keriService);
    }

    return SetupWizardScreen(
      onComplete: _onSetupComplete,
      keriService: _keriService,
    );
  }
}

class AgentMainScreen extends StatefulWidget {
  final KeriService keriService;

  const AgentMainScreen({super.key, required this.keriService});

  @override
  State<AgentMainScreen> createState() => _AgentMainScreenState();
}

class _AgentMainScreenState extends State<AgentMainScreen> {
  int _currentIndex = 0;

  late final List<Widget> _screens;

  @override
  void initState() {
    super.initState();
    _screens = [
      DashboardScreen(keriService: widget.keriService),
      ContactsScreen(keriService: widget.keriService),
      OobiScreen(keriService: widget.keriService),
      SettingsScreen(keriService: widget.keriService),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(
        index: _currentIndex,
        children: _screens,
      ),
      bottomNavigationBar: Container(
        decoration: const BoxDecoration(
          border: Border(
            top: BorderSide(color: AppColors.border, width: 1),
          ),
        ),
        child: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (index) => setState(() => _currentIndex = index),
          backgroundColor: AppColors.surface,
          selectedItemColor: AppColors.accent,
          unselectedItemColor: AppColors.textMuted,
          selectedLabelStyle: const TextStyle(
            fontSize: 10,
            fontWeight: FontWeight.w600,
            letterSpacing: 1.0,
            fontFamily: 'monospace',
          ),
          unselectedLabelStyle: const TextStyle(
            fontSize: 10,
            fontWeight: FontWeight.w500,
            letterSpacing: 1.0,
            fontFamily: 'monospace',
          ),
          type: BottomNavigationBarType.fixed,
          items: const [
            BottomNavigationBarItem(
              icon: Icon(Icons.shield_outlined),
              activeIcon: Icon(Icons.shield),
              label: 'DASHBOARD',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.people_outlined),
              activeIcon: Icon(Icons.people),
              label: 'CONTACTS',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.qr_code),
              activeIcon: Icon(Icons.qr_code),
              label: 'OOBI',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.settings_outlined),
              activeIcon: Icon(Icons.settings),
              label: 'SETTINGS',
            ),
          ],
        ),
      ),
    );
  }
}
