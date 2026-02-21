import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show debugPrint;
import 'theme/app_theme.dart';
import 'screens/dashboard_screen.dart';
import 'screens/contacts_screen.dart';
import 'screens/oobi_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/setup_wizard_screen.dart';
import 'screens/mode_selection_screen.dart';
import 'screens/entity_type_screen.dart';
import 'screens/connect_server_screen.dart';
import 'services/core_service.dart';
import 'services/keri_service.dart';
import 'services/desktop_keri_service.dart';
import 'services/remote_server_keri_service.dart';
import 'services/mobile_standalone_keri_service.dart';
import 'services/keri_helper_client.dart';
import 'services/preferences_service.dart';
import 'config/agent_config.dart';
import 'bridge/keri_bridge.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
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

enum OnboardingStep {
  loading,
  modeSelection,
  entityTypeSelection,
  connectServer,
  setupWizard,
  dashboard,
}

class AgentRouter extends StatefulWidget {
  const AgentRouter({super.key});

  @override
  State<AgentRouter> createState() => _AgentRouterState();
}

class _AgentRouterState extends State<AgentRouter> {
  OnboardingStep _step = OnboardingStep.loading;
  KeriService? _keriService;
  AgentMode? _selectedMode;
  EntityType? _selectedEntityType;
  String? _serverUrl;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadSavedState();
  }

  Future<void> _loadSavedState() async {
    try {
      final setupComplete = await PreferencesService.isSetupComplete();
      final savedMode = await PreferencesService.getMode();
      final savedEntityType = await PreferencesService.getEntityType();
      final savedServerUrl = await PreferencesService.getServerUrl();

      if (setupComplete && savedMode != null) {
        _selectedMode = savedMode;
        _selectedEntityType = savedEntityType;
        _serverUrl = savedServerUrl;

        await _initializeServiceForMode(savedMode, savedServerUrl);

        final hasIdentity = await _checkIdentityExists();

        setState(() {
          _step = hasIdentity
              ? OnboardingStep.dashboard
              : OnboardingStep.setupWizard;
        });
      } else {
        setState(() => _step = OnboardingStep.modeSelection);
      }
    } catch (e) {
      debugPrint('[Agent] Error loading saved state: $e');
      setState(() => _step = OnboardingStep.modeSelection);
    }
  }

  Future<void> _initializeServiceForMode(
      AgentMode mode, String? serverUrl) async {
    if (mode == AgentMode.connectExisting && serverUrl != null) {
      _keriService = DesktopKeriService(baseUrl: serverUrl);
      debugPrint('[Agent] Initialized in Connect mode → $serverUrl');
    } else {
      final env = KeriService.detectEnvironment(
        primaryServerUrl: AgentConfig.primaryServerUrl,
      );

      if (env == AgentEnvironment.mobileStandalone) {
        await KeriBridge.ensureInitialized();
        if (KeriBridge.isAvailable) {
          debugPrint('[Agent] Mobile Standalone — Rust bridge loaded');
          _keriService = MobileStandaloneKeriService(
            helper: KeriHelperClient(),
          );
        } else {
          debugPrint(
              '[Agent] Rust bridge unavailable, falling back to Desktop mode');
          _keriService = DesktopKeriService();
        }
      } else {
        _keriService = DesktopKeriService();
        debugPrint('[Agent] Desktop mode');
      }
    }
  }

  Future<bool> _checkIdentityExists() async {
    if (_keriService == null) return false;

    if (_keriService!.environment == AgentEnvironment.mobileStandalone) {
      return false;
    }

    try {
      final coreService = CoreService(
        baseUrl: _serverUrl ?? AgentConfig.coreBaseUrl,
      );
      final identity = await coreService.getIdentity();
      coreService.dispose();
      return identity.initialized;
    } catch (e) {
      debugPrint('[Agent] Identity check failed: $e');
      return false;
    }
  }

  void _onModeSelected(AgentMode mode) async {
    _selectedMode = mode;
    await PreferencesService.setMode(mode);

    if (mode == AgentMode.createNew) {
      setState(() => _step = OnboardingStep.entityTypeSelection);
    } else {
      setState(() => _step = OnboardingStep.connectServer);
    }
  }

  void _onEntityTypeSelected(EntityType type) async {
    _selectedEntityType = type;
    await PreferencesService.setEntityType(type);

    await _initializeServiceForMode(AgentMode.createNew, null);

    setState(() => _step = OnboardingStep.setupWizard);
  }

  void _onServerConnected(String serverUrl) async {
    _serverUrl = serverUrl;
    await PreferencesService.setServerUrl(serverUrl);

    await _initializeServiceForMode(AgentMode.connectExisting, serverUrl);
    await PreferencesService.setSetupComplete(true);

    setState(() => _step = OnboardingStep.dashboard);
  }

  void _onSetupComplete() async {
    await PreferencesService.setSetupComplete(true);
    setState(() => _step = OnboardingStep.dashboard);
  }

  void _goBackToModeSelection() {
    setState(() => _step = OnboardingStep.modeSelection);
  }

  @override
  void dispose() {
    _keriService?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    switch (_step) {
      case OnboardingStep.loading:
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
                const Text(
                  'INITIALIZING...',
                  style: TextStyle(
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

      case OnboardingStep.modeSelection:
        return ModeSelectionScreen(onModeSelected: _onModeSelected);

      case OnboardingStep.entityTypeSelection:
        return EntityTypeScreen(
          onEntityTypeSelected: _onEntityTypeSelected,
          onBack: _goBackToModeSelection,
        );

      case OnboardingStep.connectServer:
        return ConnectServerScreen(
          onConnected: _onServerConnected,
          onBack: _goBackToModeSelection,
        );

      case OnboardingStep.setupWizard:
        return SetupWizardScreen(
          onComplete: _onSetupComplete,
          keriService: _keriService!,
        );

      case OnboardingStep.dashboard:
        return AgentMainScreen(
          keriService: _keriService!,
          mode: _selectedMode,
          entityType: _selectedEntityType,
          serverUrl: _serverUrl,
        );
    }
  }
}

class AgentMainScreen extends StatefulWidget {
  final KeriService keriService;
  final AgentMode? mode;
  final EntityType? entityType;
  final String? serverUrl;

  const AgentMainScreen({
    super.key,
    required this.keriService,
    this.mode,
    this.entityType,
    this.serverUrl,
  });

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
      SettingsScreen(
        keriService: widget.keriService,
        mode: widget.mode,
        entityType: widget.entityType,
        serverUrl: widget.serverUrl,
      ),
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
