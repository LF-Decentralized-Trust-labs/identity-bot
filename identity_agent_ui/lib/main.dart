import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show debugPrint, kIsWeb;
import 'dart:io' show Platform;
import 'theme/app_theme.dart';
import 'screens/dashboard_screen.dart';
import 'screens/contacts_screen.dart';
import 'screens/oobi_screen.dart';
import 'screens/profile_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/marketplace_screen.dart';
import 'screens/setup_wizard_screen.dart';
import 'screens/mode_selection_screen.dart';
import 'screens/entity_type_screen.dart';
import 'screens/connect_server_screen.dart';
import 'services/core_service.dart';
import 'services/keri_service.dart';
import 'services/desktop_keri_service.dart';
import 'services/remote_server_keri_service.dart';
import 'services/mobile_remote_keri_service.dart';
import 'services/mobile_standalone_keri_service.dart';
import 'services/mobile_core_service.dart';
import 'services/preferences_service.dart';
import 'services/backend_process_service.dart';
import 'config/agent_config.dart';
import 'bridge/keri_bridge.dart';

String? _backendStartupError;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  if (!kIsWeb && BackendProcessService.isDesktopPlatform) {
    debugPrint('[Agent] Desktop platform detected — starting bundled backend in background...');
    BackendProcessService.instance.start().then((started) {
      debugPrint('[Agent] Backend process started: $started');
      if (!started) {
        _backendStartupError = BackendProcessService.instance.startupError;
        debugPrint('[Agent] Backend startup error: $_backendStartupError');
      }
    });
  }

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

bool get _isMobilePlatform {
  if (kIsWeb) return false;
  try {
    return Platform.isAndroid || Platform.isIOS;
  } catch (_) {
    return false;
  }
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
  bool _showedBackendError = false;

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

        if (hasIdentity) {
          setState(() => _step = OnboardingStep.dashboard);
        } else {
          await PreferencesService.clearAll();
          _selectedMode = null;
          _selectedEntityType = null;
          _serverUrl = null;
          debugPrint('[Agent] Setup was marked complete but no identity found — resetting onboarding');
          setState(() => _step = OnboardingStep.modeSelection);
        }
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
    if (_isMobilePlatform) {
      await KeriBridge.ensureInitialized();

      if (mode == AgentMode.connectExisting && serverUrl != null) {
        if (KeriBridge.isAvailable) {
          debugPrint('[Agent] Mobile Remote Controller WITHOUT Keys — '
              'Rust bridge for local child AID, '
              'remote parent server ($serverUrl) for backend/stateless ops');
          _keriService = MobileRemoteKeriService(parentServerUrl: serverUrl);
        } else {
          debugPrint('[Agent] Mobile Remote Controller — Rust bridge '
              'unavailable (${KeriBridge.loadError}), falling back to '
              'RemoteServerKeriService (all ops forwarded to remote server)');
          _keriService = RemoteServerKeriService(serverUrl: serverUrl);
        }
      } else {
        debugPrint('[Agent] Mobile Standalone — Rust bridge available: '
            '${KeriBridge.isAvailable}'
            '${KeriBridge.isAvailable ? '' : ' (error: ${KeriBridge.loadError})'}');

        final standaloneService = MobileStandaloneKeriService();

        try {
          debugPrint('[Agent] Starting embedded Go Core...');
          await standaloneService.startGoCore();
          final coreUrl = standaloneService.mobileCore.baseUrl;
          debugPrint('[Agent] Go Core started on port '
              '${standaloneService.mobileCore.port} → $coreUrl');
          _serverUrl = coreUrl;
        } catch (e) {
          debugPrint('[Agent] Go Core start failed (non-fatal): $e');
        }

        _keriService = standaloneService;
      }
    } else {
      if (mode == AgentMode.connectExisting && serverUrl != null) {
        _keriService = DesktopKeriService();
        debugPrint('[Agent] Desktop Remote Controller WITHOUT Keys — '
            'local Go+Python for child AID, '
            'remote parent server ($serverUrl) for backend/stateless ops');
      } else {
        _keriService = DesktopKeriService();
        debugPrint('[Agent] Desktop mode → ${AgentConfig.coreBaseUrl}');
      }
    }
  }

  Future<bool> _checkIdentityExists() async {
    if (_keriService == null) return false;

    try {
      String baseUrl;
      if (_keriService is MobileStandaloneKeriService) {
        final standalone = _keriService as MobileStandaloneKeriService;
        if (standalone.isCoreReady) {
          baseUrl = standalone.mobileCore.baseUrl;
        } else {
          return false;
        }
      } else {
        baseUrl = _serverUrl ?? AgentConfig.coreBaseUrl;
      }

      final coreService = CoreService(baseUrl: baseUrl);
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

  void _showBackendErrorDialog(BuildContext context, String error) {
    showDialog(
      context: context,
      barrierDismissible: true,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A2E),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: const BorderSide(color: Color(0xFFFF4444), width: 1),
        ),
        title: const Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Color(0xFFFF4444), size: 24),
            SizedBox(width: 8),
            Text(
              'BACKEND ERROR',
              style: TextStyle(
                color: Color(0xFFFF4444),
                fontSize: 16,
                fontWeight: FontWeight.w700,
                fontFamily: 'monospace',
                letterSpacing: 1.2,
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              error,
              style: const TextStyle(
                color: Color(0xFFB0B0B0),
                fontSize: 13,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'The Identity Agent backend could not be started. '
              'Identity creation and other core operations will not work until this is resolved.',
              style: TextStyle(
                color: Color(0xFF808080),
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () async {
              Navigator.of(ctx).pop();
              final started = await BackendProcessService.instance.start();
              if (started) {
                _backendStartupError = null;
              } else {
                _backendStartupError = BackendProcessService.instance.startupError;
                _showedBackendError = false;
                setState(() {});
              }
            },
            child: const Text(
              'RETRY',
              style: TextStyle(
                color: Color(0xFF00FF88),
                fontFamily: 'monospace',
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text(
              'DISMISS',
              style: TextStyle(
                color: Color(0xFF808080),
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
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
        if (_backendStartupError != null && !_showedBackendError) {
          _showedBackendError = true;
          WidgetsBinding.instance.addPostFrameCallback((_) {
            _showBackendErrorDialog(context, _backendStartupError!);
          });
        }
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
        String? effectiveServerUrl = _serverUrl;
        if (effectiveServerUrl == null && _keriService is MobileStandaloneKeriService) {
          final standalone = _keriService as MobileStandaloneKeriService;
          if (standalone.isCoreReady) {
            effectiveServerUrl = standalone.mobileCore.baseUrl;
          }
        }
        return AgentMainScreen(
          keriService: _keriService!,
          mode: _selectedMode,
          entityType: _selectedEntityType,
          serverUrl: effectiveServerUrl,
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
  final ValueNotifier<int> _oobiRefreshNotifier = ValueNotifier<int>(0);

  late final List<Widget> _screens;
  late final bool _isDesktop;

  @override
  void initState() {
    super.initState();
    _isDesktop = !kIsWeb && (Platform.isWindows || Platform.isMacOS || Platform.isLinux);
    _screens = [
      ProfileScreen(keriService: widget.keriService, serverUrl: widget.serverUrl),
      DashboardScreen(keriService: widget.keriService, serverUrl: widget.serverUrl),
      ContactsScreen(keriService: widget.keriService, serverUrl: widget.serverUrl),
      OobiScreen(keriService: widget.keriService, serverUrl: widget.serverUrl, refreshNotifier: _oobiRefreshNotifier),
      SettingsScreen(
        keriService: widget.keriService,
        mode: widget.mode,
        entityType: widget.entityType,
        serverUrl: widget.serverUrl,
      ),
      MarketplaceScreen(serverUrl: widget.serverUrl),
    ];
  }

  @override
  void dispose() {
    _oobiRefreshNotifier.dispose();
    super.dispose();
  }

  void _onTabTapped(int index) {
    setState(() => _currentIndex = index);
    if (index == 3) {
      _oobiRefreshNotifier.value++;
    }
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
          onTap: _onTabTapped,
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
          items: [
            const BottomNavigationBarItem(
              icon: Icon(Icons.person_outline),
              activeIcon: Icon(Icons.person),
              label: 'PROFILE',
            ),
            const BottomNavigationBarItem(
              icon: Icon(Icons.shield_outlined),
              activeIcon: Icon(Icons.shield),
              label: 'DASHBOARD',
            ),
            const BottomNavigationBarItem(
              icon: Icon(Icons.people_outlined),
              activeIcon: Icon(Icons.people),
              label: 'CONTACTS',
            ),
            const BottomNavigationBarItem(
              icon: Icon(Icons.qr_code),
              activeIcon: Icon(Icons.qr_code),
              label: 'OOBI',
            ),
            const BottomNavigationBarItem(
              icon: Icon(Icons.settings_outlined),
              activeIcon: Icon(Icons.settings),
              label: 'SETTINGS',
            ),
            const BottomNavigationBarItem(
              icon: Icon(Icons.apps_outlined),
              activeIcon: Icon(Icons.apps),
              label: 'APPS',
            ),
          ],
        ),
      ),
    );
  }
}
