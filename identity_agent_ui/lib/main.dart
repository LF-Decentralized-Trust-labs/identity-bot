import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show debugPrint, kIsWeb;
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'dart:io' show Platform;
import 'theme/app_theme.dart';
import 'screens/desktop/desktop_app.dart';
import 'screens/setup_wizard_screen.dart';
import 'screens/mode_selection_screen.dart';
import 'screens/connect_server_screen.dart';
import 'services/core_service.dart';
import 'services/keri_service.dart';
import 'services/desktop_on_device_keri_service.dart';
import 'services/mobile_on_device_keri_service.dart';
import 'services/mobile_remote_keri_service.dart';
import 'services/preferences_service.dart';
import 'services/backend_process_service.dart';
import 'config/agent_config.dart';
import 'bridge/keri_bridge_stub.dart'
    if (dart.library.io) 'bridge/keri_bridge.dart';
import 'screens/mobile/mobile_app.dart';
import 'screens/hosting_choice_screen.dart';
import 'screens/setup_checklist_screen.dart';
import 'screens/lock_screen.dart';
import 'services/pin_password_service.dart';

String? _backendStartupError;
Future<bool>? _backendStartupFuture;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Load persisted theme before the first frame.
  await ThemeNotifier.initialize();

  if (!kIsWeb && BackendProcessService.isDesktopPlatform) {
    debugPrint('[Agent] Desktop platform detected — starting bundled backend in background...');
    _backendStartupFuture = BackendProcessService.instance.start().then((started) {
      debugPrint('[Agent] Backend process started: $started');
      if (!started) {
        _backendStartupError = BackendProcessService.instance.startupError;
        debugPrint('[Agent] Backend startup error: $_backendStartupError');
      }
      return started;
    });
  }

  runApp(const IdentityAgentApp());
}

class IdentityAgentApp extends StatelessWidget {
  const IdentityAgentApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: ThemeNotifier.instance,
      builder: (_, themeMode, __) {
        return MaterialApp(
          title: 'Identity Agent',
          debugShowCheckedModeBanner: false,
          theme:      AppTheme.light,
          darkTheme:  AppTheme.dark,
          themeMode:  themeMode,
          home: const AgentRouter(),
        );
      },
    );
  }
}

enum OnboardingStep {
  loading,
  modeSelection,
  hostingChoice,
  connectServer,
  setupWizard,
  setupChecklist,
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
  String? _remoteBrainUrl;
  HostingChoice? _hostingChoice;
  bool _showedBackendError = false;

  @override
  void initState() {
    super.initState();
    _loadSavedState();
  }

  Future<void> _loadSavedState() async {
    try {
      if (_backendStartupFuture != null) {
        debugPrint('[Agent] Waiting for backend startup before loading state...');
        await _backendStartupFuture;
      }

      final setupComplete = await PreferencesService.isSetupComplete();
      final savedMode = await PreferencesService.getMode();
      final savedEntityType = await PreferencesService.getEntityType();
      final savedServerUrl = await PreferencesService.getServerUrl();

      if (_backendStartupError != null) {
        if (mounted) {
          setState(() {
            _step = OnboardingStep.modeSelection;
            _showedBackendError = false;
          });
        }
        return;
      }

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
        final recovered = await _tryRecoverExistingIdentity();
        if (recovered) {
          debugPrint('[Agent] Recovered existing identity — skipping onboarding');
          setState(() => _step = OnboardingStep.dashboard);
        } else {
          setState(() => _step = OnboardingStep.modeSelection);
        }
      }
    } catch (e) {
      debugPrint('[Agent] Error loading saved state: $e');
      setState(() => _step = OnboardingStep.modeSelection);
    }
  }

  Future<bool> _tryRecoverExistingIdentity() async {
    try {
      final baseUrl = AgentConfig.coreBaseUrl;
      final coreService = CoreService(baseUrl: baseUrl);
      final identity = await coreService.getIdentity();
      coreService.dispose();

      if (identity.initialized) {
        debugPrint('[Agent] Found existing identity on backend — recovering session');
        _selectedMode = AgentMode.createNew;
        _selectedEntityType = EntityType.individual;
        await PreferencesService.setMode(AgentMode.createNew);
        await PreferencesService.setEntityType(EntityType.individual);
        await PreferencesService.setSetupComplete(true);
        await _initializeServiceForMode(AgentMode.createNew, null);
        return true;
      }
    } catch (e) {
      debugPrint('[Agent] Recovery check failed: $e');
    }
    return false;
  }

  Future<void> _initializeServiceForMode(
      AgentMode mode, String? serverUrl) async {
    _keriService?.dispose();
    _keriService = null;

    if (_isMobilePlatform) {
      await KeriBridge.ensureInitialized();

      if (mode == AgentMode.connectExisting && serverUrl != null) {
        if (KeriBridge.isAvailable) {
          debugPrint('[Agent] Mobile Remote Controller WITH Keys — '
              'Rust bridge for local key ops, '
              'paired server ($serverUrl) for backend/stateless ops');
          _keriService = MobileOnDeviceKeriService(pairedServerUrl: serverUrl);
        } else {
          debugPrint('[Agent] Mobile Remote Controller WITHOUT Keys — '
              'Rust bridge unavailable (${KeriBridge.loadError}), '
              'all ops forwarded to paired server');
          _keriService = MobileRemoteKeriService(serverUrl: serverUrl);
        }
      } else {
        debugPrint('[Agent] Mobile Standalone — Rust bridge available: '
            '${KeriBridge.isAvailable}'
            '${KeriBridge.isAvailable ? '' : ' (error: ${KeriBridge.loadError})'}');

        final onDeviceService = MobileOnDeviceKeriService();

        try {
          debugPrint('[Agent] Starting embedded Go Core...');
          await onDeviceService.startGoCore();
          final coreUrl = onDeviceService.mobileCore.baseUrl;
          debugPrint('[Agent] Go Core started on port '
              '${onDeviceService.mobileCore.port} → $coreUrl');
          _serverUrl = coreUrl;
        } catch (e) {
          debugPrint('[Agent] Go Core start failed (non-fatal): $e');
        }

        _keriService = onDeviceService;
      }
    } else {
      if (mode == AgentMode.connectExisting && serverUrl != null) {
        _keriService = DesktopOnDeviceKeriService();
        debugPrint('[Agent] Desktop Remote Controller WITHOUT Keys — '
            'local Go+Python for child AID, '
            'remote parent server ($serverUrl) for backend/stateless ops');
      } else {
        _keriService = DesktopOnDeviceKeriService();
        debugPrint('[Agent] Desktop mode → ${AgentConfig.coreBaseUrl}');
      }
    }
  }

  Future<bool> _checkIdentityExists() async {
    if (_keriService == null) return false;

    try {
      String baseUrl;
      if (_keriService is MobileOnDeviceKeriService) {
        final standalone = _keriService as MobileOnDeviceKeriService;
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
      _selectedEntityType = EntityType.individual;
      await PreferencesService.setEntityType(EntityType.individual);
      setState(() => _step = OnboardingStep.hostingChoice);
    } else {
      setState(() => _step = OnboardingStep.connectServer);
    }
  }

  void _onHostingChosen(HostingChoice choice, {String? remoteBrainUrl}) async {
    _hostingChoice = choice;
    _remoteBrainUrl = remoteBrainUrl;
    await PreferencesService.setHostingChoice(choice);
    if (remoteBrainUrl != null) {
      await PreferencesService.setRemoteBrainUrl(remoteBrainUrl);
    }
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
    // Go straight to dashboard; the SetupTaskBanner will auto-open the
    // checklist modal on first load (no white-background intermediate page).
    setState(() => _step = OnboardingStep.dashboard);
  }

  void _onChecklistDone() {
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
    final conflict = BackendProcessService.instance.portConflict;
    final isPortConflict = conflict != null;

    showDialog(
      context: context,
      barrierDismissible: true,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) {
          bool _copied = false;

          void _copyLog() async {
            await Clipboard.setData(ClipboardData(text: error));
            setDialogState(() => _copied = true);
            await Future.delayed(const Duration(seconds: 2));
            setDialogState(() => _copied = false);
          }

          return AlertDialog(
        backgroundColor: const Color(0xFF1A1A2E),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: BorderSide(
            color: isPortConflict ? const Color(0xFFFF8800) : const Color(0xFFFF4444),
            width: 1,
          ),
        ),
        title: Row(
          children: [
            Icon(
              isPortConflict ? Icons.swap_horiz_rounded : Icons.warning_amber_rounded,
              color: isPortConflict ? const Color(0xFFFF8800) : const Color(0xFFFF4444),
              size: 24,
            ),
            const SizedBox(width: 8),
            Text(
              isPortConflict ? 'PORT CONFLICT' : 'BACKEND ERROR',
              style: TextStyle(
                color: isPortConflict ? const Color(0xFFFF8800) : const Color(0xFFFF4444),
                fontSize: 16,
                fontWeight: FontWeight.w700,
                fontFamily: 'monospace',
                letterSpacing: 1.2,
              ),
            ),
          ],
        ),
        content: ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 400, maxWidth: 500),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  error,
                  style: const TextStyle(
                    color: Color(0xFFB0B0B0),
                    fontSize: 12,
                    fontFamily: 'monospace',
                    height: 1.4,
                  ),
                ),
                if (!isPortConflict) ...[
                  const SizedBox(height: 16),
                  const Text(
                    'The Identity Agent backend could not be started. '
                    'Identity creation and other core operations will not work until this is resolved.',
                    style: TextStyle(
                      color: Color(0xFF808080),
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'A diagnostic log has been saved alongside the application.',
                    style: TextStyle(
                      color: Color(0xFF606060),
                      fontSize: 10,
                      fontFamily: 'monospace',
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        actions: [
          if (!isPortConflict)
            TextButton(
              onPressed: _copyLog,
              child: Text(
                _copied ? 'COPIED!' : 'COPY LOG',
                style: TextStyle(
                  color: _copied ? const Color(0xFF00FF88) : const Color(0xFF4488FF),
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          if (isPortConflict)
            TextButton(
              onPressed: () async {
                Navigator.of(ctx).pop();
                final killed = await BackendProcessService.instance.killProcessOnPort(conflict);
                if (killed) {
                  final started = await BackendProcessService.instance.start();
                  if (started) {
                    _backendStartupError = null;
                  } else {
                    _backendStartupError = BackendProcessService.instance.startupError;
                    _showedBackendError = false;
                  }
                } else {
                  _backendStartupError = 'Failed to close "${conflict.processName}". '
                      'Please close it manually and try again.';
                  _showedBackendError = false;
                }
                setState(() {});
              },
              child: const Text(
                'CLOSE IT AND RETRY',
                style: TextStyle(
                  color: Color(0xFFFF8800),
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
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
          );
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return _buildForMode(AppLayout.isMobile(context));
  }

  Widget _buildForMode(bool isMobile) {
    switch (_step) {
      case OnboardingStep.loading:
        return Scaffold(
          backgroundColor: AppColors.background,
          body: Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 40,
                  height: 40,
                  child: CircularProgressIndicator(
                    color: AppColors.primary,
                    strokeWidth: 3,
                  ),
                ),
                const SizedBox(height: 16),
                const Text(
                  'Initializing...',
                  style: TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 14,
                    letterSpacing: 0,
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

      case OnboardingStep.hostingChoice:
        return HostingChoiceScreen(onHostingChosen: _onHostingChosen);

      case OnboardingStep.connectServer:
        return ConnectServerScreen(
          onConnected: _onServerConnected,
          onBack: _goBackToModeSelection,
        );

      case OnboardingStep.setupWizard:
        return SetupWizardScreen(
          onComplete: _onSetupComplete,
          keriService: _keriService!,
          remoteBrainUrl: _remoteBrainUrl,
          entityType: _selectedEntityType,
        );

      case OnboardingStep.setupChecklist:
        return SetupChecklistScreen(
          onDone: _onChecklistDone,
          keriService: _keriService!,
          serverUrl: _serverUrl,
          hostingChoice: _hostingChoice,
          remoteBrainUrl: _remoteBrainUrl,
        );

      case OnboardingStep.dashboard:
        String? effectiveServerUrl = _serverUrl;
        if (effectiveServerUrl == null && _keriService is MobileOnDeviceKeriService) {
          final standalone = _keriService as MobileOnDeviceKeriService;
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

class _AgentMainScreenState extends State<AgentMainScreen>
    with WidgetsBindingObserver {
  bool _locked = false;
  DateTime? _backgroundedAt;
  static const _lockAfter = Duration(minutes: 5);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      _backgroundedAt ??= DateTime.now();
    } else if (state == AppLifecycleState.resumed) {
      _maybelock();
    }
  }

  Future<void> _maybelock() async {
    final bg = _backgroundedAt;
    if (bg == null) return;
    if (DateTime.now().difference(bg) < _lockAfter) return;
    _backgroundedAt = null;
    // Only lock if screen lock is enabled AND the user has set up authentication
    final enabled = await PreferencesService.isScreenLockEnabled();
    if (!enabled) return;
    final hasAuth = await PinPasswordService.hasAnyCredential();
    if (hasAuth && mounted) setState(() => _locked = true);
  }

  void _handleReset() {
    if (mounted) {
      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const AgentRouter()),
        (_) => false,
      );
    }
  }

  Widget _buildMain() {
    if (AppLayout.isMobile(context)) {
      return MobileApp(
        keriService: widget.keriService,
        mode: widget.mode,
        entityType: widget.entityType,
        serverUrl: widget.serverUrl,
      );
    }
    return DesktopApp(
      keriService: widget.keriService,
      mode: widget.mode,
      entityType: widget.entityType,
      serverUrl: widget.serverUrl,
      onResetIdentity: _handleReset,
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_locked) {
      return LockScreen(onUnlocked: () => setState(() => _locked = false));
    }
    return _buildMain();
  }
}
