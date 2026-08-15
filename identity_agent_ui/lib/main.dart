import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show debugPrint, kIsWeb;
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'dart:io' show Platform;
import 'theme/app_theme.dart';
import 'brand/brand.dart';
import 'screens/desktop/desktop_app.dart';
import 'screens/setup_wizard_screen.dart';
import 'screens/mode_selection_screen.dart';
import 'screens/connect_server_screen.dart';
import 'screens/backup/backup_only_standby_screen.dart';
import 'screens/recovery/recovery_onboarding_screen.dart';
import 'package:agent_client/services/recovery_service.dart';
import 'services/core_service.dart';
import 'package:agent_client/services/keri_service.dart';
import 'package:agent_client/services/local_core_keri_service.dart';
import 'package:agent_client/services/mobile_core_service.dart';
import 'services/preferences_service.dart';
import 'services/secure_key_store.dart';
import 'services/backend_process_service.dart';
import 'package:agent_client/config/agent_config.dart';
import 'screens/mobile/mobile_app.dart';
import 'screens/hosting_choice_screen.dart';
import 'screens/setup_checklist_screen.dart';
import 'screens/lock_screen.dart';
import 'services/pin_password_service.dart';
import 'widgets/login_consent_listener.dart';

String? _backendStartupError;
Future<bool>? _backendStartupFuture;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Move anything stored before profiles existed into the active profile,
  // before a single read happens.
  //
  // Order matters more than it looks: every later read resolves through the
  // profile scope, so a migration that ran afterwards would find the new
  // location already consulted and empty — an installation with a perfectly
  // good recovery phrase behaving as though it had none.
  //
  // Both migrations copy, verify, then delete, and leave the original in place
  // if any step fails. On the phrase that is the difference between a
  // migration and an identity nobody can recover.
  await SecureKeyStore.migrateLegacyMnemonic();
  await PreferencesService.migrateLegacyKeys();

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
          title: currentBrand.displayName,
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
  backupOnlyStandby,
  recoveryOnboarding,
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

  /// The Identity Agent core running inside this app on mobile.
  ///
  /// Held here rather than inside the KERI service, because starting the core
  /// and speaking KERI to it are two jobs and only one of them is mobile.
  final MobileCoreService _mobileCore = MobileCoreService();
  AgentMode? _selectedMode;
  EntityType? _selectedEntityType;
  String? _serverUrl;
  String? _remoteBrainUrl;
  HostingChoice? _hostingChoice;
  RecoverySession? _recoverySession;
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
      // The core runs inside this app, and KERI goes to it — the same
      // arrangement desktop has always had.
      //
      // Mobile used to have a KERI engine of its own, a Rust library reached
      // through a bridge. Its inception took the recovery phrase as an argument
      // it never read, generated a random keypair and kept it in memory, so an
      // identity created here could not be recovered from its words and did not
      // survive the app being killed. Both failures were silent.
      //
      // Starting the core is therefore no longer "non-fatal": if it does not
      // start there is nothing to do KERI with, and continuing would only
      // reach the same failure further along and with less to say about it.
      debugPrint('[Agent] Starting embedded Go Core...');
      await _mobileCore.startCore();
      if (!await _mobileCore.waitForReady()) {
        throw Exception('the Identity Agent core did not start, so this device '
            'has no KERI engine');
      }
      final coreUrl = _mobileCore.baseUrl;
      debugPrint('[Agent] Go Core ready on ${_mobileCore.port} → $coreUrl');
      _serverUrl = coreUrl;

      if (mode == AgentMode.connectExisting && serverUrl != null) {
        debugPrint('[Agent] Mobile paired with $serverUrl — '
            'keys stay here, backend work goes to the paired server');
      } else {
        debugPrint('[Agent] Mobile standalone → $coreUrl');
      }
      _keriService = LocalCoreKeriService(baseUrl: coreUrl);
    } else {
      if (mode == AgentMode.connectExisting && serverUrl != null) {
        _keriService = LocalCoreKeriService();
        debugPrint('[Agent] Desktop Remote Controller WITHOUT Keys — '
            'local Go+Python for child AID, '
            'remote parent server ($serverUrl) for backend/stateless ops');
      } else {
        _keriService = LocalCoreKeriService();
        debugPrint('[Agent] Desktop mode → ${AgentConfig.coreBaseUrl}');
      }
    }
  }

  Future<bool> _checkIdentityExists() async {
    if (_keriService == null) return false;

    try {
      String baseUrl;
      if (_isMobilePlatform) {
        if (!_mobileCore.isStarted) return false;
        baseUrl = _mobileCore.baseUrl;
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
    } else if (mode == AgentMode.backupOnly) {
      await PreferencesService.setSetupComplete(true);
      setState(() => _step = OnboardingStep.backupOnlyStandby);
    } else if (mode == AgentMode.recoverFromBackup) {
      setState(() => _step = OnboardingStep.recoveryOnboarding);
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

  void _onRecoveryStarted(RecoverySession session) async {
    _recoverySession = session;
    _selectedMode = AgentMode.recoverFromBackup;
    await PreferencesService.setMode(AgentMode.recoverFromBackup);
    await PreferencesService.setEntityType(EntityType.individual);
    await PreferencesService.setSetupComplete(true);
    await _initializeServiceForMode(AgentMode.recoverFromBackup, null);
    setState(() => _step = OnboardingStep.dashboard);
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
        return ModeSelectionScreen(
          onModeSelected: _onModeSelected,
          onRecoverFromBackup: () =>
              setState(() => _step = OnboardingStep.recoveryOnboarding),
        );

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

      case OnboardingStep.backupOnlyStandby:
        return const BackupOnlyStandbyScreen(connectionStatus: 'paired');

      case OnboardingStep.recoveryOnboarding:
        return RecoveryOnboardingScreen(
          onBack: _goBackToModeSelection,
          onRecoveryStarted: _onRecoveryStarted,
        );

      case OnboardingStep.dashboard:
        String? effectiveServerUrl = _serverUrl;
        if (effectiveServerUrl == null && _isMobilePlatform && _mobileCore.isStarted) {
          effectiveServerUrl = _mobileCore.baseUrl;
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
    final app = AppLayout.isMobile(context)
        ? MobileApp(
            keriService: widget.keriService,
            mode: widget.mode,
            entityType: widget.entityType,
            serverUrl: widget.serverUrl,
          )
        : DesktopApp(
            keriService: widget.keriService,
            mode: widget.mode,
            entityType: widget.entityType,
            serverUrl: widget.serverUrl,
            onResetIdentity: _handleReset,
          );

    return LoginConsentListener(
      serverUrl: widget.serverUrl,
      child: app,
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
