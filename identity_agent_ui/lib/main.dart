import 'package:flutter/material.dart';
import 'theme/app_theme.dart';
import 'screens/dashboard_screen.dart';
import 'screens/setup_wizard_screen.dart';
import 'services/core_service.dart';
import 'services/keri_service.dart';
import 'services/desktop_keri_service.dart';
import 'services/remote_server_keri_service.dart';
import 'services/mobile_standalone_keri_service.dart';
import 'services/keri_helper_client.dart';
import 'config/agent_config.dart';

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
  late final KeriService _keriService;
  late final AgentEnvironment _environment;

  @override
  void initState() {
    super.initState();
    _initializeServices();
    _checkIdentity();
  }

  void _initializeServices() {
    final primaryUrl = AgentConfig.primaryServerUrl;
    _environment = KeriService.detectEnvironment(
      primaryServerUrl: primaryUrl,
    );

    switch (_environment) {
      case AgentEnvironment.desktop:
        _keriService = DesktopKeriService();
        break;
      case AgentEnvironment.mobileRemote:
        _keriService = RemoteServerKeriService(serverUrl: primaryUrl);
        break;
      case AgentEnvironment.mobileStandalone:
        _keriService = MobileStandaloneKeriService(
          helper: KeriHelperClient(),
        );
        break;
    }
  }

  Future<void> _checkIdentity() async {
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
      return DashboardScreen(keriService: _keriService);
    }

    return SetupWizardScreen(
      onComplete: _onSetupComplete,
      keriService: _keriService,
    );
  }
}
