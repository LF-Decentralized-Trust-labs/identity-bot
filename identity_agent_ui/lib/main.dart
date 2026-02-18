import 'package:flutter/material.dart';
import 'theme/app_theme.dart';
import 'screens/dashboard_screen.dart';
import 'screens/setup_wizard_screen.dart';
import 'services/core_service.dart';

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

  @override
  void initState() {
    super.initState();
    _checkIdentity();
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
              const Text(
                'CONNECTING TO CORE...',
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
    }

    if (_identityExists) {
      return const DashboardScreen();
    }

    return SetupWizardScreen(onComplete: _onSetupComplete);
  }
}
