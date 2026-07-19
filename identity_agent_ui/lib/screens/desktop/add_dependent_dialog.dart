import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/config/agent_config.dart';

class AddDependentDialog extends StatefulWidget {
  final String? serverUrl;

  const AddDependentDialog({super.key, this.serverUrl});

  @override
  State<AddDependentDialog> createState() => _AddDependentDialogState();
}

class _AddDependentDialogState extends State<AddDependentDialog> {
  late final CoreService _coreService;
  int _step = 0; // 0=template, 1=info, 2=hosting, 3=confirm
  String? _selectedType;
  String _dependentName = '';
  String _hostingType = 'cloud';
  String _dateOfBirth = '';
  bool _creating = false;
  String? _error;

  final _nameController = TextEditingController();
  final _dobController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
  }

  @override
  void dispose() {
    _coreService.dispose();
    _nameController.dispose();
    _dobController.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    setState(() { _creating = true; _error = null; });
    try {
      final metadata = <String, String>{};
      if (_dateOfBirth.isNotEmpty) metadata['date_of_birth'] = _dateOfBirth;

      Map<String, dynamic>? emancipation;
      if (_selectedType == 'minor_child' && _dateOfBirth.isNotEmpty) {
        emancipation = {'type': 'age', 'value': '18'};
      } else if (_selectedType == 'temporary') {
        emancipation = {'type': 'date', 'value': ''};
      }

      await _coreService.createGuardianship(
        type: _selectedType!,
        dependentName: _dependentName,
        hostingType: _hostingType,
        emancipationTrigger: emancipation,
        metadata: metadata,
      );
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _creating = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560, maxHeight: 600),
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  Text(
                    _stepTitle(),
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context, false),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(_stepSubtitle(), style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
              const SizedBox(height: 24),

              // Step content
              Flexible(child: _buildStepContent()),

              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(_error!, style: TextStyle(color: AppColors.error, fontSize: 13)),
              ],

              // Navigation buttons
              const SizedBox(height: 24),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  if (_step > 0)
                    TextButton(
                      onPressed: () => setState(() => _step--),
                      child: const Text('Back'),
                    ),
                  const Spacer(),
                  if (_step < 3)
                    FilledButton(
                      onPressed: _canAdvance() ? () => setState(() => _step++) : null,
                      child: const Text('Next'),
                    ),
                  if (_step == 3)
                    FilledButton(
                      onPressed: _creating ? null : _create,
                      child: _creating
                          ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                          : const Text('Create'),
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _stepTitle() {
    switch (_step) {
      case 0: return 'Select Guardianship Type';
      case 1: return 'Dependent Information';
      case 2: return 'Identity Hosting';
      case 3: return 'Confirm';
      default: return '';
    }
  }

  String _stepSubtitle() {
    switch (_step) {
      case 0: return 'What type of guardianship relationship is this?';
      case 1: return 'Enter details about the dependent.';
      case 2: return 'Where will the dependent\'s Identity Agent instance be hosted?';
      case 3: return 'Review the details and create the guardianship.';
      default: return '';
    }
  }

  bool _canAdvance() {
    switch (_step) {
      case 0: return _selectedType != null;
      case 1: return _dependentName.isNotEmpty;
      case 2: return true;
      default: return false;
    }
  }

  Widget _buildStepContent() {
    switch (_step) {
      case 0: return _buildTemplateStep();
      case 1: return _buildInfoStep();
      case 2: return _buildHostingStep();
      case 3: return _buildConfirmStep();
      default: return const SizedBox.shrink();
    }
  }

  Widget _buildTemplateStep() {
    return SingleChildScrollView(
      child: Column(
        children: [
          _templateCard(
            type: 'minor_child',
            icon: Icons.child_care,
            title: 'Minor Child',
            description: 'For children under 18. You manage their identity until emancipation.',
          ),
          _templateCard(
            type: 'elderly',
            icon: Icons.elderly,
            title: 'Elderly Family Member',
            description: 'For aging parents or relatives who need help managing their identity.',
          ),
          _templateCard(
            type: 'disability',
            icon: Icons.accessible,
            title: 'Person with a Disability',
            description: 'For someone who needs ongoing assistance with identity decisions.',
          ),
          _templateCard(
            type: 'temporary',
            icon: Icons.timer_outlined,
            title: 'Temporary Guardianship',
            description: 'Time-limited. For medical events, travel, or short-term care.',
          ),
        ],
      ),
    );
  }

  Widget _templateCard({
    required String type,
    required IconData icon,
    required String title,
    required String description,
  }) {
    final isSelected = _selectedType == type;
    return InkWell(
      onTap: () => setState(() => _selectedType = type),
      borderRadius: BorderRadius.circular(12),
      child: Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected ? AppColors.primary : AppColors.border,
            width: isSelected ? 2 : 1,
          ),
          color: isSelected ? AppColors.primary.withOpacity(0.04) : Colors.transparent,
        ),
        child: Row(
          children: [
            Icon(icon, size: 28, color: isSelected ? AppColors.primary : AppColors.textSecondary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
                  const SizedBox(height: 4),
                  Text(description, style: TextStyle(fontSize: 12, color: AppColors.textMuted)),
                ],
              ),
            ),
            if (isSelected)
              Icon(Icons.check_circle, color: AppColors.primary, size: 22),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoStep() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        TextField(
          controller: _nameController,
          decoration: const InputDecoration(
            labelText: 'Full Name',
            hintText: 'Enter the dependent\'s name',
            border: OutlineInputBorder(),
          ),
          onChanged: (v) => setState(() => _dependentName = v.trim()),
        ),
        if (_selectedType == 'minor_child') ...[
          const SizedBox(height: 16),
          TextField(
            controller: _dobController,
            decoration: const InputDecoration(
              labelText: 'Date of Birth',
              hintText: 'YYYY-MM-DD',
              border: OutlineInputBorder(),
            ),
            onChanged: (v) => setState(() => _dateOfBirth = v.trim()),
          ),
        ],
      ],
    );
  }

  Widget _buildHostingStep() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        _hostingCard(
          type: 'cloud',
          icon: Icons.cloud_outlined,
          title: 'Cloud-hosted (Recommended)',
          description: 'Provision a dedicated Identity Agent instance via an Infrastructure Service Provider (default: Grape ID). Secure, isolated, TEE-backed.',
        ),
        _hostingCard(
          type: 'device',
          icon: Icons.phone_android_outlined,
          title: 'Separate physical device',
          description: 'The dependent already has a phone, laptop, or desktop with Identity Agent installed. You will pair via OOBI exchange.',
        ),
      ],
    );
  }

  Widget _hostingCard({
    required String type,
    required IconData icon,
    required String title,
    required String description,
  }) {
    final isSelected = _hostingType == type;
    return InkWell(
      onTap: () => setState(() => _hostingType = type),
      borderRadius: BorderRadius.circular(12),
      child: Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected ? AppColors.primary : AppColors.border,
            width: isSelected ? 2 : 1,
          ),
          color: isSelected ? AppColors.primary.withOpacity(0.04) : Colors.transparent,
        ),
        child: Row(
          children: [
            Icon(icon, size: 28, color: isSelected ? AppColors.primary : AppColors.textSecondary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
                  const SizedBox(height: 4),
                  Text(description, style: TextStyle(fontSize: 12, color: AppColors.textMuted)),
                ],
              ),
            ),
            if (isSelected)
              Icon(Icons.check_circle, color: AppColors.primary, size: 22),
          ],
        ),
      ),
    );
  }

  Widget _buildConfirmStep() {
    final typeLabel = {
      'minor_child': 'Minor Child',
      'elderly': 'Elderly Family Member',
      'disability': 'Person with a Disability',
      'temporary': 'Temporary Guardianship',
    }[_selectedType] ?? _selectedType ?? '';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        _confirmRow('Type', typeLabel),
        _confirmRow('Dependent Name', _dependentName),
        if (_dateOfBirth.isNotEmpty) _confirmRow('Date of Birth', _dateOfBirth),
        _confirmRow('Hosting', _hostingType == 'cloud' ? 'Cloud-hosted (Grape ID)' : 'Separate device'),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppColors.primary.withOpacity(0.06),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppColors.primary.withOpacity(0.2)),
          ),
          child: Row(
            children: [
              Icon(Icons.info_outline, size: 18, color: AppColors.primary),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  _hostingType == 'cloud'
                      ? 'A dedicated Identity Agent instance will be provisioned via your configured Infrastructure Service Provider.'
                      : 'After creation, you will need to pair with the dependent\'s device via OOBI exchange.',
                  style: TextStyle(fontSize: 12, color: AppColors.textSecondary),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _confirmRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        children: [
          SizedBox(
            width: 140,
            child: Text(label, style: TextStyle(color: AppColors.textMuted, fontSize: 13)),
          ),
          Expanded(
            child: Text(value, style: const TextStyle(fontWeight: FontWeight.w500, fontSize: 13)),
          ),
        ],
      ),
    );
  }
}
