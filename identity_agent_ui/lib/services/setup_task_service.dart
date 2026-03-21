import 'package:shared_preferences/shared_preferences.dart';
import 'preferences_service.dart';

enum SetupTask {
  connectRemoteBrain,
  backupSeedPhrase,
  setupAuthentication,
  secureKeyStorage,
  inviteContacts,
  connectEmail,
  addPhoneNumber,
  completeProfile,
  getVerified,
}

class SetupTaskMeta {
  final SetupTask task;
  final String title;
  final String description;
  final bool isStub;  // true = navigates to placeholder screen
  final bool isCritical;

  const SetupTaskMeta({
    required this.task,
    required this.title,
    required this.description,
    this.isStub = false,
    this.isCritical = false,
  });
}

// Static metadata for all tasks
const _allTaskMeta = <SetupTask, SetupTaskMeta>{
  SetupTask.connectRemoteBrain: SetupTaskMeta(
    task: SetupTask.connectRemoteBrain,
    title: 'Connect your remote brain',
    description:
        'Your identity needs a remote server to unlock email, phone, and advanced features.',
    isStub: false,
    isCritical: true,
  ),
  SetupTask.backupSeedPhrase: SetupTaskMeta(
    task: SetupTask.backupSeedPhrase,
    title: 'Back up your seed phrase',
    description:
        'Write down your 12 words or save them to an NFC tag. Without this backup, you cannot recover your identity.',
    isStub: false,
    isCritical: true,
  ),
  SetupTask.setupAuthentication: SetupTaskMeta(
    task: SetupTask.setupAuthentication,
    title: 'Set up app authentication',
    description:
        'Add a PIN or biometrics so only you can open this app.',
    isStub: true,
    isCritical: true,
  ),
  SetupTask.secureKeyStorage: SetupTaskMeta(
    task: SetupTask.secureKeyStorage,
    title: 'Secure your signing keys',
    description:
        'Protect your identity keys with the strongest security available on this device.',
    isStub: false,
    isCritical: true,
  ),
  SetupTask.inviteContacts: SetupTaskMeta(
    task: SetupTask.inviteContacts,
    title: 'Invite contacts',
    description:
        'Trusted contacts help verify your identity and can help you recover access if you get locked out. Aim for at least 3.',
    isStub: false,
    isCritical: true,
  ),
  SetupTask.connectEmail: SetupTaskMeta(
    task: SetupTask.connectEmail,
    title: 'Connect email',
    description:
        'Link your email address to enable identity-verified communications.',
    isStub: true,
    isCritical: false,
  ),
  SetupTask.addPhoneNumber: SetupTaskMeta(
    task: SetupTask.addPhoneNumber,
    title: 'Add phone number',
    description:
        'Add your phone number for SMS-based verification and recovery.',
    isStub: true,
    isCritical: false,
  ),
  SetupTask.completeProfile: SetupTaskMeta(
    task: SetupTask.completeProfile,
    title: 'Complete your profile',
    description:
        'Add your bio, organization, and title so contacts know who you are.',
    isStub: false,
    isCritical: false,
  ),
  SetupTask.getVerified: SetupTaskMeta(
    task: SetupTask.getVerified,
    title: 'Get verified',
    description:
        'Add someone you know personally as a trusted contact. This establishes your first real-world identity relationship.',
    isStub: false,
    isCritical: false,
  ),
};

class SetupTaskService {
  static const String _prefix = 'setup_task_';
  static const String _checklistDismissedKey = 'setup_checklist_dismissed';

  static SetupTaskMeta meta(SetupTask task) => _allTaskMeta[task]!;

  /// Returns the ordered task list, filtering out connectRemoteBrain
  /// if it was already connected (remoteBrainUrl is set) or not applicable.
  static List<SetupTask> orderedTasks({
    required bool needsRemoteBrain,
    bool includeSecureKeyStorage = true,
  }) {
    final all = [
      if (needsRemoteBrain) SetupTask.connectRemoteBrain,
      SetupTask.backupSeedPhrase,
      SetupTask.setupAuthentication,
      if (includeSecureKeyStorage) SetupTask.secureKeyStorage,
      SetupTask.inviteContacts,
      SetupTask.connectEmail,
      SetupTask.addPhoneNumber,
      SetupTask.completeProfile,
      SetupTask.getVerified,
    ];
    return all;
  }

  static Future<SharedPreferences> get _prefs =>
      SharedPreferences.getInstance();

  static Future<bool> isComplete(SetupTask task) async {
    final prefs = await _prefs;
    return prefs.getBool('$_prefix${task.name}') ?? false;
  }

  static Future<void> markComplete(SetupTask task) async {
    final prefs = await _prefs;
    await prefs.setBool('$_prefix${task.name}', true);
  }

  static Future<void> markIncomplete(SetupTask task) async {
    final prefs = await _prefs;
    await prefs.remove('$_prefix${task.name}');
  }

  /// Returns a map of task → isComplete for all tasks in the given list.
  static Future<Map<SetupTask, bool>> loadState(
      List<SetupTask> tasks) async {
    final prefs = await _prefs;
    return {
      for (final t in tasks)
        t: prefs.getBool('$_prefix${t.name}') ?? false,
    };
  }

  /// How many critical tasks are still incomplete.
  static Future<int> criticalTasksRemaining(
      {required bool needsRemoteBrain}) async {
    final tasks = orderedTasks(needsRemoteBrain: needsRemoteBrain);
    final state = await loadState(tasks);
    return tasks
        .where((t) => meta(t).isCritical && !(state[t] ?? false))
        .length;
  }

  static Future<bool> isChecklistDismissed() async {
    final prefs = await _prefs;
    return prefs.getBool(_checklistDismissedKey) ?? false;
  }

  static Future<void> dismissChecklist() async {
    final prefs = await _prefs;
    await prefs.setBool(_checklistDismissedKey, true);
  }

  /// Pre-mark tasks that are already done based on onboarding state.
  static Future<void> applyOnboardingDefaults({
    required bool backupVerified,
    required bool contactsInvited,
    required bool remoteBrainConnected,
  }) async {
    if (backupVerified) await markComplete(SetupTask.backupSeedPhrase);
    if (contactsInvited) await markComplete(SetupTask.inviteContacts);
    if (remoteBrainConnected) {
      await markComplete(SetupTask.connectRemoteBrain);
    }
  }
}
