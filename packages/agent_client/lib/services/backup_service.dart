import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import '../crypto/owner_signature.dart';
import 'the_agent_this_app_talks_to.dart';

class BackupDestination {
  final String id;
  final String type;
  final String label;
  final String? localPath;
  final String? pairedUrl;
  final bool iaGated;
  final bool enabled;
  final String? lastSuccessAt;
  final String? lastError;

  /// Whether the owner has said this destination is not in the same place as
  /// the machine backing up to it.
  ///
  /// Only a person can answer it. The agent knows what KIND of thing a
  /// destination is and never where it physically sits, so a machine at a
  /// relative's house and one on the same desk look identical to it — and two
  /// copies in one room is a copy, not a backup, however healthy everything
  /// else looks.
  final bool elsewhere;

  BackupDestination({
    required this.id,
    required this.type,
    required this.label,
    this.localPath,
    this.pairedUrl,
    this.iaGated = false,
    this.enabled = true,
    this.elsewhere = false,
    this.lastSuccessAt,
    this.lastError,
  });

  factory BackupDestination.fromJson(Map<String, dynamic> json) {
    return BackupDestination(
      id: json['id'] ?? '',
      type: json['type'] ?? '',
      label: json['label'] ?? '',
      localPath: json['local_path'],
      pairedUrl: json['paired_url'],
      iaGated: json['ia_gated'] ?? false,
      enabled: json['enabled'] ?? true,
      elsewhere: json['elsewhere'] ?? false,
      lastSuccessAt: json['last_success_at'],
      lastError: json['last_error'],
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type,
        'label': label,
        if (localPath != null) 'local_path': localPath,
        if (pairedUrl != null) 'paired_url': pairedUrl,
        'ia_gated': iaGated,
        // Sent back deliberately. This map is a whitelist and the agent
        // decodes onto what it has stored, so a field left out of it is one
        // the owner can never change — and for this one, only they can
        // answer it at all.
        'elsewhere': elsewhere,
        'enabled': enabled,
      };
}

/// One backup run, as the core recorded it.
class BackupRun {
  final String id;
  final String timestamp;
  final int sizeBytes;
  final String snapshotType;
  final bool success;
  final List<String> destinations;
  final String? error;

  /// This archive was reopened and its contents checked before it was kept.
  /// A run without it succeeded at making a file, which is a different claim.
  final bool verified;

  /// It reached somewhere losing this device does not reach.
  final bool offDevice;

  /// It restores on its own. An incremental one does not, however recent.
  final bool selfSufficient;

  BackupRun({
    required this.id,
    required this.timestamp,
    required this.sizeBytes,
    required this.snapshotType,
    required this.success,
    required this.destinations,
    this.error,
    this.verified = false,
    this.offDevice = false,
    this.selfSufficient = false,
  });

  factory BackupRun.fromJson(Map<String, dynamic> json) => BackupRun(
        id: json['id'] ?? '',
        timestamp: json['timestamp'] ?? '',
        sizeBytes: json['size_bytes'] ?? 0,
        snapshotType: json['snapshot_type'] ?? '',
        success: json['success'] ?? false,
        destinations: List<String>.from(json['destinations'] ?? const []),
        error: json['error'],
        verified: json['verified'] ?? false,
        offDevice: json['off_device'] ?? false,
        selfSufficient: json['self_sufficient'] ?? false,
      );
}

class BackupStatus {
  final bool enabled;
  final String? lastBackupAt;
  final String health;
  final List<BackupDestination> destinations;
  final String? redundancyWarning;
  final String? antiDeadlockWarning;
  final int consecutiveFailures;

  /// The most recent archive that was reopened and proven to open.
  ///
  /// Null means no archive has ever been proven to open — which is not the
  /// same as no archive existing, and is the more alarming of the two.
  final String? lastVerifiedAt;

  /// The most recent archive that reached somewhere the loss of this device
  /// does not reach. Null means every archive ever made is on the machine
  /// that made it, which is a copy rather than a backup.
  final String? lastOffDeviceAt;

  /// What is missing, in the core's own plain words, or null when nothing is.
  final String? protection;

  /// What a fire, a burglary or a flood in one place would take, or null when
  /// something would survive it.
  ///
  /// Its own field beside [protection] rather than folded into it, because
  /// they answer different questions — losing a machine, losing a room — and
  /// somebody can be fine on the first and ruined on the second. It also
  /// carries the reason health goes yellow in the commonest arrangement there
  /// is: a paired machine becomes a destination on its own, and two machines
  /// in one room is what most people will have.
  final String? localDisaster;

  final List<BackupRun> history;

  BackupStatus({
    required this.enabled,
    this.lastBackupAt,
    required this.health,
    required this.destinations,
    this.redundancyWarning,
    this.antiDeadlockWarning,
    this.consecutiveFailures = 0,
    this.lastVerifiedAt,
    this.lastOffDeviceAt,
    this.protection,
    this.localDisaster,
    this.history = const [],
  });

  /// Whether anything at all has ever been backed up. Distinguishes "not set
  /// up" from "set up and failing", which look identical if you only read
  /// [health] and are the opposite of each other to act on.
  bool get everRan => (lastBackupAt ?? '').isNotEmpty;

  /// Whether this is genuinely good news right now.
  ///
  /// All three things must have happened AND the agent must still grade it
  /// green. Presence alone is a claim about the past.
  bool get isReassuring =>
      everRan &&
      (lastOffDeviceAt ?? '').isNotEmpty &&
      (lastVerifiedAt ?? '').isNotEmpty &&
      agentSaysHealthy;

  /// Whether the agent itself considers this healthy.
  ///
  /// The three facts below say whether something ever happened; HEALTH says
  /// whether it is still true. The agent grades red on three consecutive
  /// failures, red when nothing has left this device in 72 hours, and yellow
  /// when nothing has been checked in a week — none of which presence can see.
  ///
  /// Without this the summary was computed from presence alone, so an identity
  /// whose every destination had been failing for months, with an off-device
  /// copy six months stale, read as "backed up, off this device, and checked
  /// that it opens". The agent was saying red the whole time and nothing asked.
  bool get agentSaysHealthy => health == 'green';

  /// The one sentence this status is worth. Written here rather than in each
  /// screen so both apps say the same true thing, and so no screen can
  /// accidentally summarise a red status optimistically.
  String get plainSummary {
    if (!everRan) {
      return enabled
          ? 'Backup is on, and nothing has been written yet'
          : 'Not set up yet - no backup has been made';
    }
    if ((lastOffDeviceAt ?? '').isEmpty) {
      return 'Backed up, but only onto this device';
    }
    if ((lastVerifiedAt ?? '').isEmpty) {
      return 'Backed up off this device, never checked that it opens';
    }
    // Everything has happened at least once. Whether it is still true is a
    // different question, and it is the agent's to answer.
    if (health == 'red') {
      return consecutiveFailures > 0
          ? 'Backed up before, but the last $consecutiveFailures attempts failed'
          : 'Backed up before, but not recently enough to rely on';
    }
    if (health == 'yellow') {
      return 'Backed up, and it has been a while since that was checked';
    }
    return 'Backed up, off this device, and checked that it opens';
  }

  factory BackupStatus.fromJson(Map<String, dynamic> json) {
    return BackupStatus(
      enabled: json['enabled'] ?? false,
      lastBackupAt: json['last_backup_at'],
      health: json['health'] ?? 'red',
      destinations: (json['destinations'] as List<dynamic>? ?? [])
          .map((d) => BackupDestination.fromJson(d as Map<String, dynamic>))
          .toList(),
      redundancyWarning: json['redundancy_warning'],
      antiDeadlockWarning: json['anti_deadlock_warning'],
      consecutiveFailures: json['consecutive_failures'] ?? 0,
      lastVerifiedAt: json['last_verified_at'],
      lastOffDeviceAt: json['last_off_device_at'],
      protection: json['protection'],
      localDisaster: json['local_disaster'],
      history: (json['history'] as List<dynamic>? ?? const [])
          .map((h) => BackupRun.fromJson(h as Map<String, dynamic>))
          .toList(),
    );
  }
}

class BackupConfig {
  bool enabled;
  List<String> defaultTiers;
  List<BackupDestination> destinations;
  bool scheduleDaily;
  bool wifiOnlyTier23;
  String recoveryPreset;

  BackupConfig({
    this.enabled = false,
    this.defaultTiers = const ['tier1', 'tier2'],
    this.destinations = const [],
    this.scheduleDaily = true,
    this.wifiOnlyTier23 = true,
    this.recoveryPreset = 'seed',
  });

  factory BackupConfig.fromJson(Map<String, dynamic> json) {
    return BackupConfig(
      enabled: json['enabled'] ?? false,
      defaultTiers: List<String>.from(json['default_tiers'] ?? ['tier1', 'tier2']),
      destinations: (json['destinations'] as List<dynamic>? ?? [])
          .map((d) => BackupDestination.fromJson(d as Map<String, dynamic>))
          .toList(),
      scheduleDaily: json['schedule_daily'] ?? true,
      wifiOnlyTier23: json['wifi_only_tier23'] ?? true,
      recoveryPreset: json['recovery_preset'] ?? 'seed',
    );
  }

  Map<String, dynamic> toJson() => {
        'enabled': enabled,
        'default_tiers': defaultTiers,
        'destinations': destinations.map((d) => d.toJson()).toList(),
        'schedule_daily': scheduleDaily,
        'wifi_only_tier23': wifiOnlyTier23,
        'recovery_preset': recoveryPreset,
      };
}

/// What one machine holds for one other identity.
///
/// Metadata and nothing else, deliberately. Somebody hosting archives needs to
/// manage disk and notice a backup that stopped arriving; they must never be
/// able to read what they hold.
class HeldArchives {
  final String identityAid;
  final int archives;
  final int totalBytes;

  /// When the last archive arrived. What makes a stalled backup visible - an
  /// identity that stopped pushing months ago looks exactly like a healthy one
  /// if all you show is a count.
  final String? lastArrivedAt;

  HeldArchives({
    required this.identityAid,
    required this.archives,
    required this.totalBytes,
    this.lastArrivedAt,
  });

  factory HeldArchives.fromJson(Map<String, dynamic> json) => HeldArchives(
        identityAid: json['identity_aid'] ?? '',
        archives: json['archives'] ?? 0,
        totalBytes: json['total_bytes'] ?? 0,
        lastArrivedAt: json['last_arrived_at'],
      );
}

/// What this machine has volunteered to hold for other identities.
class HoldingOffer {
  /// Whether it holds anything for anyone. False until somebody says otherwise,
  /// so a machine never starts holding strangers' data by being upgraded.
  final bool accepting;

  /// Whether it takes on identities it does not already hold. Separate from
  /// [accepting] on purpose: turning this off must not stop the deltas of
  /// somebody already relying on this machine, or they are left with a
  /// destination that holds only their first archive.
  final bool acceptingNewIdentities;

  /// Disk this machine will not fill with other people's archives. Hosting a
  /// backup is a favour and must not cost somebody a working computer.
  final int reserveBytes;

  const HoldingOffer({
    this.accepting = false,
    this.acceptingNewIdentities = false,
    this.reserveBytes = 5 * 1024 * 1024 * 1024,
  });

  factory HoldingOffer.fromJson(Map<String, dynamic> json) => HoldingOffer(
        accepting: json['accepting'] ?? false,
        acceptingNewIdentities: json['accepting_new_identities'] ?? false,
        reserveBytes: json['reserve_bytes'] ?? 5 * 1024 * 1024 * 1024,
      );

  Map<String, dynamic> toJson() => {
        'accepting': accepting,
        'accepting_new_identities': acceptingNewIdentities,
        'reserve_bytes': reserveBytes,
      };

  HoldingOffer copyWith({
    bool? accepting,
    bool? acceptingNewIdentities,
    int? reserveBytes,
  }) =>
      HoldingOffer(
        accepting: accepting ?? this.accepting,
        acceptingNewIdentities:
            acceptingNewIdentities ?? this.acceptingNewIdentities,
        reserveBytes: reserveBytes ?? this.reserveBytes,
      );
}

class BackupService {
  /// The agent, not this computer.
  ///
  /// An archive is of the IDENTITY, so it is made and read where the identity
  /// is. In controller mode the local core holds none, and every call here
  /// would have described an empty agent as though it were the person's.
  static String get _agent => TheAgentThisAppTalksTo.origin;
  static String get _base => '$_agent/api/backup';
  static String get _recovery => '$_agent/api/recovery';

  /// A client that proves who is asking.
  ///
  /// Backup routes are owner-only, and the top-level http functions used here
  /// before sent nothing — so on an agent reached over a network every one of
  /// these was correctly refused, which is the state this whole class was
  /// unusable in.
  static http.Client get _client => TheAgentThisAppTalksTo.clientFor(_agent);

  /// Who holds a share of this identity's recovery.
  static Future<WhoHoldsYourRecovery> getWhoHoldsYourRecovery() async {
    final resp = await _client.get(Uri.parse('$_recovery/who-holds-this'));
    if (resp.statusCode != 200) {
      throw Exception('Could not read who holds your recovery: ${resp.statusCode}');
    }
    return WhoHoldsYourRecovery.fromJson(jsonDecode(resp.body));
  }

  /// Records who holds a share, and answers with what that choice costs.
  ///
  /// A refusal comes back as the agent's own sentence rather than a status
  /// code, because everything refused here is refused for a reason somebody
  /// can act on — a threshold nobody could ever satisfy, a holder named at an
  /// email address, a passphrase standing alone. Showing "400" instead would
  /// throw away the only useful part.
  static Future<WhoHoldsYourRecovery> setWhoHoldsYourRecovery(
      WhoHoldsYourRecovery choice) async {
    final resp = await _client.put(
      Uri.parse('$_recovery/who-holds-this'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(choice.toJson()),
    );
    if (resp.statusCode != 200) {
      throw Exception(_whyItWasRefused(resp.body, resp.statusCode));
    }
    return WhoHoldsYourRecovery.fromJson(jsonDecode(resp.body));
  }

  /// The agent's own explanation, or something honest when there is not one.
  static String _whyItWasRefused(String body, int status) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map) {
        for (final key in ['details', 'detail', 'error']) {
          final v = decoded[key];
          if (v is String && v.isNotEmpty) return v;
        }
      }
    } catch (_) {
      // Falls through to the status, which is all there is to say.
    }
    return 'Your Identity Agent would not save this setting ($status).';
  }

  static Future<BackupStatus> getStatus() async {
    final resp = await _client.get(Uri.parse('$_base/status'));
    if (resp.statusCode != 200) {
      throw Exception('Backup status failed: ${resp.statusCode}');
    }
    return BackupStatus.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  static Future<BackupConfig> getConfig() async {
    final resp = await _client.get(Uri.parse('$_base/config'));
    if (resp.statusCode != 200) throw Exception('Load config failed');
    return BackupConfig.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  static Future<void> saveConfig(BackupConfig config) async {
    final resp = await _client.put(
      Uri.parse('$_base/config'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(config.toJson()),
    );
    if (resp.statusCode != 200) throw Exception('Save config failed');
  }

  /// Takes a backup.
  ///
  /// Deliberately does not send the recovery phrase, and no longer accepts one.
  /// A delegated device seals to the recovery public keys it was given at
  /// pairing; a root device reads its own wrapped seed off disk. Sending the
  /// words would put a second copy of the identity on the wire and derive the
  /// same key that would have been derived anyway.
  static Future<Map<String, dynamic>> exportNow({
    String? passphrase,
    List<String>? tiers,
    String? destPath,
  }) async {
    final resp = await _client.post(
      Uri.parse('$_base/export'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        if (passphrase != null) 'passphrase': passphrase,
        if (tiers != null) 'tiers': tiers,
        if (destPath != null) 'dest_path': destPath,
      }),
    );
    if (resp.statusCode != 200) {
      final body = resp.body;
      throw Exception('Export failed: $body');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  static Future<void> addDestination(BackupDestination dest) async {
    final resp = await _client.post(
      Uri.parse('$_base/destinations'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'destination': dest.toJson()}),
    );
    if (resp.statusCode != 200) throw Exception('Add destination failed');
  }

  static Future<void> removeDestination(String id) async {
    final resp = await _client
        .delete(Uri.parse('$_base/destinations/${Uri.encodeComponent(id)}'));
    // 204 is what this route actually answers. Checking only for 200 threw on
    // every successful removal, so somebody saw "could not remove that
    // destination" having just removed it - and would reasonably try again.
    if (resp.statusCode != 204 && resp.statusCode != 200) {
      throw Exception('Could not remove that destination: ${resp.body}');
    }
  }

  /// Turns backup on, and starts the daily schedule.
  ///
  /// This is the switch nothing in either app could reach. Backup shipped
  /// `enabled: false` with no caller anywhere that set it true, so the whole
  /// subsystem was unreachable by design rather than by oversight — every
  /// other route worked and none of them would ever be called on a timer.
  ///
  /// Reads the config first and writes it back changed, rather than sending a
  /// fresh one: a blank config would silently drop the destinations somebody
  /// had already added.
  static Future<void> turnOn({bool daily = true}) async {
    final cfg = await getConfig();
    cfg.enabled = true;
    cfg.scheduleDaily = daily;
    await saveConfig(cfg);
  }

  static Future<void> turnOff() async {
    final cfg = await getConfig();
    cfg.enabled = false;
    await saveConfig(cfg);
  }

  /// Asks for a backup on the schedule's terms - debounced by five minutes.
  ///
  /// This is NOT "back up now"; [exportNow] is. The distinction matters on a
  /// button, because a person who taps something labelled "back up now" and is
  /// told "scheduled" will go and check, find nothing, and conclude it is
  /// broken.
  ///
  /// Throws [BackupImpossible] when the agent has no way to reach its own root
  /// seed. The core checks that before answering rather than reporting
  /// "scheduled" for a run that will skip quietly minutes later.
  static Future<void> requestScheduledRun() async {
    final resp = await _client.post(Uri.parse('$_base/trigger'));
    if (resp.statusCode == 409) {
      throw BackupImpossible(_detailOf(resp.body));
    }
    if (resp.statusCode != 200) throw Exception('Trigger failed: ${resp.body}');
  }

  /// Fetches back what a destination is holding, for a restore.
  static Future<Map<String, dynamic>> pullFrom(String destId) async {
    final resp = await _client.post(Uri.parse('$_base/pull/$destId'));
    if (resp.statusCode != 200) {
      throw Exception('Could not fetch from that destination: ${resp.body}');
    }
    return jsonDecode(resp.body) as Map<String, dynamic>;
  }

  /// What this machine is holding for one identity you already know of.
  static Future<List<dynamic>> whatThisMachineHoldsFor(String identityAid) async {
    final resp = await _client.get(Uri.parse('$_base/receive/${Uri.encodeComponent(identityAid)}'));
    if (resp.statusCode != 200) {
      throw Exception('Could not list what is held: ${resp.body}');
    }
    final body = jsonDecode(resp.body);
    if (body is List) return body;
    return (body as Map<String, dynamic>)['archives'] as List<dynamic>? ??
        const [];
  }

  /// Everything this machine holds, for every identity.
  ///
  /// The question the person who owns the hardware actually has, and the one
  /// that could not be asked: the older route needed an identity you already
  /// knew of, so nothing could answer "what is this machine holding".
  ///
  /// Metadata only. There is no route that returns contents - the archives are
  /// sealed to keys this machine does not hold, which is the whole arrangement.
  static Future<List<HeldArchives>> whatThisMachineHolds() async {
    final resp = await _client.get(Uri.parse('$_base/held'));
    if (resp.statusCode != 200) {
      throw Exception('Could not read what this machine holds: ${resp.body}');
    }
    final body = jsonDecode(resp.body) as Map<String, dynamic>;
    return (body['held'] as List<dynamic>? ?? const [])
        .map((h) => HeldArchives.fromJson(h as Map<String, dynamic>))
        .toList();
  }

  /// What this machine has volunteered to hold for others.
  static Future<HoldingOffer> readOffer() async {
    final resp = await _client.get(Uri.parse('$_base/offer'));
    if (resp.statusCode != 200) throw Exception('Could not read the offer');
    return HoldingOffer.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  /// Volunteers this machine, or stops volunteering it.
  static Future<HoldingOffer> setOffer(HoldingOffer offer) async {
    final resp = await _client.put(
      Uri.parse('$_base/offer'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(offer.toJson()),
    );
    if (resp.statusCode != 200) {
      throw Exception('Could not change what this machine offers: ${resp.body}');
    }
    return HoldingOffer.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
  }

  /// Removes everything this machine holds for one identity.
  ///
  /// The identity is NOT told by this call, and nothing else tells it either.
  /// Whoever calls this owes them that, or leaves an agent believing it has an
  /// off-site copy it no longer has.
  static Future<void> stopHoldingFor(String identityAid) async {
    final resp = await _client.delete(Uri.parse('$_base/held/${Uri.encodeComponent(identityAid)}'));
    if (resp.statusCode != 204 && resp.statusCode != 200) {
      throw Exception('Could not remove those archives: ${resp.body}');
    }
  }

  /// Pulls the core's own sentence out of an error body, so the reason a
  /// person is shown is the one the core actually gave rather than a status
  /// code dressed up as an explanation.
  static String _detailOf(String body) {
    try {
      final m = jsonDecode(body) as Map<String, dynamic>;
      final detail = (m['detail'] ?? m['error'] ?? m['message'] ?? '') as String;
      if (detail.isNotEmpty) return detail;
    } catch (_) {
      // Not JSON. Fall through to the raw body, which is still better than
      // inventing a message.
    }
    return body;
  }
}

/// This agent cannot take a backup at all, and the core said why.
///
/// Distinct from a failure, because nothing was attempted and retrying changes
/// nothing. The usual cause is an agent with no route to its own root seed.
class BackupImpossible implements Exception {
  final String reason;
  BackupImpossible(this.reason);
  @override
  String toString() => reason;
}
/// Who holds a share of this identity's recovery, and what that choice costs.
///
/// The recovery words alone used to open a backup, so anybody holding both
/// read everything in it — offline, with their own code, and with nothing to
/// notice it. A share is one piece of a second key, held by one person or one
/// machine, and useless on its own.
class WhoHoldsYourRecovery {
  /// How many shares must come back before a backup opens. Zero with no
  /// holders means the recovery words alone, which is a real answer.
  final int needed;
  final List<ShareHolder> holders;

  /// What the agent says this choice costs, in the agent's own words.
  ///
  /// Shown verbatim and never rewritten here. Both apps ask the same question
  /// and must give the same answer, and working out what a threshold of one
  /// means is not a thing to reimplement twice.
  final String sayThis;

  WhoHoldsYourRecovery({
    required this.needed,
    required this.holders,
    this.sayThis = '',
  });

  factory WhoHoldsYourRecovery.fromJson(Map<String, dynamic> json) =>
      WhoHoldsYourRecovery(
        needed: json['needed'] ?? 0,
        holders: ((json['holders'] as List?) ?? [])
            .map((h) => ShareHolder.fromJson(h as Map<String, dynamic>))
            .toList(),
        sayThis: json['say_this'] ?? '',
      );

  Map<String, dynamic> toJson() => {
        'needed': needed,
        'holders': holders.map((h) => h.toJson()).toList(),
      };
}

/// One person or machine holding a share.
class ShareHolder {
  /// How this holder is named — its own identifier, never an email address or
  /// a phone number. A holder reachable only at a handle is one an attacker
  /// can take over, and a recovery approved through a hijacked mailbox looks
  /// exactly like a genuine one.
  final String id;

  /// 'witness' for a person, 'device' for one of the owner's own machines,
  /// 'passphrase' for something they know. For what the screen says rather
  /// than for how any of it works.
  final String kind;
  final String publicKeyB64;
  final String address;

  ShareHolder({
    required this.id,
    required this.kind,
    required this.publicKeyB64,
    this.address = '',
  });

  factory ShareHolder.fromJson(Map<String, dynamic> json) => ShareHolder(
        id: json['id'] ?? '',
        kind: json['kind'] ?? '',
        publicKeyB64: json['public_key_b64'] ?? '',
        address: json['address'] ?? '',
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'kind': kind,
        'public_key_b64': publicKeyB64,
        if (address.isNotEmpty) 'address': address,
      };
}

/// Setting up the machines somebody already has as share holders.
///
/// This lives in the app rather than in the agent, and that is not an
/// arrangement anybody chose for convenience. Asking a machine to hold a share
/// is owner-only, and THE AGENT CORE CANNOT PROVE IT IS THE OWNER: the root
/// identity's key belongs to whatever the person carries, and the core refuses
/// to sign as the root precisely so that it cannot claim an authority it does
/// not have. So the request has to be made by the thing holding that key.
///
/// The agent says which machines exist; this signs and asks each one; the
/// answers go back as the choice. Three steps, each in the place that can
/// actually do it.
class RecoveryHolderSetup {
  /// Asks every paired machine to hold a share, and records those that agreed.
  ///
  /// A machine that refuses or cannot be reached is left out rather than
  /// failing the whole thing — it is one holder fewer, which a threshold is
  /// built to survive, and refusing to set anything up because a laptop was
  /// closed would be the worse outcome by a distance. What went wrong with
  /// each one comes back so a screen can say so, because a holder silently
  /// missing from a backup is discovered during a recovery and not before.
  static Future<HolderSetupResult> enrolPairedMachines({
    required Uint8List ownerSeed,
    required String identityAid,
    int waitHours = 0,
    bool requireApproval = false,
  }) async {
    final machines = await _pairedMachines();
    final holders = <ShareHolder>[];
    final couldNotAsk = <String, String>{};

    for (final m in machines) {
      final url = (m['url'] ?? '') as String;
      final aid = (m['aid'] ?? '') as String;
      if (url.isEmpty || aid.isEmpty) {
        couldNotAsk[aid.isEmpty ? '(unnamed machine)' : aid] =
            'there is no address to reach this machine at';
        continue;
      }
      try {
        final key = await _askOneMachine(
          url: url,
          ownerSeed: ownerSeed,
          // One of the owner's OWN machines files the holding under this
          // identity's AID: it already knows whose machine it is, so an
          // identifier made to hide that would hide nothing from it. Somebody
          // else's machine is the case that needs one.
          identityAid: identityAid,
          holderId: aid,
          waitHours: waitHours,
          requireApproval: requireApproval,
        );
        holders.add(ShareHolder(
          id: aid,
          kind: 'device',
          publicKeyB64: key,
          address: url,
        ));
      } catch (e) {
        couldNotAsk[aid] = _plainly(e);
      }
    }
    return HolderSetupResult(holders: holders, couldNotAsk: couldNotAsk);
  }

  /// Which machines are paired, read from the agent — a fact about the
  /// identity, so it is asked where the identity is, with something that proves
  /// who is asking.
  static Future<List<Map<String, dynamic>>> _pairedMachines() async {
    final resp = await TheAgentThisAppTalksTo.clientFor()
        .get(Uri.parse('${TheAgentThisAppTalksTo.origin}/api/pairing/agents'));
    if (resp.statusCode != 200) {
      throw Exception('Could not read which machines are paired.');
    }
    final decoded = jsonDecode(resp.body);
    final list = decoded is List ? decoded : (decoded['agents'] as List? ?? []);
    return list.cast<Map<String, dynamic>>();
  }

  static Future<String> _askOneMachine({
    required String url,
    required Uint8List ownerSeed,
    required String identityAid,
    required String holderId,
    required int waitHours,
    required bool requireApproval,
  }) async {
    const path = '/api/recovery/holdings';
    final body = utf8.encode(jsonEncode({
      'identity_aid': identityAid,
      'holder_id': holderId,
      'policy': {'wait_hours': waitHours, 'require_approval': requireApproval},
    }));

    // A plain client, deliberately. This asks SOMEBODY ELSE'S machine, not
    // this identity's agent, and it carries its own owner signature below. A
    // client built for the agent would pass this through untouched anyway,
    // which would work and would say the wrong thing about what is going on.
    final resp = await http.post(
      Uri.parse('${url.replaceAll(RegExp(r'/+$'), '')}$path'),
      headers: {
        'Content-Type': 'application/json',
        // What proves the owner asked. Without it a machine across a network
        // answers 403 — correctly, because from its side the request is
        // indistinguishable from a stranger's.
        ...OwnerSignature.headers(
          method: 'POST',
          path: path,
          body: body,
          ownerSeed: ownerSeed,
        ),
      },
      body: body,
    );
    if (resp.statusCode == 403 || resp.statusCode == 401) {
      throw Exception('this machine did not accept your signature');
    }
    if (resp.statusCode != 200) {
      throw Exception('this machine did not agree to hold a share');
    }
    final key = (jsonDecode(resp.body)['public_key_b64'] ?? '') as String;
    if (key.isEmpty) {
      // Without a key there is nothing to seal a share to, and carrying on
      // would record a holder that could never take part.
      throw Exception('this machine agreed but gave no key');
    }
    return key;
  }

  /// What to show somebody, with no address, port or errno in it.
  static String _plainly(Object e) {
    final s = e.toString().replaceFirst('Exception: ', '');
    if (s.contains('SocketException') ||
        s.contains('Connection') ||
        s.contains('127.0.0.1')) {
      return 'this machine could not be reached';
    }
    return s;
  }
}

/// What came back from asking the machines somebody already has.
class HolderSetupResult {
  final List<ShareHolder> holders;

  /// Which machines are not holding a share, and why — keyed by machine.
  final Map<String, String> couldNotAsk;

  HolderSetupResult({required this.holders, required this.couldNotAsk});
}
