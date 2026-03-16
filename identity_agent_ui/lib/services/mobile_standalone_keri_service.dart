import 'keri_service.dart';
import 'mobile_core_service.dart';
import '../bridge/keri_bridge_stub.dart'
    if (dart.library.io) '../bridge/keri_bridge.dart';

class MobileStandaloneKeriService extends KeriService {
  final KeriBridge _bridge;
  final MobileCoreService _mobileCore;
  bool _coreStarted = false;

  MobileStandaloneKeriService({
    KeriBridge? bridge,
    MobileCoreService? mobileCore,
  })  : _bridge = bridge ?? KeriBridge(),
        _mobileCore = mobileCore ?? MobileCoreService();

  @override
  AgentEnvironment get environment => AgentEnvironment.mobileStandalone;

  MobileCoreService get mobileCore => _mobileCore;

  bool get isCoreReady => _coreStarted;

  Future<void> startGoCore({String? dataDir, int? port}) async {
    if (_coreStarted) return;

    await _mobileCore.startCore(dataDir: dataDir, port: port);
    final ready = await _mobileCore.waitForReady();
    if (!ready) {
      throw Exception('Go Core server did not become ready within timeout');
    }
    _coreStarted = true;
  }

  Future<void> stopGoCore() async {
    if (!_coreStarted) return;
    await _mobileCore.stopCore();
    _coreStarted = false;
  }

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final result = await _bridge.inceptAid(name: name, code: code);

    if (_coreStarted) {
      try {
        await _mobileCore.storeIdentity(
          aid: result.aid,
          publicKey: result.publicKey,
        );
        await _mobileCore.storeEvent(
          aid: result.aid,
          eventType: 'icp',
          sequenceNumber: 0,
          eventJson: result.kel,
          publicKey: result.publicKey,
        );
      } catch (_) {}
    }

    return InceptionResult(
      aid: result.aid,
      publicKey: result.publicKey,
      kel: result.kel,
      created: DateTime.now().toIso8601String(),
    );
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    final result = await _bridge.rotateAid(name: name);

    if (_coreStarted) {
      try {
        await _mobileCore.storeEvent(
          aid: result.aid,
          eventType: 'rot',
          sequenceNumber: 1,
          eventJson: result.kel,
          publicKey: result.newPublicKey,
        );
      } catch (_) {}
    }

    return RotationResult(
      aid: result.aid,
      newPublicKey: result.newPublicKey,
      kel: result.kel,
    );
  }

  @override
  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    final result = await _bridge.signPayload(name: name, data: data);
    return SignatureResult(
      signature: result.signature,
      publicKey: result.publicKey,
    );
  }

  @override
  Future<String> getCurrentKel({required String name}) async {
    return await _bridge.getCurrentKel(name: name);
  }

  @override
  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    return await _bridge.verifySignature(
      data: data,
      signature: signature,
      publicKey: publicKey,
    );
  }

  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    throw UnimplementedError('interactAid not yet supported on mobile standalone');
  }

  @override
  Future<CredentialIssuanceResult> issueCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    String holderAid = '',
    String name = '',
  }) async {
    throw UnimplementedError('issueCredential not yet supported on mobile standalone');
  }

  @override
  Future<PresentationResult> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String issuerAid = '',
    String schemaSaid = '',
  }) async {
    throw UnimplementedError('presentCredential not yet supported on mobile standalone');
  }

  @override
  void dispose() {
    if (_coreStarted) {
      _mobileCore.stopCore();
    }
    _mobileCore.dispose();
  }
}
