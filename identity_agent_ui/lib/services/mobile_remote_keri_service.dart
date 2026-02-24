import 'keri_service.dart';
import '../bridge/keri_bridge.dart';

class MobileRemoteKeriService extends KeriService {
  final KeriBridge _bridge;
  final String parentServerUrl;

  MobileRemoteKeriService({
    required this.parentServerUrl,
    KeriBridge? bridge,
  }) : _bridge = bridge ?? KeriBridge();

  @override
  AgentEnvironment get environment => AgentEnvironment.mobileRemoteWithoutKeys;

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final result = await _bridge.inceptAid(name: name, code: code);
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
  void dispose() {}
}
