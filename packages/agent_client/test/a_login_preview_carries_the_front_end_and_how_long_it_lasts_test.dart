import 'package:agent_client/services/login_service.dart';
import 'package:test/test.dart';

void main() {
  test('an installed app\'s preview says so and that it lasts until ended', () {
    final p = LoginPreview.fromJson(
        {'front_end': 'installed_app', 'lasts_until_ended': true});
    expect(p.frontEnd, 'installed_app');
    expect(p.lastsUntilEnded, isTrue);
  });

  test('a preview that says nothing is not read as lasting until ended', () {
    final p = LoginPreview.fromJson({});
    expect(p.frontEnd, '');
    expect(p.lastsUntilEnded, isFalse);
  });

  test('an installed app\'s preview names the device and what it calls it', () {
    final p = LoginPreview.fromJson({
      'front_end': 'installed_app',
      'device_platform': 'android',
      'device_name': 'Ann\'s Pixel',
    });
    expect(p.devicePlatform, 'android');
    expect(p.deviceName, 'Ann\'s Pixel');
  });

  test('a preview that names no device does not make one up', () {
    final p = LoginPreview.fromJson({'front_end': 'browser'});
    expect(p.devicePlatform, '');
    expect(p.deviceName, '');
  });
}
