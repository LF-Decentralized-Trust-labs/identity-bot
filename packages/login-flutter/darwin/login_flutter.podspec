Pod::Spec.new do |s|
  s.name             = 'login_flutter'
  s.version          = '0.1.0'
  s.summary          = 'The Apple hardware key of an installed utility-app front end (App Attest).'
  s.description      = 'See README.md of the package.'
  s.homepage         = 'https://github.com/LF-Decentralized-Trust-labs/identity-bot'
  s.license          = { :type => 'Apache-2.0' }
  s.author           = { 'identity-bot' => 'noreply@example.invalid' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.ios.dependency 'Flutter'
  s.osx.dependency 'FlutterMacOS'
  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '11.0'
  s.frameworks       = 'DeviceCheck', 'CryptoKit', 'Security'
  s.swift_version    = '5.0'
end
