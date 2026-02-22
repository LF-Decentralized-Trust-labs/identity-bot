Pod::Spec.new do |s|
  s.name         = 'Mobilecore'
  s.version      = '0.1.0'
  s.summary      = 'Go Mobile Core for Identity Agent'
  s.homepage     = 'https://github.com/LF-Decentralized-Trust-labs/identity-bot'
  s.license      = { :type => 'Apache-2.0' }
  s.author       = 'Identity Agent'
  s.source       = { :path => '.' }
  s.ios.deployment_target = '15.5'
  s.vendored_frameworks = 'Mobilecore.xcframework'
  s.static_framework = true
end
