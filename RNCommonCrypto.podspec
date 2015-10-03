Pod::Spec.new do |s|
  s.name = 'RNCommonCrypto'
  s.version = '4.0.0-beta.1'
  s.summary = 'Swift-compatibility module for CommonCrypto'
  s.authors = {'Rob Napier' => 'robnapier@gmail.com'}
  s.social_media_url = 'https://twitter.com/cocoaphony'
  s.license = 'MIT'
  s.source = { :git => 'https://github.com/rnapier/RNCryptor.git', :tag => "v#{s.version.to_s}" }
  s.homepage = 'https://github.com/rnapier/RNCryptor'
  s.source_files = 'CommonCrypto/CommonCrypto.c'
  s.public_header_files = 'CommonCrypto/CommonCrypto.h'
  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.9'
end
