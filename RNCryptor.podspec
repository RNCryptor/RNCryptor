Pod::Spec.new do |s|
	s.name = 'RNCryptor'
	s.version = '5.0.1'
	s.summary = 'Cross-language AES Encryptor/Decryptor data format.'
	s.authors = {'Rob Napier' => 'robnapier@gmail.com'}
	s.social_media_url = 'https://twitter.com/cocoaphony'
	s.license = 'MIT'
	s.source = { :git => 'https://github.com/rnapier/RNCryptor.git', :tag => "RNCryptor-#{s.version.to_s}" }
	s.description = 'Implements a secure encryption format based on AES, PBKDF2, and HMAC.'
	s.homepage = 'https://github.com/rnapier/RNCryptor'
	s.source_files = 'RNCryptor.swift', 'RNCryptor.h'
	s.ios.deployment_target = '8.0'
	s.tvos.deployment_target = '9.0'
	s.osx.deployment_target = '10.9'
	s.watchos.deployment_target = '2.0'
end
