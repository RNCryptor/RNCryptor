Ruby RNCryptor
--------------

This is a Ruby port of Rob Napier's Cocoa [RNCryptor](https://github.com/rnapier/RNCryptor/) library. Like RNCryptor, Ruby RNCryptor intends to be an easy-to-use class that correctly handles random initialization vectors, password stretching with PBKDF2, and HMAC verification.

This port is based on his [Data Format](https://github.com/rnapier/RNCryptor/wiki/Data-Format) wiki page. It currently implements version 2 and version 3.

Usage Example:
--------------

    require './lib/ruby_rncryptor'
    require "base64"

    password = "n3v3r gue55!!"
    encrypted = RubyRNCryptor.encrypt("This is a tiny bit of text to encrypt", password)

    puts Base64.encode64(encrypted)
    puts "Decrypting..."

    decrypted = RubyRNCryptor.decrypt(encrypted, password)

    puts decrypted

Release Notes
-------------

2013-12-20 - version 3.0

- Generates version 3 file format files by default.
- Made a gemspec for this library, version 3.0 for file format version 3.
- Decrypts files encrypted with a bug in the Cocoa version where multibyte passwords were truncated.

Generate and install as a gemfile
---------------------------------

	gem build ruby_rncryptor.gemspec
	gem install ./ruby_rncryptor-3.0.0.gem

Credits
-------

- Ruby port by Erik Wrenholt 2013. 
- Original RNCrypto library and format are by Rob Napier.
