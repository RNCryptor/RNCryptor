Ruby RNCryptor
--------------

This is a Ruby port of Rob Napier's Cocoa [RNCryptor](https://github.com/rnapier/RNCryptor/) library. Like RNCryptor, Ruby RNCryptor intends to be an easy-to-use class that correctly handles random initialization vectors, password stretching with PBKDF2, and HMAC verification.

This port is based on his [Data Format](https://github.com/rnapier/RNCryptor/wiki/Data-Format) wiki page. It currently only implements version 2.

Usage Example:
-------------

    require './lib/ruby_rncryptor'
    require "base64"

    password = "n3v3r gue55!!"
    encrypted = RubyRNCryptor.encrypt("This is a tiny bit of text to encrypt", password)

    puts Base64.encode64(encrypted)
    puts "Decrypting..."

    decrypted = RubyRNCryptor.decrypt(encrypted, password)

    puts decrypted

Credits
-------

- Ruby port by Erik Wrenholt 2013. 
- Original RNCrypto library and format are by Rob Napier.
