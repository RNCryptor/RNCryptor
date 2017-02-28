require './lib/ruby_rncryptor'
require "base64"

password = "n3v3r gue55!!"

encrypted = RubyRNCryptor.encrypt("This is a tiny bit of text to encrypt", password)
puts Base64.encode64(encrypted)

puts
puts "Decrypting..."

decrypted = RubyRNCryptor.decrypt(encrypted, password)

puts decrypted