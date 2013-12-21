# RubyRNCryptor by Erik Wrenholt.
# Based on data format described by Rob Napier 
# https://github.com/rnapier/RNCryptor/wiki/Data-Format
# MIT License

require 'openssl'

class RubyRNCryptor
	include OpenSSL

	def self.decrypt(data, password)

		version =			data[0,1]
		raise "RubyRNCryptor only decrypts version 2 or 3" unless (version == "\x02" || version == "\x03")
		options =			data[1,1]
		encryption_salt = 	data[2,8]
		hmac_salt =			data[10,8]
		iv =				data[18,16]
		cipher_text =		data[34,data.length-66]
		hmac =				data[data.length-32,32]
				
		msg = version + options + encryption_salt + hmac_salt + iv + cipher_text
		
		# Verify password is correct. First try with correct encoding
		hmac_key = PKCS5.pbkdf2_hmac_sha1(password, hmac_salt, 10000, 32)
		verified = [HMAC.hexdigest('sha256', hmac_key, msg)].pack('H*') == hmac

		if !verified && version == "\x02"
			# Version 2 Cocoa version truncated multibyte passwords, so try truncating.
			password = RubyRNCryptor.truncate_multibyte_password(password)
			hmac_key = PKCS5.pbkdf2_hmac_sha1(password, hmac_salt, 10000, 32)
			verified = [HMAC.hexdigest('sha256', hmac_key, msg)].pack('H*') == hmac
		end
		
		raise "Password may be incorrect, or the data has been corrupted. (HMAC could not be verified)" unless verified
		
		# HMAC was verified, now decrypt it.
		cipher = Cipher::Cipher.new('aes-256-cbc')
		cipher.decrypt
		cipher.iv = iv
		cipher.key = PKCS5.pbkdf2_hmac_sha1(password, encryption_salt, 10000, 32)

		return cipher.update(cipher_text) + cipher.final
	end

	def self.encrypt(data, password, version = 3)

		raise "RubyRNCryptor only encrypts version 2 or 3" unless (version == 2 || version == 3)
		
		version =			version.chr.to_s		# Currently version 3
		options =			1.chr.to_s				# Uses password
		encryption_salt =	Random.random_bytes(8)
		hmac_salt =			Random.random_bytes(8)
		iv =				Random.random_bytes(16)
		cipher_text =		data[34,data.length-66]

		hmac_key = PKCS5.pbkdf2_hmac_sha1(password, hmac_salt, 10000, 32)
		
		cipher = Cipher::Cipher.new('aes-256-cbc')
		cipher.encrypt
		cipher.iv = iv
		cipher.key = PKCS5.pbkdf2_hmac_sha1(password, encryption_salt, 10000, 32)
		cipher_text = cipher.update(data) + cipher.final

		msg = version + options + encryption_salt + hmac_salt + iv + cipher_text
		hmac = [HMAC.hexdigest('sha256', hmac_key, msg)].pack('H*')

		return msg + hmac		 
	end

	def self.truncate_multibyte_password(str)
		if str.bytes.to_a.count == str.length
			return str
		end
		return str.bytes.to_a[0...str.length].map {|c| c.chr}.join
	end
	
end
