# RubyRNCryptor by Erik Wrenholt.
# Based on data format described by Rob Napier 
# https://github.com/rnapier/RNCryptor/wiki/Data-Format
# MIT License

require 'openssl'

class RubyRNCryptor
  include OpenSSL
  
  def self.decrypt(data, password)

    version =         data[0,1]
    raise "RubyRNCryptor only supports version 2" if version != "\x02"
    options =         data[1,1]
    encryption_salt = data[2,8]
    hmac_salt =       data[10,8]
    iv =              data[18,16]
    cipher_text =     data[34,data.length-66]
    hmac =            data[data.length-32,32]
        
    key = PKCS5.pbkdf2_hmac_sha1(password, encryption_salt, 10000, 32)
    hmac_key = PKCS5.pbkdf2_hmac_sha1(password, hmac_salt, 10000, 32)

    # Verify password is correct.
    msg = version + options + encryption_salt + hmac_salt + iv + cipher_text
    verified = [HMAC.hexdigest('sha256', hmac_key, msg)].pack('H*') == hmac
    raise "HMAC could not be verified. Password may be incorrect, or the data has been corrupted." unless verified
    
    # HMAC was verified, now decrypt it.
    cipher = Cipher::Cipher.new('aes-256-cbc')
    cipher.decrypt
    cipher.iv = iv
    cipher.key = key

    return cipher.update(cipher_text) + cipher.final
  end

  def self.encrypt(data, password)
    
    version =         0x02.chr.to_s   # Currently version 2
    options =         0x01.chr.to_s   # Uses password
    encryption_salt = Random.random_bytes(8)
    hmac_salt =       Random.random_bytes(8)
    iv =              Random.random_bytes(16)
    
    cipher_text =     data[34,data.length-66]

    key = PKCS5.pbkdf2_hmac_sha1(password, encryption_salt, 10000, 32)
    hmac_key = PKCS5.pbkdf2_hmac_sha1(password, hmac_salt, 10000, 32)
    
    cipher = Cipher::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.iv = iv
    cipher.key = key
    cipher_text = cipher.update(data) + cipher.final

    msg = version + options + encryption_salt + hmac_salt + iv + cipher_text
    hmac = [HMAC.hexdigest('sha256', hmac_key, msg)].pack('H*')

    return msg + hmac    
  end
  
end
