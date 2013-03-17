#!/usr/bin/python

import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Random
import Crypto.Protocol.KDF
import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import StringIO

class RNCryptor:
	"""Cryptor for RNCryptor"""

	salt_size = 8
	key_length = 32
	iterations = 10000
	HMAC_hash_algo = Crypto.Hash.SHA256
	block_size = Crypto.Cipher.AES.block_size
	mode = Crypto.Cipher.AES.MODE_CBC

	def encrypt(self, message, password):
		random = Crypto.Random.new()

		encryption_salt = random.read(self.salt_size)
		encryption_key = Crypto.Protocol.KDF.PBKDF2(password, encryption_salt, self.key_length, self.iterations)

		hmac_salt = random.read(self.salt_size)
		hmac_key = Crypto.Protocol.KDF.PBKDF2(password, hmac_salt, self.key_length, self.iterations)

		iv = random.read(self.block_size)
		cipher = Crypto.Cipher.AES.new(encryption_key, self.mode, iv)

		ciphertext = cipher.encrypt(self.pad(message))

		output = StringIO.StringIO()
		output.write(chr(2)) # Version 2
		output.write(chr(1)) # Password
		output.write(encryption_salt)
		output.write(hmac_salt)
		output.write(iv)
		output.write(ciphertext)

		hmac = Crypto.Hash.HMAC.new(hmac_key, output.getvalue(), self.HMAC_hash_algo)

		output.write(hmac.digest())

		return output.getvalue()

	def pad(self, data):
		block_size = self.block_size
		return data + (block_size - len(data) % block_size) * chr(block_size - len(data) % block_size)

def main():
	plaintext = b"Attack at dawn"
	password = b"mypassword"
	
	message = RNCryptor().encrypt(plaintext, password)
	print ''.join('%02x' % ord(byte) for byte in message)

if __name__ == '__main__':
	main()
