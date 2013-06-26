#!/usr/bin/python

import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Random
import Crypto.Protocol.KDF
import Crypto.Cipher.AES
import Crypto.Hash.HMAC
from cStringIO import StringIO
from pkcs7 import PKCS7Encoder

class RNCryptor:
	"""Cryptor for RNCryptor"""

	salt_size = 8
	key_length = 32
	iterations = 10000
	HMAC_hash_algo = Crypto.Hash.SHA256
	block_size = Crypto.Cipher.AES.block_size
	mode = Crypto.Cipher.AES.MODE_CBC

	def __init__(self):
		self.pkcs7 = PKCS7Encoder(self.block_size)

	def encrypt(self, message, password):
		random = Crypto.Random.new()

		encryption_salt = random.read(self.salt_size)
		encryption_key = Crypto.Protocol.KDF.PBKDF2(password, encryption_salt, self.key_length, self.iterations)

		hmac_salt = random.read(self.salt_size)

		iv = random.read(self.block_size)
		cipher = Crypto.Cipher.AES.new(encryption_key, self.mode, iv)

		ciphertext = cipher.encrypt(self.pkcs7.encode(message))

		output = StringIO()
		output.write(chr(2)) # Version 2
		output.write(chr(1)) # Password
		output.write(encryption_salt)
		output.write(hmac_salt)
		output.write(iv)
		output.write(ciphertext)

		hmac = self.generate_hmac(password, hmac_salt, output.getvalue())

		output.write(hmac)

		return output.getvalue()

	def decrypt(self, message, password):
		input = StringIO(message)
		version = input.read(1) # Version
		option = input.read(1)
		encryption_salt = input.read(8)
		hmac_salt = input.read(8)
		iv = input.read(16)
		ciphertext = input.read(len(message)-32-34)

		hmac = input.read(32)
		# print '\n<', len(message), '>', ''.join('%02x' % ord(byte) for byte in hmac)

		new_hmac = self.generate_hmac(password, hmac_salt, message[0:len(message)-32])
		# print '\n<nmac', len(message), '>', ''.join('%02x' % ord(byte) for byte in new_hmac)

		if hmac != new_hmac :
			return False

		encryption_key = Crypto.Protocol.KDF.PBKDF2(password, encryption_salt, self.key_length, self.iterations)

		cipher = Crypto.Cipher.AES.new(encryption_key, self.mode, iv)
		plain = cipher.decrypt(ciphertext)

		return self.pkcs7.decode(plain)


	def generate_hmac(self, password, hmac_salt, msg):
		hmac_key = Crypto.Protocol.KDF.PBKDF2(password, hmac_salt, self.key_length, self.iterations)
		hmac = Crypto.Hash.HMAC.new(hmac_key, msg, self.HMAC_hash_algo)
		return hmac.digest()

def main():
	plaintext = b"Attack at dawn"
	password = b"mypassword"
	
	message = RNCryptor().encrypt(plaintext, password)
	print ''.join('%02x' % ord(byte) for byte in message)

	plain = RNCryptor().decrypt(message, password)
	print plain


if __name__ == '__main__':
	main()
