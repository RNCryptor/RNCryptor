#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io

import Crypto.Cipher
import Crypto.Hash
import Crypto.Protocol.KDF
import Crypto.Random

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

		output = b'\x02\x01' + encryption_salt + hmac_salt + iv + ciphertext
		return output + self.generate_hmac(password, hmac_salt, output)

	def decrypt(self, message, password):
		input = io.BytesIO(message)
		version = input.read(1) # Version
		option = input.read(1)
		encryption_salt = input.read(8)
		hmac_salt = input.read(8)
		iv = input.read(16)
		ciphertext = input.read(len(message)-32-34)

		hmac = input.read(32)
		new_hmac = self.generate_hmac(password, hmac_salt, message[0:len(message)-32])

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
	from time import time

	cryptor = RNCryptor()

	passwords = u'p@s$VV0Rd'.encode('utf-8'), u'пароль'.encode('utf-8')
	texts = b'Attack at dawn', u'текст'.encode('utf-8'), b'', b'1' * 16, b'2' * 15, b'3' * 17

	for password in passwords:
		for text in texts:
			print('text: {!r}'.format(text))

			s = time()
			encrypted_data = cryptor.encrypt(text, password)
			print('encrypted', time() - s)

			s = time()
			decrypted_data = cryptor.decrypt(encrypted_data, password)
			print('decrypted {}: {!r}\n'.format(time() - s, decrypted_data))

			assert text == decrypted_data


if __name__ == '__main__':
	main()
