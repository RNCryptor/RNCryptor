from Crypto.Cipher import AES
from Crypto import Random
import StringIO
from pkcs7 import PKCS7Encoder

class RNCryptor:
	"""Cryptor for RNCryptor"""
	def __init__(self, settings):
		self.settings = settings
	
	def encrypt(self, message, key, hmac_key):
		output = StringIO.StringIO()
		output.write(1) # Version 1
		output.write(0) # No options
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		encoder = PKCS7Encoder()
		output.write(iv)
		output.write(cipher.encrypt(encoder.encode(message)))
		return output.getvalue()


def main():
	plaintext = b"Attack at dawn"
	key = '000102030405060708090a0b0c0d0e0f'.decode("hex")
	hmac_key = '0f0e0d0c0b0a09080706050403020100'.decode("hex")
	cipher = RNCryptor("")
	ciphertext = cipher.encrypt(plaintext, key, hmac_key)
	print ''.join('%02x' % ord(byte) for byte in ciphertext)

if __name__ == '__main__':
	main()