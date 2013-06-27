#!/usr/bin/env python

import Crypto.Cipher.AES as AES
import Crypto.Hash as Hash
import Crypto.Protocol.KDF as KDF
import Crypto.Random as Random


class RNCryptor(object):
    """Cryptor for RNCryptor"""

    AES_BLOCK_SIZE = AES.block_size
    AES_MODE = AES.MODE_CBC
    SALT_SIZE = 8

    def pre_decrypt_data(self, data):
        """ Change this function for handling data before decryption. """
        return data

    def post_decrypt_data(self, data):
        """ Removes useless symbols which appear over padding for AES (PKCS#7). """

        return data[:-ord(data[-1])]

    def decrypt(self, data, password):
        data = self.pre_decrypt_data(data)

        n = len(data)

        version = data[0]
        options = data[1]
        encryption_salt = data[2:10]
        hmac_salt = data[10:18]
        iv = data[18:34]
        cipher_text = data[34:n - 32]
        hmac = data[n - 32:]

        encryption_key = self._pbkdf2(password, encryption_salt)
        hmac_key = self._pbkdf2(password, hmac_salt)

        if self._hmac(hmac_key, data[:n - 32]) != hmac:
            raise Exception("Bad data")

        decrypted_data = self._aes_decrypt(encryption_key, iv, cipher_text)

        return self.post_decrypt_data(decrypted_data)

    def pre_encrypt_data(self, data):
        """ Does padding for the data for AES (PKCS#7). """

        rem = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
        return data + rem * chr(rem)

    def post_encrypt_data(self, data):
        """ Change this function for handling data after encryption. """
        return data

    def encrypt(self, data, password):
        data = self.pre_encrypt_data(data)

        encryption_salt = self.encryption_salt
        encryption_key = self._pbkdf2(password, encryption_salt)

        hmac_salt = self.hmac_salt
        hmac_key = self._pbkdf2(password, hmac_salt)

        iv = self.iv
        cipher_text = self._aes_encrypt(encryption_key, iv, data)

        version = chr(2)
        options = chr(1)

        new_data = ''.join([version, options, encryption_salt, hmac_salt, iv, cipher_text])
        encrypted_data = new_data + self._hmac(hmac_key, new_data)

        return self.post_encrypt_data(encrypted_data)

    @property
    def encryption_salt(self):
        return Random.new().read(self.SALT_SIZE)

    @property
    def hmac_salt(self):
        return Random.new().read(self.SALT_SIZE)

    @property
    def iv(self):
        return Random.new().read(self.AES_BLOCK_SIZE)

    def _aes_encrypt(self, key, iv, text):
        return AES.new(key, self.AES_MODE, iv).encrypt(text)

    def _aes_decrypt(self, key, iv, text):
        return AES.new(key, self.AES_MODE, iv).decrypt(text)

    def _hmac(self, key, data):
        return Hash.HMAC.new(key, data, Hash.SHA256).digest()

    def _pbkdf2(self, password, salt, iterations=10000, key_length=32):
        """ Several realisation may be used. Choose one you like (requires 3-party libraries). """

        ## crypto version -- very slow
        return KDF.PBKDF2(password, salt, dkLen=key_length, count=iterations)

        ## requires https://github.com/mitsuhiko/python-pbkdf2 version -- medium speed
        # from pbkdf2 import pbkdf2_bin
        # return pbkdf2_bin(password, salt, iterations=iterations, keylen=key_length)

        ## requires django 1.5 version -- fast enough
        # import hashlib
        # from django.utils.crypto import pbkdf2
        # return pbkdf2(password, salt, iterations, dklen=key_length, digest=hashlib.sha1)


def test():
    from time import time

    cryptor = RNCryptor()
    password = 'p@s$VV0Rd'
    texts = ['test', '', '1' * 16, '2' * 15, '3' * 17]

    for text in texts:
        print 'text: "{}"'.format(text)

        s = time()
        encrypted_data = cryptor.encrypt(text, password)
        print 'encrypted {}: "{}"'.format(time() - s, encrypted_data.encode('hex').replace('\n', ''))

        s = time()
        decrypted_data = cryptor.decrypt(encrypted_data, password)
        print 'decrypted {}: "{}"'.format(time() - s, decrypted_data)

        assert text == decrypted_data
        print


if __name__ == '__main__':

    test()
