from StringIO import StringIO
from unittest import TestCase
from RNCryptor import RNCryptor


class RNCryptorTest(TestCase):
    plaintext = "Attack at dawn and use yellow submarines"
    password = "password"

    def test_encrypt_decrypt(self):
        message = RNCryptor().encrypt(self.plaintext, self.password)
        new_plain = RNCryptor().decrypt(message, self.password)
        self.assertEqual(new_plain, self.plaintext)

    def test_randomizes_salts(self):
        """Note that this is not a full test for high-quality randomness - it merely tests whether
        at least these values change between different calls."""
        message = RNCryptor().encrypt(self.plaintext, self.password)
        (version, option, encryption_salt, hmac_salt, iv, ciphertext, hmac) = self._split_message(message)
        message2 = RNCryptor().encrypt(self.plaintext, self.password)
        (version2, option2, encryption_salt2, hmac_salt2, iv2, ciphertext2, hmac2) = self._split_message(message2)
        self.assertEqual(version, version2)
        self.assertEqual(option, option2)
        self.assertNotEqual(encryption_salt, encryption_salt2)
        self.assertNotEqual(hmac_salt, hmac_salt2)
        self.assertNotEqual(iv, iv2)
        self.assertNotEqual(ciphertext, ciphertext2)
        self.assertNotEqual(hmac, hmac2)

    def test_rejects_invalid_password(self):
        message = RNCryptor().encrypt(self.plaintext, self.password)
        new_plain = RNCryptor().decrypt(message, "wrong password---")
        self.assertFalse(new_plain)

    def test_rejects_invalid_hmac(self):
        message = RNCryptor().encrypt(self.plaintext, self.password)
        message += 'x'
        new_plain = RNCryptor().decrypt(message, self.password)
        self.assertFalse(new_plain)

    def _split_message(self, message):
        input = StringIO(message)
        version = input.read(1)
        option = input.read(1)
        encryption_salt = input.read(8)
        hmac_salt = input.read(8)
        iv = input.read(16)
        ciphertext = input.read(len(message)-32-34)
        hmac = input.read(32)
        return version, option, encryption_salt, hmac_salt, iv, ciphertext, hmac