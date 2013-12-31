<?php

require_once __DIR__ . '/../../RNDecryptor.php';
require_once __DIR__ . '/../../RNEncryptor.php';

abstract class VectorBase extends PHPUnit_Framework_TestCase {
	
	protected function _runKdfTest(array $vector) {

		$cryptor = new RNCryptor();
		$key = $cryptor->generateKey(
			$this->_prettyHexToBin($vector['salt_hex']),
			$vector['password'],
			$vector['version']
		);
		
		$this->assertEquals(
			$this->_prettyHexToBin($vector['key_hex']),
			$key
		);
	}

	protected function _runKeyTest(array $vector) {

		$encryptor = new RNEncryptor();
		$encryptedB64 = $encryptor->encryptWithArbitraryKeys(
			$this->_prettyHexToBin($vector['plaintext_hex']),
			$this->_prettyHexToBin($vector['enc_key_hex']),
			$this->_prettyHexToBin($vector['hmac_key_hex']),
			$this->_prettyHexToBin($vector['iv_hex']),
			$vector['version']
		);

		$this->assertEquals(
			$vector['ciphertext_hex'],
			$this->_binToPrettyHex(base64_decode($encryptedB64))
		);
	}

	protected function _runPasswordTest(array $vector) {

		$encryptor = new RNEncryptor();
		$encryptedB64 = $encryptor->encryptWithArbitrarySalts(
			$this->_prettyHexToBin($vector['plaintext_hex']),
			$vector['password'],
			$this->_prettyHexToBin($vector['enc_salt_hex']),
			$this->_prettyHexToBin($vector['hmac_salt_hex']),
			$this->_prettyHexToBin($vector['iv_hex']),
			$vector['version']
		);

		$decryptor = new RNDecryptor();
		$decrypted = $decryptor->decrypt($encryptedB64, $vector['password']);
		$this->assertEquals(
			$this->_prettyHexToBin($vector['plaintext_hex']),
			$decrypted
		);

		$this->assertEquals(
			$vector['ciphertext_hex'],
			$this->_binToPrettyHex(base64_decode($encryptedB64))
		);
	}

	private function _prettyHexToBin($data) {
		return hex2bin(preg_replace("/[^a-z0-9]/i", '', $data));
	}

	private function _binToPrettyHex($data) {

		$hex = bin2hex($data);

		$prettyHex = '';
		foreach (str_split($hex, 8) as $index => $part) {
			$prettyHex .= ($index != 0 ? ' ' : '') . $part;
		}
		return $prettyHex;
	}
	
}
