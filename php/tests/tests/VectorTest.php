<?php

require_once __DIR__ . '/../../RNDecryptor.php';
require_once __DIR__ . '/../../RNEncryptor.php';

class VectorBase extends PHPUnit_Framework_TestCase {

	/**
	 * Base directory for the test vector files,
	 * relative to __DIR__
	 */
	const VECTOR_DIR = '/../../../vectors';

	public function testKdfVectors() {

		$vectors = $this->_getVectors('kdf');
		foreach ($vectors as $vector) {
	
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
	}

	public function testKeyVectors() {

		$vectors = $this->_getVectors('key');
		foreach ($vectors as $vector) {
	
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
	}

	public function testPasswordVectors() {

		$vectors = $this->_getVectors('password');
		foreach ($vectors as $vector) {

			$encryptor = new RNEncryptor();
			$encryptedB64 = $encryptor->encryptWithArbitrarySalts(
				$this->_prettyHexToBin($vector['plaintext_hex']),
				$vector['password'],
				$this->_prettyHexToBin($vector['enc_salt_hex']),
				$this->_prettyHexToBin($vector['hmac_salt_hex']),
				$this->_prettyHexToBin($vector['iv_hex']),
				$vector['version']
			);
	
			$this->assertEquals(
				$vector['ciphertext_hex'],
				$this->_binToPrettyHex(base64_decode($encryptedB64))
			);
		}
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

	private function _getVectors($filename) {

		$absolutePath = __DIR__ . '/' . self::VECTOR_DIR . '/' . $filename;
		if (!file_exists($absolutePath)) {
			throw new Exception('No such file: ' . $absolutePath);
		}

		$index = -1;
		$tests = array();
		$fd = fopen($absolutePath, 'r');
		while (!feof($fd)) {
			$line = trim(fgets($fd));
	
			if (preg_match("/^\s*(\w+)\s*\:\s*(.*)/", $line, $match)) {
				$key = strtolower($match[1]);
				$value = trim($match[2]);
	
				if ($key == 'title') {
					$index++;
				}
	
				$tests[$index][$key] = $value;
			}
		}
		fclose($fd);
	
		return $tests;
	}
	
}
