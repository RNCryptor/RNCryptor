<?php

require_once __DIR__ . '/RNCryptor.php';

/**
 * RNEncryptor for PHP
 * 
 * Encrypt data interchangeably with the iOS implementation
 * of RNCryptor. Supports all schema versions through v2.
 */
class RNEncryptor extends RNCryptor {

	/**
	 * Encrypt plaintext using RNCryptor's algorithm
	 * 
	 * @param string $plaintext Text to be encrypted
	 * @param string $password Password to use
	 * @param int $version (Optional) RNCryptor schema version to use.
	 * @throws Exception If the provided version (if any) is unsupported
	 * @return string Encrypted, Base64-encoded string
	 */
	public function encrypt($plaintext, $password, $version = RNCryptor::DEFAULT_SCHEMA_VERSION) {

		$this->_configureSettings($version);

		$components = new stdClass();
		$components->headers = new stdClass();
		$components->headers->version = chr($version);
		$components->headers->options = chr($this->_settings->options);
		$components->headers->salt = $this->_generateSalt();
		$components->headers->hmacSalt = $this->_generateSalt();
		$components->headers->iv = $this->_generateIv($this->_settings->ivLength);

		$key = $this->_generateKey($components->headers->salt, $password);
		
		switch ($this->_settings->mode) {
			case 'ctr':
				$components->ciphertext = $this->_aesCtrLittleEndianCrypt($plaintext, $key, $components->headers->iv);
				break;

			case 'cbc':
				$paddedPlaintext = $this->_addPKCS7Padding($plaintext, strlen($components->headers->iv));
				$components->ciphertext = mcrypt_encrypt($this->_settings->algorithm, $key, $paddedPlaintext, 'cbc', $components->headers->iv);
				break;
		}

		$binaryData = ''
			. $components->headers->version
			. $components->headers->options
			. $components->headers->salt
			. $components->headers->hmacSalt
			. $components->headers->iv
			. $components->ciphertext;

		$hmac = $this->_generateHmac($components, $password);
		
		return base64_encode($binaryData . $hmac);
	}

	public function encryptWithArbitrarySalts($plaintext, $password, $salt, $hmacSalt, $iv, $version = RNCryptor::DEFAULT_SCHEMA_VERSION) {
	
		$this->_configureSettings($version);

		$components = new stdClass();
		$components->headers = new stdClass();
		$components->headers->version = chr($version);
		$components->headers->options = chr($this->_settings->options);
		$components->headers->salt = $salt;
		$components->headers->hmacSalt = $hmacSalt;
		$components->headers->iv = $iv;

		$key = $this->_generateKey($components->headers->salt, $password);
	
		switch ($this->_settings->mode) {
			case 'ctr':
				$components->ciphertext = $this->_aesCtrLittleEndianCrypt($plaintext, $key, $components->headers->iv);
				break;
	
			case 'cbc':
				$paddedPlaintext = $this->_addPKCS7Padding($plaintext, strlen($components->headers->iv));
				$components->ciphertext = mcrypt_encrypt($this->_settings->algorithm, $key, $paddedPlaintext, 'cbc', $components->headers->iv);
				break;
		}
	
		$binaryData = ''
				. $components->headers->version
				. $components->headers->options
				. $components->headers->salt
				. $components->headers->hmacSalt
				. $components->headers->iv
				. $components->ciphertext;
	
		$hmac = $this->_generateHmac($components, $password);

		return base64_encode($binaryData . $hmac);
	}

	public function encryptWithArbitraryKeys($plaintext, $key, $hmacKey, $iv, $version = RNCryptor::DEFAULT_SCHEMA_VERSION) {
	
		$this->_configureSettings($version);

		$this->_settings->options = 0;

		$components = new stdClass();
		$components->headers = new stdClass();
		$components->headers->version = chr($version);
		$components->headers->options = chr($this->_settings->options);
		$components->headers->iv = $iv;
	
		switch ($this->_settings->mode) {
			case 'ctr':
				$components->ciphertext = $this->_aesCtrLittleEndianCrypt($plaintext, $key, $components->headers->iv);
				break;
	
			case 'cbc':
				$paddedPlaintext = $this->_addPKCS7Padding($plaintext, strlen($components->headers->iv));
				$components->ciphertext = mcrypt_encrypt($this->_settings->algorithm, $key, $paddedPlaintext, 'cbc', $components->headers->iv);
				break;
		}

		$binaryData = ''
				. $components->headers->version
				. $components->headers->options
				. $components->headers->iv
				. $components->ciphertext;
	
		$hmac = $this->_generateHmacWithArbitraryKey($components, $hmacKey);
	
		return base64_encode($binaryData . $hmac);
	}

	private function _addPKCS7Padding($plaintext, $blockSize) {
		$padSize = $blockSize - (strlen($plaintext) % $blockSize);
		return $plaintext . str_repeat(chr($padSize), $padSize);
	}

	private function _generateSalt() {
		return $this->_generateIv($this->_settings->saltLength);
	}

	private function _generateIv($blockSize) {
		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$randomSource = MCRYPT_RAND;
		} else {
			$randomSource = MCRYPT_DEV_URANDOM;
		}
		return mcrypt_create_iv($blockSize, $randomSource);
	}
}
