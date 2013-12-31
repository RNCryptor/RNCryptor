<?php

require_once __DIR__ . '/RNCryptor.php';

/**
 * RNEncryptor for PHP
 * 
 * Encrypt data interchangeably with Rob Napier's Objective-C implementation
 * of RNCryptor
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

		$components = $this->_generateInitializedComponents($version);
		$components->headers->encSalt = $this->_generateSalt();
		$components->headers->hmacSalt = $this->_generateSalt();
		$components->headers->iv = $this->_generateIv($this->_settings->ivLength);

		$encKey = $this->_generateKey($components->headers->encSalt, $password);
		$hmacKey = $this->_generateKey($components->headers->hmacSalt, $password);

		return $this->_encrypt($plaintext, $components, $encKey, $hmacKey);
	}

	public function encryptWithArbitrarySalts($plaintext, $password, $encSalt, $hmacSalt, $iv, $version = RNCryptor::DEFAULT_SCHEMA_VERSION) {
	
		$this->_configureSettings($version);

		$components = $this->_generateInitializedComponents($version);
		$components->headers->encSalt = $encSalt;
		$components->headers->hmacSalt = $hmacSalt;
		$components->headers->iv = $iv;

		$encKey = $this->_generateKey($components->headers->encSalt, $password);
		$hmacKey = $this->_generateKey($components->headers->hmacSalt, $password);

		return $this->_encrypt($plaintext, $components, $encKey, $hmacKey);
	}

	public function encryptWithArbitraryKeys($plaintext, $encKey, $hmacKey, $iv, $version = RNCryptor::DEFAULT_SCHEMA_VERSION) {

		$this->_configureSettings($version);

		$this->_settings->options = 0;

		$components = $this->_generateInitializedComponents($version);
		$components->headers->iv = $iv;

		return $this->_encrypt($plaintext, $components, $encKey, $hmacKey);
	}

	private function _generateInitializedComponents($version) {

		$components = new stdClass();
		$components->headers = new stdClass();
		$components->headers->version = chr($version);
		$components->headers->options = chr($this->_settings->options);

		return $components;
	}

	private function _encrypt($plaintext, stdClass $components, $encKey, $hmacKey) {
	
		switch ($this->_settings->mode) {
			case 'ctr':
				$components->ciphertext = $this->_aesCtrLittleEndianCrypt($plaintext, $encKey, $components->headers->iv);
				break;
	
			case 'cbc':
				$paddedPlaintext = $this->_addPKCS7Padding($plaintext, strlen($components->headers->iv));
				$components->ciphertext = mcrypt_encrypt($this->_settings->algorithm, $encKey, $paddedPlaintext, 'cbc', $components->headers->iv);
				break;
		}

		$binaryData = ''
				. $components->headers->version
				. $components->headers->options
				. (isset($components->headers->encSalt) ? $components->headers->encSalt : '')
				. (isset($components->headers->hmacSalt) ? $components->headers->hmacSalt : '')
				. $components->headers->iv
				. $components->ciphertext;
	
		$hmac = $this->_generateHmac($components, $hmacKey);
	
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
