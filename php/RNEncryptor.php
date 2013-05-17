<?php

require_once __DIR__ . '/RNCryptor.php';

/**
 * RNEncryptor for PHP
 * 
 * Encrypt data interchangeably with the iOS implementation
 * of RNCryptor. Supports all schema versions through v2.
 */
class RNEncryptor extends RNCryptor {

	private $_randomSource;

	public function __construct() {
		$this->_setupRandomSource();
	}

	private function _setupRandomSource() {
		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$this->_randomSource = MCRYPT_RAND;
		} else {
			$this->_randomSource = MCRYPT_DEV_RANDOM;
		}
	}

	/**
	 * Encrypt plaintext using RNCryptor's algorithm
	 * 
	 * @param string $plaintext Text to be encrypted
	 * @param string $password Password to use
	 * @param int $version (Optional) RNCryptor schema version to use.
	 *                     Defaults to 2.
	 * @throws Exception If the provided version (if any) is unsupported
	 * @return string Encrypted, Base64-encoded string
	 */
	public function encrypt($plaintext, $password, $version = 2) {

		$this->_assertVersionIsSupported($version);

		$keySalt = mcrypt_create_iv(RNCryptor::SALT_SIZE, $this->_randomSource);
		$key = $this->_generateKey($keySalt, $password);

		$versionChr = chr($version);

		$cryptor = $this->_getCryptor($versionChr);
		$iv = $this->_generateIv($cryptor);

		switch (ord($versionChr)) {

			case 0:
				$blockSize = $this->_getCryptorBlockSize($versionChr);
				$plaintextChunks = str_split($plaintext, $blockSize);

				$ctrCounter = $iv;
				$ciphertext = '';
				foreach ($plaintextChunks as $plaintextChunk) {
					mcrypt_generic_init($cryptor, $key, $ctrCounter);
					$ciphertext .= mcrypt_generic($cryptor, $plaintextChunk);
				
					$ctrCounter = $this->_incrementAesCtrLECounter($ctrCounter, $blockSize);
				}
				break;

			case 1:
			case 2:
				$padded_plaintext = $this->_addPKCS7Padding($plaintext, $versionChr);
				mcrypt_generic_init($cryptor, $key, $iv);
				$ciphertext = mcrypt_generic($cryptor, $padded_plaintext);
				break;
		}

		mcrypt_generic_deinit($cryptor);
		mcrypt_module_close($cryptor);

		$hmacSalt = $this->_generateHmacSalt();
		$optionsChr = $this->_generateOptions($versionChr);
		$binaryData = $versionChr . $optionsChr . $keySalt . $hmacSalt . $iv . $ciphertext;

		$hmac = $this->_generateHmac($binaryData, $password);
		
		return base64_encode($binaryData . $hmac);
	}

	private function _incrementAesCtrLECounter($counter, $blockSize) {
		$ordinalOfFirstCharacter = ord(substr($counter, 0, 1)) + 1;
		return chr($ordinalOfFirstCharacter) . substr($counter, 1, $blockSize - 1);
	}

	private function _addPKCS7Padding($plaintext, $versionChr) {
		$blockSize = $this->_getCryptorBlockSize($versionChr);
		$padSize = $blockSize - (strlen($plaintext) % $blockSize);
		return $plaintext . str_repeat(chr($padSize), $padSize);
	}

	private function _generateOptions($versionChr) {
	
		switch (ord($versionChr)) {
			case 0:
				$optionsChr = chr(0);
				break;
			case 1:
			case 2:
				$optionsChr = chr(1); /* We're using a password */
				break;
		}
		return $optionsChr;
	}
	
	private function _generateIv($cryptor) {
		return mcrypt_create_iv(mcrypt_enc_get_iv_size($cryptor), $this->_randomSource);
	}
	
	private function _generateHmacSalt() {
		return mcrypt_create_iv(RNCryptor::SALT_SIZE, $this->_randomSource);
	}
	
	private function _generateHmac($binaryData, $password) {
	
		$versionChr = $this->_extractVersionFromBinData($binaryData);
		switch (ord($versionChr)) {
			case 0:
			case 1:
				$hmac_message = substr($binaryData, 34);
				break;
	
			case 2:
				$hmac_message = $binaryData;
				break;
		}

		$hmac_salt = $this->_extractHmacSaltFromBinData($binaryData);
		$hmac_key = hash_pbkdf2(RNCryptor::PBKDF2_PRF, $password, $hmac_salt, RNCryptor::PBKDF2_ITERATIONS, RNCryptor::KEY_SIZE, true);

		$algorithm = $this->_getHmacAlgorithm($versionChr);
		$hmac = hash_hmac($algorithm, $hmac_message, $hmac_key, true);
		
		if (ord($versionChr) == 0) {
			$hmac = str_pad($hmac, 32, chr(0));
		}
		
		return $hmac;
	}
}
