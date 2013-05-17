<?php
require_once __DIR__ . '/RNCryptor.php';

/**
 * RNDecryptor for PHP
 * 
 * Decrypt data interchangeably with the iOS implementation
 * of RNCryptor.
 */
class RNDecryptor extends RNCryptor {

	/**
	 * Decrypt RNCryptor-encrypted data
	 *
	 * @param string $encrypted Encrypted, Base64-encoded text
	 * @param string $password Password the text was encoded with
	 * @throws Exception If the detected version is unsupported
	 * @return string|false Decrypted string, or false if decryption failed
	 */
	public function decrypt($b64_data, $password) {

		$binaryData = base64_decode($b64_data);

		$versionChr = $this->_extractVersionFromBinData($binaryData);
		$this->_assertVersionIsSupported(ord($versionChr));

		if (!$this->_hmacIsValid($binaryData, $password)) {
			return false;
		}

		$keySalt = $this->_extractSaltFromBinData($binaryData);
		$key = $this->_generateKey($keySalt, $password);
		$iv = $this->_extractIvFromBinData($binaryData);

		$ciphertext = $this->_extractCiphertextFromBinData($binaryData);

		$cryptor = $this->_getCryptor($versionChr);

		switch (ord($versionChr)) {
			case 0:
				$plaintext = '';
				$blockSize = $this->_getCryptorBlockSize($versionChr);
				for ($blockNumber = 0; $blockNumber < ceil(strlen($ciphertext) / $blockSize); $blockNumber++) {
					$blockCounter = chr(ord(substr($iv, 0, 1)) + $blockNumber) . substr($iv, 1, $blockSize - 1);
					$blockCiphertext = substr($ciphertext, $blockSize * $blockNumber, $blockSize);
					mcrypt_generic_init($cryptor, $key, $blockCounter);
					$plaintext .= mdecrypt_generic($cryptor, $blockCiphertext);
				}
				break;
			case 1:
			case 2:
				mcrypt_generic_init($cryptor, $key, $iv);
				$plaintext = mdecrypt_generic($cryptor, $ciphertext);
				$plaintext = $this->_stripPKCS7Padding($plaintext);
				break;
		}

		mcrypt_generic_deinit($cryptor);
		mcrypt_module_close($cryptor);

		return $plaintext;
	}

	private function _stripPKCS7Padding($plaintext) {
		$padLength = ord(substr($plaintext, -1));
		return substr($plaintext, 0, strlen($plaintext) - $padLength);
	}

	private function _hmacIsValid($binaryData, $password) {
	
		$versionChr = $this->_extractVersionFromBinData($binaryData);
		switch (ord($versionChr)) {
			case 0:
			case 1:
				$dataWithoutHMAC = $this->_extractCiphertextFromBinData($binaryData);
				break;

			case 2:
				$dataWithoutHMAC = substr($binaryData, 0, strlen($binaryData) - RNCryptor::HMAC_SIZE);
				break;
		}

		$hmac = substr($binaryData, strlen($binaryData) - RNCryptor::HMAC_SIZE);

		$hmac_salt = $this->_extractHmacSaltFromBinData($binaryData);
		$hmac_key = hash_pbkdf2(RNCryptor::PBKDF2_PRF, $password, $hmac_salt, RNCryptor::PBKDF2_ITERATIONS, RNCryptor::KEY_SIZE, true);

		$algorithm = $this->_getHmacAlgorithm($versionChr);
		$hmac_hash = hash_hmac($algorithm, $dataWithoutHMAC , $hmac_key, true);

		if (ord($versionChr) == 0) {
			$hmac_hash = str_pad($hmac_hash, 32, chr(0));
		}
		
		return ($hmac_hash == $hmac);
	}
	
	private function _extractSaltFromBinData($binaryData) {
		return substr($binaryData, 2, 8);
	}

	private function _extractIvFromBinData($binaryData) {
		return substr($binaryData, 18, 16);
	}

	private function _extractCiphertextFromBinData($binaryData) {
		return substr($binaryData, 34, strlen($binaryData) - 34 - RNCryptor::HMAC_SIZE);
	}

}
