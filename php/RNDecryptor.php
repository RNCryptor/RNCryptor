<?php
require_once __DIR__ . '/RNCryptor.php';

/**
 * RNDecryptor for PHP
 * 
 * Decrypt data interchangeably with the iOS implementation
 * of RNCryptor.
 */
class RNDecryptor extends RNCryptor {

	const HMAC_SIZE = 32;

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

		switch (ord($versionChr)) {
			case 0:
				$plaintext = $this->_aesCtrDecrypt($ciphertext, $key, $iv);
				break;

			case 1:
			case 2:
				$plaintext = $this->_aesCbcDecrypt($ciphertext, $key, $iv);
				break;
		}

		return $plaintext;
	}

	private function _aesCtrDecrypt($ciphertext, $key, $iv) {
		return $this->_aesCtrCrypt($ciphertext, $key, $iv);
	}

	private function _aesCbcDecrypt($ciphertext, $key, $iv) {
		$plaintext = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ciphertext, MCRYPT_MODE_CBC, $iv);
		return $this->_stripPKCS7Padding($plaintext);
	}
	
	private function _stripPKCS7Padding($plaintext) {
		$padLength = ord(substr($plaintext, -1));
		return substr($plaintext, 0, strlen($plaintext) - $padLength);
	}

	private function _hmacIsValid($binaryData, $password) {

		$hmac = substr($binaryData, strlen($binaryData) - self::HMAC_SIZE);
		$versionChr = $this->_extractVersionFromBinData($binaryData);

		$binaryDataWithoutHmac = substr($binaryData, 0, strlen($binaryData) - self::HMAC_SIZE);
		$hmacHash = $this->_generateHmac($binaryDataWithoutHmac, $password, $versionChr);
		
		return ($hmacHash == $hmac);
	}

	private function _extractVersionFromBinData($binaryData) {
		return substr($binaryData, 0, 1);
	}

	private function _extractSaltFromBinData($binaryData) {
		return substr($binaryData, 2, 8);
	}
	
	private function _extractIvFromBinData($binaryData) {
		return substr($binaryData, 18, 16);
	}

	private function _extractCiphertextFromBinData($binaryData) {
		return substr($binaryData, 34, strlen($binaryData) - 34 - self::HMAC_SIZE);
	}

}
