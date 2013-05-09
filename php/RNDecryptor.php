<?php
require_once dirname(__FILE__) . '/RNCryptor.php';

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
	 * @param bool $stripTrailingControlCharacters Whether to strip trailing
	 *                                             non-null padding characters
	 *                                             after decryption
	 * @throws Exception If the detected version is unsupported
	 * @return string|false Decrypted string, or false if decryption failed
	 */
	public function decrypt($b64_data, $password, $stripTrailingControlCharacters = true) {

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
		mcrypt_generic_init($cryptor, $key, $iv);
		$plaintext = mdecrypt_generic($cryptor, $ciphertext);

		mcrypt_generic_deinit($cryptor);
		mcrypt_module_close($cryptor);
	
		if ($stripTrailingControlCharacters) {
			$plaintext = $this->_stripTrailingControlChars($plaintext);
		}
	
		return trim($plaintext);
	}

	/**
	 * Sometimes the resulting padding is not null characters "\0" but rather
	 * one of several control characters. If you know your data is not supposed
	 * to have any trailing control characters "as we did" you can strip them
	 * like so.
	 *
	 * See http://www.php.net/manual/en/function.mdecrypt-generic.php
	 */
	private function _stripTrailingControlChars($plaintext) {
		return preg_replace("/\p{Cc}*$/u", "", $plaintext);
	}
	
	private function _hmacIsValid($binaryData, $password) {
	
		$versionChr = $this->_extractVersionFromBinData($binaryData);
		switch (ord($versionChr)) {
			case 0:
			case 1:
				// see http://robnapier.net/blog/rncryptor-hmac-vulnerability-827
				$dataWithoutHMAC = $this->_extractCiphertextFromBinData($binaryData);
				break;
			case 2:
				$dataWithoutHMAC = substr($binaryData, 0, strlen($binaryData) - RNCryptor::HMAC_SIZE);
				break;
		}
	
		$hmac = substr($binaryData, strlen($binaryData) - RNCryptor::HMAC_SIZE);
	
		$hmac_salt = $this->_extractHmacSaltFromBinData($binaryData);
		$hmac_key = hash_pbkdf2(RNCryptor::PBKDF2_PRF, $password, $hmac_salt, RNCryptor::PBKDF2_ITERATIONS, RNCryptor::KEY_SIZE, true);
	
		$hmac_hash = hash_hmac(RNCryptor::HMAC_ALGORITHM, $dataWithoutHMAC , $hmac_key, true);
	
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
