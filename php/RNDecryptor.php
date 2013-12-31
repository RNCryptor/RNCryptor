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
	 * @param string $base64EncryptedData Encrypted, Base64-encoded text
	 * @param string $password Password the text was encoded with
	 * @throws Exception If the detected version is unsupported
	 * @return string|false Decrypted string, or false if decryption failed
	 */
	public function decrypt($encryptedBase64Data, $password) {

		$components = $this->_unpackEncryptedBase64Data($encryptedBase64Data);

		if (!$this->_hmacIsValid($components, $password)) {
			return false;
		}

		$key = $this->_generateKey($components->headers->salt, $password);

		switch ($this->_settings->mode) {
			case 'ctr':
				$plaintext = $this->_aesCtrLittleEndianCrypt($components->ciphertext, $key, $components->headers->iv);
				break;

			case 'cbc':
				$paddedPlaintext = mcrypt_decrypt($this->_settings->algorithm, $key, $components->ciphertext, 'cbc', $components->headers->iv);
				$plaintext = $this->_stripPKCS7Padding($paddedPlaintext);
				break;
		}

		return $plaintext;
	}

	private function _unpackEncryptedBase64Data($encryptedBase64Data) {

		$binaryData = base64_decode($encryptedBase64Data);

		$components = new stdClass();
		$components->headers = $this->_parseHeaders($binaryData);

		$components->hmac = substr($binaryData, - $this->_settings->hmac->length);

		$headerLength = $components->headers->length;
		$components->ciphertext = substr($binaryData, $headerLength, strlen($binaryData) - $headerLength - strlen($components->hmac));

		return $components;
	}

	private function _parseHeaders($binData) {

		$offset = 0;

		$versionChr = $binData[0];
		$offset += strlen($versionChr);

		$this->_configureSettings(ord($versionChr));

		$optionsChr = $binData[1];
		$offset += strlen($optionsChr);

		$salt = substr($binData, $offset, $this->_settings->saltLength);
		$offset += strlen($salt);
		
		$hmacSalt = substr($binData, $offset, $this->_settings->saltLength);
		$offset += strlen($hmacSalt);
		
		$iv = substr($binData, $offset, $this->_settings->ivLength);
		$offset += strlen($iv);

		$headers = (object)array(
			'version' => $versionChr,
			'options' => $optionsChr,
			'salt' => $salt,
			'hmacSalt' => $hmacSalt,
			'iv' => $iv,
			'length' => $offset
		);

		return $headers;
	}

	private function _stripPKCS7Padding($plaintext) {
		$padLength = ord($plaintext[strlen($plaintext)-1]);
		return substr($plaintext, 0, strlen($plaintext) - $padLength);
	}

	private function _hmacIsValid($components, $password) {
		return ($components->hmac == $this->_generateHmac($components, $password));
	}

}
