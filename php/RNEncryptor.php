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
	 *                     Defaults to 2.
	 * @throws Exception If the provided version (if any) is unsupported
	 * @return string Encrypted, Base64-encoded string
	 */
	public function encrypt($plaintext, $password, $version = 2) {

		$this->_assertVersionIsSupported($version);

		$keySalt = $this->_generateSalt();
		$key = $this->_generateKey($keySalt, $password);

		$versionChr = chr($version);

		switch (ord($versionChr)) {

			case 0:
				list($iv, $ciphertext) = $this->_aesCtrEncrypt($plaintext, $key);
				break;

			case 1:
			case 2:
				list($iv, $ciphertext) = $this->_aesCbcEncrypt($plaintext, $key);
				break;
		}

		$hmacSalt = $this->_generateSalt();
		$optionsChr = $this->_generateOptions($versionChr);
		$binaryData = $versionChr . $optionsChr . $keySalt . $hmacSalt . $iv . $ciphertext;

		$hmac = $this->_generateHmac($binaryData, $password, $versionChr);
		
		return base64_encode($binaryData . $hmac);
	}

	private function _aesCtrEncrypt($plaintext, $key) {
		$blockSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, 'ctr');
		$iv = $this->_generateIv($blockSize);
		
		$ciphertext = $this->_aesCtrCrypt($plaintext, $key, $iv);
		
		return array($iv, $ciphertext);
	}
	
	private function _aesCbcEncrypt($plaintext, $key) {
		$blockSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, 'cbc');
		$iv = $this->_generateIv($blockSize);

		$padded_plaintext = $this->_addPKCS7Padding($plaintext, strlen($iv));
		$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $padded_plaintext, MCRYPT_MODE_CBC, $iv);
		
		return array($iv, $ciphertext);
	}
	
	private function _addPKCS7Padding($plaintext, $blockSize) {
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
				$optionsChr = chr(1);
				break;
		}
		return $optionsChr;
	}

	private function _generateSalt() {
		return $this->_generateIv(8);
	}

	private function _generateIv($blockSize) {
		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$randomSource = MCRYPT_RAND;
		} else {
			$randomSource = MCRYPT_DEV_RANDOM;
		}
		
		return mcrypt_create_iv($blockSize, $randomSource);
	}
}
