<?php
require_once __DIR__ . '/functions.php';

abstract class RNCryptor {

	protected function _aesCtrCrypt($payload, $key, $iv) {

		$numOfBlocks = ceil(strlen($payload) / strlen($iv));
		$counter = '';
		for ($i = 0; $i < $numOfBlocks; ++$i) {
			$counter .= $iv;

			// Yes, the next line only ever increments the first character
			// of the counter string, ignoring overflow conditions.  This
			// matches CommonCrypto's behavior!
			$iv[0] = chr(ord(substr($iv, 0, 1)) + 1);
		}

		return $payload ^ mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $counter, MCRYPT_MODE_ECB);
	}

	protected function _generateHmac($binaryDataWithoutHmac, $password, $versionChr) {
	
		switch (ord($versionChr)) {
			case 0:
			case 1:
				$hmacMessage = substr($binaryDataWithoutHmac, 34);
				break;
	
			case 2:
				$hmacMessage = $binaryDataWithoutHmac;
				break;
		}
	
		$hmacSalt = $this->_extractHmacSaltFromBinData($binaryDataWithoutHmac);
		$hmacKey = $this->_generateKey($hmacSalt, $password);
	
		$algorithm = $this->_getHmacAlgorithm($versionChr);
		$hmac = hash_hmac($algorithm, $hmacMessage, $hmacKey, true);
	
		if (ord($versionChr) == 0) {
			$hmac = str_pad($hmac, 32, chr(0));
		}
	
		return $hmac;
	}

	private function _extractHmacSaltFromBinData($binaryData) {
		return substr($binaryData, 10, 8);
	}

	protected function _generateKey($salt, $password) {
		return hash_pbkdf2('sha1', $password, $salt, 10000, 32, true);
	}

	protected function _getHmacAlgorithm($versionChr) {
		switch (ord($versionChr)) {
			case 0:
				$algorithm = 'sha1';
				break;
		
			case 1:
			case 2:
				$algorithm = 'sha256';
				break;
		}
		return $algorithm;
	}

	/**
	 * Ensure the RNCryptor schema version is supported
	 * 
	 * @param int $version Version to check
	 * @throws Exception if not supported
	 */
	protected function _assertVersionIsSupported($version) {
		if ($version < 0 || $version > 2) {
			throw new Exception('Unsupported schema version ' . $version);
		}
	}

}
