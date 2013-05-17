<?php
require_once __DIR__ . '/functions.php';

abstract class RNCryptor {

	/* kRNCryptorAES256Settings */
	const ALGORITHM = MCRYPT_RIJNDAEL_128;
	const KEY_SIZE = 32;
	const RNCRYPTOR_1x_MODE = 'ctr';
	const RNCRYPTOR_2x_MODE = 'cbc';
	const SALT_SIZE = 8;
	const PBKDF2_ITERATIONS = 10000;
	const PBKDF2_PRF = 'sha1';
	const HMAC_ALGORITHM_1x = 'sha1';
	const HMAC_ALGORITHM_2x = 'sha256';
	const HMAC_SIZE = 32;

	protected function _generateKey($salt, $password) {
		return hash_pbkdf2(self::PBKDF2_PRF, $password, $salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);
	}

	protected function _getCryptor($versionChr) {
		$mode = $this->_getEncryptionMode($versionChr);
		return mcrypt_module_open(self::ALGORITHM, '', $mode, '');
	}
	
	protected function _getCryptorBlockSize($versionChr) {
		$mode = $this->_getEncryptionMode($versionChr);
		return mcrypt_get_block_size(self::ALGORITHM, $mode);
	}

	protected function _extractVersionFromBinData($binaryData) {
		return substr($binaryData, 0, 1);
	}

	protected function _extractHmacSaltFromBinData($binaryData) {
		return substr($binaryData, 10, 8);
	}

	protected function _getEncryptionMode($versionChr) {
		switch (ord($versionChr)) {
			case 0:
				$mode = self::RNCRYPTOR_1x_MODE;
				break;
			case 1:
			case 2:
				$mode = self::RNCRYPTOR_2x_MODE;
				break;
		}

		return $mode;
	}

	protected function _getHmacAlgorithm($versionChr) {
		switch (ord($versionChr)) {
			case 0:
				$algorithm = self::HMAC_ALGORITHM_1x;
				break;
		
			case 1:
				$algorithm = self::HMAC_ALGORITHM_2x;
				break;
		
			case 2:
				$algorithm = self::HMAC_ALGORITHM_2x;
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
