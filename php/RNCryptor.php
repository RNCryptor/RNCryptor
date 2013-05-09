<?php

require_once dirname(__FILE__) . '/functions.php';

/**
 * RNCryptor for PHP
 * 
 * Encrypt and decrypt data interchangeably with the iOS version 
 * of RNCryptor. Supports file versions 1 and 2.  (Version 0 not 
 * supported due to lack of information on how to adapt the 
 * RNCryptor 1.0 algorithm to PHP, particularly supporting 
 * AES CTR LE mode and making the HMAC verification work.)
 * 
 * Copyright (c) 2013 Curtis Farnham <curtis@farnhamtech.com>
 * License: MIT, or any future license RNCryptor may be distributed under
 */
class RNCryptor {

	/* kRNCryptorAES256Settings */
	const ALGORITHM = MCRYPT_RIJNDAEL_128;
	const KEY_SIZE = 32;
	const RNCRYPTOR_1x_MODE = 'ctr';
	const RNCRYPTOR_2x_MODE = 'cbc';
	const SALT_SIZE = 8;
	const PBKDF2_ITERATIONS = 10000;
	const PBKDF2_PRF = 'sha1';
	const HMAC_ALGORITHM = 'sha256';
	const HMAC_SIZE = 32;

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
	 * Adapted by Curtis Farnham <curtis@farnhamtech.com> from an 
	 * undocumented source.  Support for RNCryptor file version 1 added.
	 * 
	 * @param string $plaintext Text to be encrypted
	 * @param string $password Password to use
	 * @param int $version (Optional) RNCryptor file version to use.
	 *                     Defaults to 2.
	 * @return string Encrypted, Base64-encoded string
	 */
	public function encrypt($plaintext, $password, $version = 2) {

		$this->_assertVersionIsSupported($version);

		$keySalt = mcrypt_create_iv(self::SALT_SIZE, $this->_randomSource);
		$key = $this->_generateKey($keySalt, $password);

		$versionChr = chr($version);

		$cryptor = $this->_getCryptor($versionChr);
		$iv = $this->_generateIv($cryptor);
		
		$padded_plaintext = $this->_padToBlockSizeMultiple($cryptor, $plaintext);
		
		mcrypt_generic_init($cryptor, $key, $iv);
		$ciphertext = mcrypt_generic($cryptor, $padded_plaintext);
		
		mcrypt_generic_deinit($cryptor);
		mcrypt_module_close($cryptor);

		$hmacSalt = $this->_generateHmacSalt();
		$optionsChr = $this->_generateOptions($versionChr);
		$binaryData = $versionChr . $optionsChr . $keySalt . $hmacSalt . $iv . $ciphertext;

		$hmac = $this->_generateHmac($binaryData, $password);
		
		return base64_encode($binaryData . $hmac);
	}

	/**
	 * Decrypt RNCryptor-encrypted data
	 *
	 * Adapted from:
	 *
	 *   AES128-apis.php
	 *
	 *   RNCryptor PHP BackEnd Script
	 *   Using kCCAlgorithmAES128
	 *   Advanced Encryption Standard, 128-bit block
	 *   Copyright (c) 2013 Guysung Kim
	 *
	 * Suppport added by Curtis Farnham for RNCryptor file version 1.
	 *
	 * @param string $encrypted Encrypted, Base64-encoded text
	 * @param string $password Password the text was encoded with
	 * @param bool $stripTrailingControlCharacters Whether to strip trailing
	 *                                             non-null padding characters
	 *                                             after decryption
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

	private function _generateKey($salt, $password) {
		return hash_pbkdf2(self::PBKDF2_PRF, $password, $salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);
	}

	private function _getCryptor($versionChr) {
		$mode = $this->_getEncryptionMode($versionChr);
		return mcrypt_module_open(self::ALGORITHM, '', $mode, '');
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
			default:
				throw new Exception('Unsupported version ' . ord($versionChr));
		}
		return $optionsChr;
	}

	private function _generateIv($cryptor) {
		return mcrypt_create_iv(mcrypt_enc_get_iv_size($cryptor), $this->_randomSource);
	}

	private function _generateHmacSalt() {
		return mcrypt_create_iv(self::SALT_SIZE, $this->_randomSource);
	}

	private function _generateHmac($binaryData, $password) {

		$version = ord($this->_extractVersionFromBinData($binaryData));
		switch ($version) {
			case 0:
			case 1:
				$hmac_message = substr($binaryData, 34);
				break;
		
			case 2:
				$hmac_message = $binaryData;
				break;
		}

		$hmac_salt = $this->_extractHmacSaltFromBinData($binaryData);

		$hmac_key = hash_pbkdf2(self::PBKDF2_PRF, $password, $hmac_salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);
		return hash_hmac(self::HMAC_ALGORITHM, $hmac_message, $hmac_key, true);
	}

	private function _padToBlockSizeMultiple($cryptor, $plaintext) {
		$block_size = mcrypt_enc_get_block_size($cryptor);
		$pad_size = $block_size - (strlen($plaintext) % $block_size);
		return $plaintext . str_repeat(chr($pad_size), $pad_size);
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
				$dataWithoutHMAC = substr($binaryData, 0, strlen($binaryData) - self::HMAC_SIZE);
				break;
		}
		
		$hmac = substr($binaryData, strlen($binaryData) - self::HMAC_SIZE);

		$hmac_salt = $this->_extractHmacSaltFromBinData($binaryData);
		$hmac_key = hash_pbkdf2(self::PBKDF2_PRF, $password, $hmac_salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);

		$hmac_hash = hash_hmac(self::HMAC_ALGORITHM, $dataWithoutHMAC , $hmac_key, true);
		
		return ($hmac_hash == $hmac);
	}

	private function _extractVersionFromBinData($binaryData) {
		return substr($binaryData, 0, 1);
	}

	private function _extractSaltFromBinData($binaryData) {
		return substr($binaryData, 2, 8);
	}

	private function _extractHmacSaltFromBinData($binaryData) {
		return substr($binaryData, 10, 8);
	}

	private function _extractIvFromBinData($binaryData) {
		return substr($binaryData, 18, 16);
	}

	private function _extractCiphertextFromBinData($binaryData) {
		return substr($binaryData, 34, strlen($binaryData) - 34 - self::HMAC_SIZE);
	}

	private function _getEncryptionMode($versionChr) {
		switch (ord($versionChr)) {
			case 0:
				$mode = self::RNCRYPTOR_1x_MODE;
				break;
			case 1:
			case 2:
				$mode = self::RNCRYPTOR_2x_MODE;
				break;
			default:
				throw new Exception('Unsupported version ' . ord($versionChr));
		}

		return $mode;
	}

	/**
	 * Ensure the RNCryptor file version is supported
	 * 
	 * @param int $version Version to check
	 * @throws Exception if not supported
	 */
	private function _assertVersionIsSupported($version) {
		if ($version !== 1 && $version !== 2 && $version !== 0) {
			throw new Exception('Unsupported file version ' . $version);
		}
	}
}
