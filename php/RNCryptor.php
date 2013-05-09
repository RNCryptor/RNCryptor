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
	const MODE = MCRYPT_MODE_CBC;
	const SALT_SIZE = 8;
	const PBKDF2_ITERATIONS = 10000;
	const PBKDF2_PRF = 'sha1';
	const HMAC_ALGORITHM = 'sha256';
	const HMAC_SIZE = 32;

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
	 * @return string Encrypted, Base64-encoded text
	 */
	public function encrypt($plaintext, $password, $version = 2) {

		$this->_assertVersionIsSupported($version);

		$versionChr = chr($version);
		$optionsChr = chr(1);  /* We're using a password */

		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
			$random_source = MCRYPT_RAND;
		} else {
			$random_source = MCRYPT_DEV_RANDOM;
		}

		$td = mcrypt_module_open(self::ALGORITHM, '', self::MODE, '');
		$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), $random_source);

		$key_salt = mcrypt_create_iv(self::SALT_SIZE, $random_source);
		$hmac_salt = mcrypt_create_iv(self::SALT_SIZE, $random_source);
		
		$key = hash_pbkdf2(self::PBKDF2_PRF, $password, $key_salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);
		$hmac_key = hash_pbkdf2(self::PBKDF2_PRF, $password, $hmac_salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);
		
		$block_size = mcrypt_enc_get_block_size($td);
		$pad_size = $block_size - (strlen($plaintext) % $block_size);
		$padded_plaintext = $plaintext . str_repeat(chr($pad_size), $pad_size);

		mcrypt_generic_init($td, $key, $iv);
		$encrypted = mcrypt_generic($td, $padded_plaintext);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);

		$message = $versionChr . $optionsChr . $key_salt . $hmac_salt . $iv . $encrypted;
		
		switch ($version) {
			case 1:
				$hmac_message = $encrypted;
				break;

			case 2:
				$hmac_message = $message;
				break;
		}
		
		$hmac = hash_hmac(self::HMAC_ALGORITHM, $hmac_message, $hmac_key, true);
		
		return base64_encode($message . $hmac);
	}

	/**
	 * Decrypt RNCryptor-encrypted text
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
	 * @return string|false Decrypted text, or false if decryption failed
	 */
	public function decrypt($b64_data, $password, $stripTrailingControlCharacters = true) {

		$bin_data = base64_decode($b64_data);

		$versionChr = substr($bin_data, 0, 1);
		$optionsChr = substr($bin_data, 1, 1);
		$salt = substr($bin_data, 2, 8);
		$hmac_salt = substr($bin_data, 10, 8);
		$iv = substr($bin_data, 18, 16);

		$headerLength = 34;

		$data = substr($bin_data, $headerLength, strlen($bin_data) - $headerLength - self::HMAC_SIZE);

		$this->_assertVersionIsSupported(ord($versionChr));
		
		switch (ord($versionChr)) {
			case 1:
				// see http://robnapier.net/blog/rncryptor-hmac-vulnerability-827
				$dataWithoutHMAC = $data;
				break;
			case 2:
				$dataWithoutHMAC = $versionChr.$optionsChr.$salt.$hmac_salt.$iv.$data;
				break;
		}

		$hmac = substr($bin_data, strlen($bin_data) - self::HMAC_SIZE);
		$hmac_key = hash_pbkdf2(self::PBKDF2_PRF, $password, $hmac_salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);
		$hmac_hash = hash_hmac(self::HMAC_ALGORITHM, $dataWithoutHMAC , $hmac_key, true);
		if ($hmac_hash != $hmac) {
			return false;
		}

		$key = hash_pbkdf2(self::PBKDF2_PRF, $password, $salt, self::PBKDF2_ITERATIONS, self::KEY_SIZE, true);

		$cypher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', self::MODE, '');
		if (mcrypt_generic_init($cypher, $key, $iv) != -1) {

			$decrypted = mdecrypt_generic($cypher, $data);

			if ($stripTrailingControlCharacters) {
				// Sometimes the resulting padding is not null characters "\0" but rather one of several control characters.
				// If you know your data is not supposed to have any trailing control characters "as we did" you can strip them like so.
				// See http://www.php.net/manual/en/function.mdecrypt-generic.php
				$decrypted = preg_replace("/\p{Cc}*$/u", "", $decrypted);
			}

			mcrypt_generic_deinit($cypher);
			mcrypt_module_close($cypher);
			return trim($decrypted);
		}
		return false;
	}

	/**
	 * Ensure the RNCryptor file version is supported
	 * 
	 * @param int $version Version to check
	 * @throws Exception if not supported
	 */
	private function _assertVersionIsSupported($version) {
		if ($version !== 1 && $version !== 2) {
			throw new Exception('Unsupported file version ' . $version);
		}
	}
}
