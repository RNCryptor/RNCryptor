<?php

require_once dirname(__file__) . '/../../RNDecryptor.php';
require_once dirname(__file__) . '/../../RNEncryptor.php';

class RNCryptorTest extends RNCryptorTestCase {

    public static function main() {
        $suite  = new PHPUnit_Framework_TestSuite(get_called_class());
        $result = PHPUnit_TextUI_TestRunner::run($suite);
    }

  	public function testCanDecryptSelfEncryptedDefaultVersion() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(RNCryptorTestCase::PLAINTEXT, RNCryptorTestCase::GOOD_PASSWORD);
  		
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(RNCryptorTestCase::PLAINTEXT_EQUAL_TO_BLOCK_SIZE, RNCryptorTestCase::GOOD_PASSWORD);
  	
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT_EQUAL_TO_BLOCK_SIZE, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion0() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(RNCryptorTestCase::PLAINTEXT, RNCryptorTestCase::GOOD_PASSWORD, 0);
  		
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion1() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(RNCryptorTestCase::PLAINTEXT, RNCryptorTestCase::GOOD_PASSWORD, 1);
  		
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}
  	
  	public function testCanDecryptSelfEncryptedVersion2() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(RNCryptorTestCase::PLAINTEXT, RNCryptorTestCase::GOOD_PASSWORD, 2);
  	
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}
  	
}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == 'RNCryptorTest::main') {
	RNCryptorTest::main();
}

