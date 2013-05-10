<?php

require_once dirname(__file__) . '/../../RNDecryptor.php';
require_once dirname(__file__) . '/../RNCryptorTestCase.php';

class RNDecryptorTest extends RNCryptorTestCase {

    public static function main() {
        $suite  = new PHPUnit_Framework_TestSuite(get_called_class());
        $result = PHPUnit_TextUI_TestRunner::run($suite);
    }

  	public function testCanDecryptIosEncryptedVersion0() {
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt(RNCryptorTestCase::IOS_ENCRYPTED_V0, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptIosEncryptedVersion1() {
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt(RNCryptorTestCase::IOS_ENCRYPTED_V1, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}
  	
  	public function testCanDecryptIosEncryptedVersion2() {
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt(RNCryptorTestCase::IOS_ENCRYPTED_V2, RNCryptorTestCase::GOOD_PASSWORD);
  		$this->assertEquals(RNCryptorTestCase::PLAINTEXT, $decrypted);
  	}

  	public function testDecryptingWithBadPasswordFails() {
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt(RNCryptorTestCase::IOS_ENCRYPTED_V2, RNCryptorTestCase::BAD_PASSWORD);
  		$this->assertEquals(false, $decrypted);
  	}
  	
}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == 'RNDecryptorTest::main') {
	RNDecryptorTest::main();
}

