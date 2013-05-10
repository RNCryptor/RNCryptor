<?php

require_once dirname(__file__) . '/../../RNEncryptor.php';
require_once dirname(__file__) . '/../RNCryptorTestCase.php';

class RNEncryptorTest extends PHPUnit_Framework_TestCase {

    public static function main() {
        $suite  = new PHPUnit_Framework_TestSuite(get_called_class());
        $result = PHPUnit_TextUI_TestRunner::run($suite);
    }

    public function testCanEncryptWithDefaultVersion() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD);
    	$this->assertNotEmpty($encrypted);
    }

    public function testCanEncryptWithVersion0() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD, 0);
    	$this->assertNotEmpty($encrypted);
    }
    
    public function testCanEncryptWithVersion1() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD, 1);
    	$this->assertNotEmpty($encrypted);
    }
    
    public function testCanEncryptWithVersion2() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD, 2);
    	$this->assertNotEmpty($encrypted);
    }

    public function testSelfEncryptedVersion0VectorIsVersion0() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD, 0);
    	$actualVersion = ord(substr(base64_decode($encrypted), 0, 1));
    	$this->assertEquals(0, $actualVersion);
    }
    
    public function testSelfEncryptedVersion1VectorIsVersion1() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD, 1);
    	$actualVersion = ord(substr(base64_decode($encrypted), 0, 1));
    	$this->assertEquals(1, $actualVersion);
    }

    public function testSelfEncryptedVersion2VectorIsVersion2() {
    	$encryptor = new RNEncryptor();
    	$encrypted = $encryptor->encrypt(RNCryptorTest::PLAINTEXT, RNCryptorTest::GOOD_PASSWORD, 2);
    	$actualVersion = ord(substr(base64_decode($encrypted), 0, 1));
    	$this->assertEquals(2, $actualVersion);
    }

}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == 'RNEncryptorTest::main') {
	RNEncryptorTest::main();
}

