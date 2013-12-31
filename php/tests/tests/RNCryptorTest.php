<?php

require_once __DIR__ . '/../../RNDecryptor.php';
require_once __DIR__ . '/../../RNEncryptor.php';

class RNCryptorTest extends PHPUnit_Framework_TestCase {

	// relative to __DIR__
	const TEXT_FILENAME = 'lorem-ipsum.txt';

	const SAMPLE_PLAINTEXT = 'What\'s your name?  My name is Tilgath Pilesar.  Why are you crying?';
	const SAMPLE_PASSWORD = 'do-not-write-this-down';
	
	const SAMPLE_PLAINTEXT_V2_BLOCKSIZE = 'Lorem ipsum dolor sit amet, cons';

    public static function main() {
        $suite  = new PHPUnit_Framework_TestSuite(get_called_class());
        $result = PHPUnit_TextUI_TestRunner::run($suite);
    }

  	public function testCanDecryptSelfEncryptedDefaultVersion() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(self::SAMPLE_PLAINTEXT, self::SAMPLE_PASSWORD);
  		
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals(self::SAMPLE_PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(self::SAMPLE_PLAINTEXT_V2_BLOCKSIZE, self::SAMPLE_PASSWORD);
  	
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals(self::SAMPLE_PLAINTEXT_V2_BLOCKSIZE, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion0() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(self::SAMPLE_PLAINTEXT, self::SAMPLE_PASSWORD, 0);
  		
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals(self::SAMPLE_PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion1() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(self::SAMPLE_PLAINTEXT, self::SAMPLE_PASSWORD, 1);
  		
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals(self::SAMPLE_PLAINTEXT, $decrypted);
  	}
  	
  	public function testCanDecryptSelfEncryptedVersion2() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(self::SAMPLE_PLAINTEXT, self::SAMPLE_PASSWORD, 2);
  	
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals(self::SAMPLE_PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptLongText() {

  		$text = file_get_contents(__DIR__ . '/_files/lorem-ipsum.txt');
  	
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt($text, self::SAMPLE_PASSWORD);
  	
  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals($text, $decrypted);
  	}

  	public function testCannotUseWithUnsupportedSchemaVersions() {
  		$fakeSchemaNumber = 57;
  		$encrypted = $this->_generateEncryptedStringWithUnsupportedSchemaNumber($fakeSchemaNumber);
  		$decryptor = new RNDecryptor();
  		$this->setExpectedException('Exception');
  		$decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  	}

  	private function _generateEncryptedStringWithUnsupportedSchemaNumber($fakeSchemaNumber) {
  		$encryptor = new RNEncryptor();
  		$plaintext = 'The price of ice is nice for mice';
  		$encrypted = $encryptor->encrypt($plaintext, self::SAMPLE_PASSWORD);

  		$encryptedBinary = base64_decode($encrypted);
  		$encryptedBinary = chr($fakeSchemaNumber) . substr($encryptedBinary, 1, strlen($encryptedBinary - 1));
  		return base64_encode($encryptedBinary);
  	}
}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == 'RNCryptorTest::main') {
	RNCryptorTest::main();
}

