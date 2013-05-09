<?php

require_once dirname(__file__) . '/../../RNCryptor.php';

class RNCryptorTest extends PHPUnit_Framework_TestCase {

	const GOOD_PASSWORD = 'mypassword123$!';
	const BAD_PASSWORD = 'wrongpass';

	const PLAINTEXT = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...';

	const IOS_ENCRYPTED_V0 = 'AADu55As8qH9KsSR17p1akydMUlbHrsHudMOr/yTj4olfQedJPTZg8hK4ua99zNkj3Nw7Hle1f1onHclWIYoLkWtMVk4Cp96CcxRhaWbBZqAVvTabtVruxcAi+GEB2K4rrmyARxB2QJH9tfz2yTFoFNMln+xOCUm0wAAAAAAAAAAAAAAAA==';
	const IOS_ENCRYPTED_V1 = 'AQE9u3aB1APkWDRHcfy1cvD3kwwoXUw+8JhtCkZ3xDkSQghIyFoqLgazX3cXBxv3Mj75sSofHoDI35KaFTdXovY3HQYAaQmMdPNvSRVGvlptkyr5LSBMUA3/Uj7lmhnaf515pN8pUbcbOV8RP+oWhXX4iKN009mrcMaX2j1KQz2JfFj8bfpbu9BOtj+1NotIe14=';
	const IOS_ENCRYPTED_V2 = 'AgG8X+ixN6HN9zFnuK1NMJAPntIuC0+WPsmFhGL314zLuq1T9xWDHYzpnzW8EqDz81Amj36+EqrjazQ1gO9ao6bpMwUKdT2xY4ZUrhtCQm3LD2okbEIGjj5dtMJtB3i759WdnmNf8K0ULDWNzNQHPzdNDcEE2BPh+2kRaqVzWyBOzJppJoD5n+WdglS7BEBU+4U=';

    public static function main() {
        $suite  = new PHPUnit_Framework_TestSuite(get_called_class());
        $result = PHPUnit_TextUI_TestRunner::run($suite);
    }

    public function testCanEncryptWithDefaultVersion() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD);
    	$this->assertNotEmpty($encrypted);
    }

    public function testCanEncryptWithVersion0() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 0);
    	$this->assertNotEmpty($encrypted);
    }
    
    public function testCanEncryptWithVersion1() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 1);
    	$this->assertNotEmpty($encrypted);
    }
    
    public function testCanEncryptWithVersion2() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 2);
    	$this->assertNotEmpty($encrypted);
    }
    
    public function testSelfEncryptedVersion0VectorIsVersion0() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 0);
    	$actualVersion = ord(substr(base64_decode($encrypted), 0, 1));
    	$this->assertEquals(0, $actualVersion);
    }
    
    public function testSelfEncryptedVersion1VectorIsVersion1() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 1);
    	$actualVersion = ord(substr(base64_decode($encrypted), 0, 1));
    	$this->assertEquals(1, $actualVersion);
    }

    public function testSelfEncryptedVersion2VectorIsVersion2() {
    	$cryptor = new RNCryptor();
    	$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 2);
    	$actualVersion = ord(substr(base64_decode($encrypted), 0, 1));
    	$this->assertEquals(2, $actualVersion);
    }

  	public function testCanDecryptSelfEncryptedDefaultVersion() {
  		$cryptor = new RNCryptor();
  		$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD);
  		$decrypted = $cryptor->decrypt($encrypted, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion0() {
  		$cryptor = new RNCryptor();
  		$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 0);
  		$decrypted = $cryptor->decrypt($encrypted, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion1() {
  		$cryptor = new RNCryptor();
  		$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 1);
  		$decrypted = $cryptor->decrypt($encrypted, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptSelfEncryptedVersion2() {
  		$cryptor = new RNCryptor();
  		$encrypted = $cryptor->encrypt(self::PLAINTEXT, self::GOOD_PASSWORD, 2);
  		$decrypted = $cryptor->decrypt($encrypted, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptIosEncryptedVersion0() {
  		$cryptor = new RNCryptor();
  		$decrypted = $cryptor->decrypt(self::IOS_ENCRYPTED_V0, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}

  	public function testCanDecryptIosEncryptedVersion1() {
  		$cryptor = new RNCryptor();
  		$decrypted = $cryptor->decrypt(self::IOS_ENCRYPTED_V1, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}
  	
  	public function testCanDecryptIosEncryptedVersion2() {
  		$cryptor = new RNCryptor();
  		$decrypted = $cryptor->decrypt(self::IOS_ENCRYPTED_V2, self::GOOD_PASSWORD);
  		$this->assertEquals(self::PLAINTEXT, $decrypted);
  	}

  	public function testDecryptingWithBadPasswordFails() {
  		$cryptor = new RNCryptor();
  		$decrypted = $cryptor->decrypt(self::IOS_ENCRYPTED_V2, self::BAD_PASSWORD);
  		$this->assertEquals(false, $decrypted);
  	}
  	
}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == 'RNCryptorTest::main') {
	RNCryptorTest::main();
}

