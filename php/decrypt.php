<?php

//
//  AES128-apis.php
//
//  RNCryptor PHP BackEnd Script
//  Using kCCAlgorithmAES128  
//  Advanced Encryption Standard, 128-bit block
//
//  Copyright (c) 2013 Guysung Kim
//
//
//

define('IV_SIZE', 24);
define('SALT_SIZE', 12);
define('HMAC_SIZE', 44);
$gPassword = "myPassword";

/*
	// Corresponding iOS encrypt codes example.
	// Use the CPCryptController from https://github.com/iosptl/ios6ptl/blob/master/ch15/CryptPic/CryptPic/RNCryptManager.m
	if (! [[CPCryptController sharedController] encryptData:srcData password:kRNCryptorPasswd error:&error] ) {
		NSLog(@"Could not encrypt data: %@", error);
	}
	
	// Do Base64 encoding for AES128 encrypted data
	NSString *saltBase64 = [[CPCryptController sharedController].salt base64EncodedString];
	NSString *HMACSaltBase64 = [[CPCryptController sharedController].HMACSalt base64EncodedString];
	NSString *ivBase64 = [[CPCryptController sharedController].iv base64EncodedString];
	NSString *encryptedDataBase64 = [[CPCryptController sharedController].encryptedData base64EncodedString];
	NSString *HMACBase64 = [[CPCryptController sharedController].HMAC base64EncodedString];
	
	// Build the final format
	NSString *encryptedDataBase64Final = [NSString stringWithFormat:@"%@%@%@%@%@",saltBase64, HMACSaltBase64, ivBase64, encryptedDataBase64, HMACBase64];
	DebugLog(@"encryptedDataBase64Final: %@",encryptedDataBase64Final );
	
	//If no error we send the post, voila!
	if (!error) {
		
		NSMutableDictionary *params = [[NSMutableDictionary alloc] init];
		
		// Post enctypted
		[params setObject:encryptedDataBase64Final forKey:@"json_encrypted_base64"];
		
		// Do Post!
		[[RKClient sharedClient] post:postResourcePath params:params delegate:self];
		
	}
*/

function decrypt_data($data) {
  global $gPassword;

  /* kRNCryptorAES256Settings */
  $algorithm = MCRYPT_RIJNDAEL_128;
  $key_size = 16;
  $mode = MCRYPT_MODE_CBC;
  $pbkdf2_iterations = 10000;
  $pbkdf2_prf = 'sha1';
  $hmac_algorithm = 'sha256';

  // extract salt
  $salt = substr($data, 0, SALT_SIZE); 
  $salt = base64_decode($salt);
  // Remove $salt from $data.
  $data = substr($data, SALT_SIZE); 

  // extract HMAC salt
  $hmac_salt = substr($data, 0, SALT_SIZE);
  $hmac_salt = base64_decode($hmac_salt);
  // Remove $hmac_salt from $data.
  $data = substr($data, SALT_SIZE); 

  // extract IV
  $iv = substr($data, 0, IV_SIZE);
  $iv = base64_decode($iv);
  // Remove $iv from $data.
  $data = substr($data, IV_SIZE); 

  // extract data
  $final_data = substr($data, 0, strlen($data) - HMAC_SIZE);
  $final_data = base64_decode($final_data);

  // extract HMAC
  $hmac = substr($data, strlen($data)-HMAC_SIZE);
  $hmac = base64_decode($hmac);

  // make HMAC key
  $hmac_key = hash_pbkdf2($pbkdf2_prf, $gPassword, $hmac_salt, $pbkdf2_iterations, $key_size, true);

  // make HMAC hash
  $hmac_hash = hash_hmac($hmac_algorithm, $final_data , $hmac_key, true);

  // check if HMAC hash matches HMAC : HMAC inteegrity checking
  if($hmac_hash != $hmac) {
   echo 'HMAC integrity check has been failed...';  
   return false;
  }

  // make data key
  $key = hash_pbkdf2($pbkdf2_prf, $gPassword, $salt, $pbkdf2_iterations, $key_size, true);

  $cypher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
  // initialize encryption handle
  if (mcrypt_generic_init($cypher, $key, $iv) != -1) {
          // decrypt
          $decrypted = mdecrypt_generic($cypher, $final_data);

          // http://www.php.net/manual/en/function.mdecrypt-generic.php
          // We found that sometimes the resulting padding is not null characters "\0" but rather one of several control characters.
          // If you know your data is not supposed to have any trailing control characters "as we did" you can strip them like so.
          $decrypted = preg_replace( "/\p{Cc}*$/u", "", $decrypted ); 

          // clean up
          mcrypt_generic_deinit($cypher);
          mcrypt_module_close($cypher);

          return trim($decrypted);
  }

  return false;
}


/*
 * Based on pbkdf2() from https://defuse.ca/php-pbkdf2.htm. Made signature-compatible with hash_pbkdf2() in PHP5.5
 *
 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
 * $algorithm - The hash algorithm to use. Recommended: SHA256
 * $password - The password.
 * $salt - A salt that is unique to the password.
 * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
 * $key_length - The length of the derived key in bytes.
 * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
 * Returns: A $key_length-byte key derived from the password and salt.
 *
 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
 *
 * This implementation of PBKDF2 was originally created by https://defuse.ca
 * With improvements by http://www.variations-of-shadow.com
 */
function hash_pbkdf2($algorithm, $password, $salt, $count, $key_length = 0, $raw_output = false)
{
  $algorithm = strtolower($algorithm);
  if(!in_array($algorithm, hash_algos(), true))
    die('PBKDF2 ERROR: Invalid hash algorithm.');
  if($count <= 0 || $key_length <= 0)
    die('PBKDF2 ERROR: Invalid parameters.');

  $hash_length = strlen(hash($algorithm, "", true));
  $block_count = ceil($key_length / $hash_length);

  $output = "";
  for($i = 1; $i <= $block_count; $i++) {
        // $i encoded as 4 bytes, big endian.
    $last = $salt . pack("N", $i);
        // first iteration
    $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
        // perform the other $count - 1 iterations
    for ($j = 1; $j < $count; $j++) {
      $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
    }
    $output .= $xorsum;
  }

  if($raw_output)
    return substr($output, 0, $key_length);
  else
    return bin2hex(substr($output, 0, $key_length));
}


