<?php

if (!function_exists('hash_pbkdf2')) {

	/**
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
}
