<?php

  /* Your data goes here */
  $password = "myPassword";
  $plaintext = "here is my test vector. It's not too long, but more than a block and needs padding";

  /* kRNCryptorAES256Settings */
  $algorithm = MCRYPT_RIJNDAEL_128;
  $key_size = 32;
  $mode = MCRYPT_MODE_CBC;
  $salt_size = 8;
  $pbkdf2_iterations = 10000;
  $pbkdf2_prf = 'sha1';
  $hmac_algorithm = 'sha256';
  $version = chr(2);
  $options = chr(1);  /* We're using a password */

  /* Other settings */
  $random_source = MCRYPT_DEV_RANDOM; /* use MCRYPT_RAND on Windows */

  /* Open the cipher */
  $td = mcrypt_module_open($algorithm, '', $mode, '');

  /* Create the IV and determine the keysize length */
  $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), $random_source);

  /* Create the salts */
  $key_salt = mcrypt_create_iv($salt_size, $random_source);
  $hmac_salt = mcrypt_create_iv($salt_size, $random_source);

  /* Create key */
  $key = hash_pbkdf2($pbkdf2_prf, $password, $key_salt, $pbkdf2_iterations, $key_size, true);
  $hmac_key = hash_pbkdf2($pbkdf2_prf, $password, $hmac_salt, $pbkdf2_iterations, $key_size, true);

  /* Pad data */
  $block_size = mcrypt_enc_get_block_size($td);
  $pad_size = $block_size - (strlen($plaintext) % $block_size);
  $padded_plaintext = $plaintext . str_repeat(chr($pad_size), $pad_size);

  /* Intialize encryption */
  mcrypt_generic_init($td, $key, $iv);

  /* Encrypt data */
  $encrypted = mcrypt_generic($td, $padded_plaintext);

  /* Terminate encryption handler */
  mcrypt_generic_deinit($td);
  mcrypt_module_close($td);

  /* Create message for HMAC */
  $message  = $version . $options . $key_salt . $hmac_salt . $iv . $encrypted;

  /* Generate HMAC */
  $hmac = hash_hmac($hmac_algorithm, $message, $hmac_key, true);

  /* Package the whole thing */
  $envelope = $message . $hmac;

  echo base64_encode($envelope), "\n";

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

?>