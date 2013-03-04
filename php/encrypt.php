<?php

  require_once("crypt-common.inc");

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

?>