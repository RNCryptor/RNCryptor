<?php

require_once dirname(__FILE__) . '/../RNEncryptor.php';

$password = "myPassword";
$plaintext = "Here is my test vector. It's not too long, but more than a block and needs padding.";

$cryptor = new RNEncryptor();
$base64Encrypted = $cryptor->encrypt($plaintext, $password);

echo "Plaintext: $plaintext\n";
echo "\n";
echo "Base64 Encrypted: $base64Encrypted\n";
echo "\n";