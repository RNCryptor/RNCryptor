<?php

require_once __DIR__ . '/../RNEncryptor.php';

$password = "myPassword";
$plaintext = "Here is my test vector. It's not too long, but more than a block and needs padding.";

$cryptor = new RNEncryptor();
$base64Encrypted = $cryptor->encrypt($plaintext, $password);

echo "Plaintext:\n$plaintext\n\n";
echo "Base64 Encrypted:\n$base64Encrypted\n\n";
