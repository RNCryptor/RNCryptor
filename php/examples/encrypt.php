<?php

require_once dirname(__FILE__) . '/../RNCryptor.php';

$password = "myPassword";
$plaintext = "Here is my test vector. It's not too long, but more than a block and needs padding.";

$rncryptor = new RNCryptor();
$base64Encrypted = $rncryptor->encrypt($plaintext, $password);

echo "Plaintext: $plaintext\n";
echo "Base64 Encrypted: $base64Encrypted\n";
