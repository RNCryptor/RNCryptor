<?php

require_once dirname(__FILE__) . '/../RNCryptor.php';

$password = "myPassword";
$base64Encrypted = "AgGXutvFqW9RqQuokYLjehbfM7F+8OO/2sD8g3auA+oNCQFoarRmc59qcKJve7FHyH9MkyJWZ4Cj6CegDU+UbtpXKR0ND6UlfwaZncRUNkw53jy09cgUkHRJI0gCfOsS4rXmRdiaqUt+ukkkaYfAJJk/o3HBvqK/OI4qttyo+kdiLbiAop5QQwWReG2LMQ08v9TAiiOQgFWhd1dc+qFEN7Cv";

$rncryptor = new RNCryptor();
$plaintext = $rncryptor->decrypt($base64Encrypted, $password);

echo "Base64 Encrypted: $base64Encrypted\n";
echo "Plaintext: $plaintext\n";
