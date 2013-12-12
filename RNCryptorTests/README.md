openssl.enc:
	echo Test data | openssl enc -aes-256-cbc -out test.enc -k Passw0rd

