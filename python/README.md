Python RNCryptor
----------------

This is a Python port of Rob Napier's Cocoa [RNCryptor](https://github.com/rnapier/RNCryptor/) library. Like RNCryptor, Python RNCryptor intends to be an easy-to-use class that correctly handles random initialization vectors, password stretching with PBKDF2, and HMAC verification.

This port is based on his [Data Format](https://github.com/rnapier/RNCryptor/wiki/Data-Format) wiki page. It currently only implements version 2.

This code should be adapted and copy-pasted into your project (for instance to remove the six dependency)

Requirements:
------------
* Python ≥ 2.5 (Python 3 is supported)
* PyCrypto ≥ 2.6
