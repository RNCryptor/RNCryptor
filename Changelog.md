# Version ...

* Remove OpenSSL support. This has been moved to RNOpenSSLCryptor.
* Remove warnings on OS X 10.8
* 
# Version 2.2

Version 2.2 is a fairly large release. It's been almost a year since 2.1 came out, and there are many small and large bug fixes.

V2.2 updates the file format from 2 to 3. It will read format 2 files, but will only write format 3. These are not readable by RNCryptor v2.1. See Issue #77 for details. The PHP, Python, and Ruby implementations also write format 3 and read format 2 or 3.

## Security Issues

* Issue #91:  Use constant time HMAC comparisons to avoid timing attacks
* Issue #77: KeyForPassword() broken for multi-byte passwords (UTF-8)

## Other Noteable Changes

* Improved PHP, Python, and Ruby implementations
* Improved test cases, with test vectors
* Issue #76: Support OSX in podspec
* Resolved static analyzer warnings
* Ensure compatibility with iOS 4.2
* Accept settings to RNDecryptor (Issue #65)
* Copy password rather than retain it (Issue #64)
* Crash when reading v1 header
