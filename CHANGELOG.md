# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [5.1.0](https://github.com/RNCryptor/RNCryptor/releases/tag/5.1.0)

* Update to Swift 5
* Uses CommonCrypto modular headers (available since 4.2)

## [5.0.3](https://github.com/RNCryptor/RNCryptor/releases/tag/5.0.3)

*  #272. Correct warnings related to incorrect memory access. The previous code was invalid Swift (it accessed a value inside its own `withUnsafeBytes` block), but happened to work.
* Removes a `Data.init` work-around that is no longer needed.

## [5.0.2](https://github.com/RNCryptor/RNCryptor/releases/tag/5.0.2)

* Update Swift Package Manager support
* Update Linux support
* Add tvOS support
* Update to Xcode 9.1 settings
* Update to Swift 4 (no code changes; completely backward compatible)
* Remove code coverage from Release builds (necessary for Carthage)

## [5.0.1](https://github.com/RNCryptor/RNCryptor/releases/tag/5.0.1)

* Perform final decryption after HMAC validation. Fixes #185. This improves security very slightly. There is no known or proposed attack that could exploit the previous behavior, but where possible it is better to validate prior to decryption.
* Fix CocoaPods

## [5.0.0](https://github.com/RNCryptor/RNCryptor/releases/tag/5.0.0) Swift 3.0. Drop ObjC bridge.

* Rework for Swift 3
* Drops ObjC bridging. There are too many problems with the Swift compiler at this point to support this cleanly. ObjC code should use [RNCryptor-ObjC](https://github.com/RNCryptor/RNCryptor-ObjC).
* #159 Add WatchOS support to Podspec
* Better debugging output in case of unexpected cryptor failure
* Added Examples/KeyDerivation to explain how to manually derive keys

## [4.0.0](https://github.com/RNCryptor/RNCryptor/releases/tag/4.0.0) - Complete rewrite in Swift with ObjC bridging

* No changes from beta except version bump

## [4.0.0-beta.1](https://github.com/RNCryptor/RNCryptor/releases/tag/4.0.0-beta.1) - Complete rewrite in Swift with ObjC bridging

## [3.0.1](https://github.com/RNCryptor/RNCryptor/releases/tag/RNCryptor-3.0.1) - CocoaPods fixes (Current ObjC Version)

### Fixed
* Removed private headers from CocoaPods

## [3.0.0](https://github.com/RNCryptor/RNCryptor/releases/tag/RNCryptor-3.0.0) - Remove OpenSSL

### Breaking
* Remove OpenSSL support. This has been moved to [rnapier/RNOpenSSLCryptor](https://github.com/rnapier/RNOpenSSLCryptor).

### Added
* Integrates with Swift as a framework
* Remove warnings on OS X 10.8

## [2.2](https://github.com/RNCryptor/RNCryptor/releases/tag/RNCryptor-2.2) - Data format v3

Version 2.2 is a fairly large release. It's been almost a year since 2.1 came out, and there are many small and large bug fixes.

V2.2 updates the file format from 2 to 3. It will read format 2 files, but will only write format 3. These are not readable by RNCryptor v2.1. See Issue #77 for details. The PHP, Python, and Ruby implementations also write format 3 and read format 2 or 3.

### Security

* Issue #91:  Use constant time HMAC comparisons to avoid timing attacks
* Issue #77: KeyForPassword() broken for multi-byte passwords (UTF-8)

### Changes

* Improved PHP, Python, and Ruby implementations
* Improved test cases, with test vectors
* Issue #76: Support OSX in podspec
* Resolved static analyzer warnings
* Ensure compatibility with iOS 4.2
* Accept settings to RNDecryptor (Issue #65)
* Copy password rather than retain it (Issue #64)
* Crash when reading v1 header
