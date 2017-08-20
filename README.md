# RNCryptor

[![BuddyBuild](https://dashboard.buddybuild.com/api/statusImage?appID=57ea731dbd45750100873fb1&branch=master&build=latest)](https://dashboard.buddybuild.com/apps/57ea731dbd45750100873fb1/build/latest)

Cross-language AES Encryptor/Decryptor [data format](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md).

The primary targets are Swift and Objective-C, but implementations are available in [C](https://github.com/RNCryptor/RNCryptor-C), [C++](https://github.com/RNCryptor/RNCryptor-cpp), [C#](https://github.com/RNCryptor/RNCryptor-cs), [Erlang](https://github.com/RNCryptor/RNCryptor-erlang), [Go](https://github.com/RNCryptor/RNCryptor-go), [Haskell](https://github.com/RNCryptor/rncryptor-hs), [Java](https://github.com/RNCryptor/JNCryptor),
[PHP](https://github.com/RNCryptor/RNCryptor-php), [Python](https://github.com/RNCryptor/RNCryptor-python),
[Javascript](https://github.com/chesstrian/JSCryptor), and [Ruby](https://github.com/RNCryptor/ruby_rncryptor).

The data format includes all the metadata required to securely implement AES encryption, as described in ["Properly encrypting with AES with CommonCrypto,"](http://robnapier.net/aes-commoncrypto) and [*iOS 6 Programming Pushing the Limits*](http://iosptl.com), Chapter 15. Specifically, it includes:

* AES-256 encryption
* CBC mode
* Password stretching with PBKDF2
* Password salting
* Random IV
* Encrypt-then-hash HMAC

## Contents

* [Format Versus Implementation](#format-versus-implementation)
* [Basic Password Usage](#basic-password-usage)
* [Incremental Usage](#incremental-usage)
* [Installation](#installation)
* [Advanced Usage](#advanced-usage)
* [FAQ](#faq)
* [Design Considerations](#design-considerations)
* [License](#license)

## Format Versus Implementation

The RNCryptor data format is cross-platform and there are many implementations. The framework named "RNCryptor" is a specific implementation for Swift and Objective-C. Both have version numbers. The current data format is v3. The current framework implementation (which reads the v3 format) is v4.

## Basic Password Usage

```swift
// Encryption
let data: NSData = ...
let password = "Secret password"
let ciphertext = RNCryptor.encrypt(data: data, withPassword: password)

// Decryption
do {
    let originalData = try RNCryptor.decrypt(data: ciphertext, withPassword: password)
    // ...
} catch {
    print(error)
}
```

## Incremental Usage

RNCryptor supports incremental use, for example when using with `NSURLSession`. This is also useful for cases where the encrypted or decrypted data will not comfortably fit in memory.

To operate in incremental mode, you create an `Encryptor` or `Decryptor`, call `updateWithData()` repeatedly, gathering its results, and then call `finalData()` and gather its result.

```swift
//
// Encryption
//
let password = "Secret password"
let encryptor = RNCryptor.Encryptor(password: password)
let ciphertext = NSMutableData()

// ... Each time data comes in, update the encryptor and accumulate some ciphertext ...
ciphertext.appendData(encryptor.updateWithData(data))

// ... When data is done, finish up ...
ciphertext.appendData(encryptor.finalData())

//
// Decryption
//
let password = "Secret password"
let decryptor = RNCryptor.Decryptor(password: password)
let plaintext = NSMutableData()

// ... Each time data comes in, update the decryptor and accumulate some plaintext ...
try plaintext.appendData(decryptor.updateWithData(data))

// ... When data is done, finish up ...
try plaintext.appendData(decryptor.finalData())
```

### Importing into Swift

Most RNCryptor symbols are nested inside an `RNCryptor` namespace.

## Installation

### Requirements

RNCryptor 5 is written in Swift 3 and does not bridge to Objective-C (it includes features that are not available). If you want an ObjC implementation, see [RNCryptor-objc](https://github.com/RNCryptor/RNCryptor-objc). That version can be accessed from Swift, or both versions can coexist in the same project.

### The Bridging Header

CommonCrypto is not a modular header (and Apple has suggested it may never be). This makes it very challenging to import into Swift. To work around this, the necessary header files have been copied into `RNCryptor.h`, which needs to be bridged into Swift. You can do this either by using RNCryptor as a framework, adding `#import "RNCryptor/RNCryptor.h"` to your existing bridging header, or making `RNCryptor/RNCryptor.h` your bridging header in Build Settings, "Objective-C Bridging Header."

### Installing Manually

The easiest way to use RNCryptor is by making it part of your project, without a framework. RNCryptor is just one swift file and one bridging header, and you can skip all the complexity of managing frameworks this way. It also makes version control very simple if you use submodules, or checkin specific versions of RNCryptor to your repository.

This process works for most targets: iOS and OS X GUI apps, Swift frameworks, and OS X commandline apps. **It is not safe for ObjC frameworks or frameworks that may be imported into ObjC, since it would cause duplicate symbols if some other framework includes RNCryptor.**

* Drag and link `RNCryptor/RNCryptor.swift` and `RNCryptor.h` into your project
* If you already have a bridging header file, add `#import "RNCryptor.h"` (or the path to which you copied `RNCryptor.h`).
* If you don't have a bridging header:
  * Swift project: In your target's Build Settings, set "Objective-C Bridging Header" to your path for `RNCryptor.h`. (Or create a bridiging header and follow instructions above.)
  * ObjC project: Xcode will ask if you want to create a bridging header. Allow it to, and add `#import "RNCryptor.h"` to the header (or the path to which you copied `RNCryptor.h`)
* To access RNCryptor from Swift, you don't need to import anything. It's just part of your module.
* To access RNCryptor from ObjC, import your Swift header (*modulename*-Swift.h). For example: `#import "MyApp-Swift.h"`.

Built this way, you don't need to (and can't) `import RNCryptor` into your code. RNCryptor will be part of your module.

### [Carthage](https://github.com/Carthage/Carthage)

    github "RNCryptor/RNCryptor" ~> 5.0

This approach will not work for OS X commandline apps. Don't forget to embed `RNCryptor.framework`. 

Built this way, you should add `@import RNCryptor;` to your ObjC or `import RNCryptor` to your Swift code.

This approach will not work for OS X commandline apps.

### [CocoaPods](https://cocoapods.org)

    pod 'RNCryptor', '~> 5.0'

This approach will not work for OS X commandline apps.

Built this way, you should add `import RNCryptor` to your Swift code.

## Advanced Usage

### Version-Specific Cryptors

The default `RNCryptor.Encryptor` is the "current" version of the data format (currently v3). If you're interoperating with other implementations, you may need to choose a specific format for compatibility.

To create a version-locked cryptor, use `RNCryptor.EncryptorV3` and `RNCryptor.DecryptorV3`.

Remember: the version specified here is the *format* version, not the implementation version. The v4 RNCryptor framework reads and writes the v3 RNCryptor data format.

### Key-Based Encryption

*You need a little expertise to use key-based encryption correctly, and it is very easy to make insecure systems that look secure. The most important rule is that keys must be random across all their bytes. If you're not comfortable with basic cryptographic concepts like AES-CBC, IV, and HMAC, you probably should avoid using key-based encryption.*

Cryptography works with keys, which are random byte sequences of a specific length. The RNCryptor v3 format uses two 256-bit (32-byte) keys to perform encryption and authentication.

Passwords are not "random byte sequences of a specific length." They're not random at all, and they can be a wide variety of lengths, very seldom exactly 32. RNCryptor defines a specific and secure way to convert passwords into keys, and that is one of it's primary features.

Occasionally there are reasons to work directly with random keys. Converting a password into a key is intentionally slow (tens of milliseconds). Password-encrypted messages are also a 16 bytes longer than key-encrypted messages. If your system encrypts and decrypts many short messages, this can be a significant performance impact, particularly on a server.

RNCryptor supports direct key-based encryption and decryption. The size and number of keys may change between format versions, so key-based cryptors are [version-specific](#version-specific-cryptors).

In order to be secure, the keys must be a random sequence of bytes. See [Converting a Password to a Key](#converting-a-password-to-a-key) for how to create random sequences of bytes if you only have a password.

```swift
let encryptor = RNCryptor.EncryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey)
let decryptor = RNCryptor.DecryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey)
```

## FAQ

### How do I detect an incorrect password?

If you decrypt with the wrong password, you will receive an `HMACMismatch` error. This is the same error you will receive if your ciphertext is corrupted.

The v3 data format has no way to detect incorrect passwords directly. It just decrypts gibberish, and then uses the HMAC (a kind of encrypted hash) to determine that the result is corrupt. You won't discover this until the entire message has been decrypted (during the call to `finalData()`).

This can be inconvenient for the user if they have entered the wrong password to decrypt a very large file. If you have this situation, the recommendation is to encrypt some small, known piece of data with the same password. Test the password on the small ciphertext before decrypting the larger one.

The [v4 data format](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/draft-RNCryptor-Spec-v4.0.md) will provide a faster and more useful mechanism for validating the password or key.

### What is an "HMAC Error?" (Error code 1)

See previous question. Either your data is corrupted or you have the wrong password.

The most common cause of this error (if your password is correct) is that you have misunderstood how [Base64 encoding](https://en.wikipedia.org/wiki/Base64) works while transferring data to or from the server. If you have a string like "YXR0YWNrIGF0IGRhd24=", this is not "data." This is a string. It is probably Base64 encoded, which is a mechanism for converting data into strings. Some languages (JavaScript, PHP) have a habit of implicitly converting between data into Base64 strings, which is confusing and error-prone (and the source of many of these issues). Simple rule: if you can print it out without your terminal going crazy, it's not encrypted data.

If you convert a Base64-encoded string to data using `dataUsingEncoding()`, you will get gibberish as far as RNCryptor is concerned. You need to use `init?(base64EncodedData:options:)`. Depending on the options on the iOS side or the server side, spaces and newlines may matter. You need to verify that precisely the bytes that came out of the encryptor are the bytes that go into the decryptor.

### Can I use RNCryptor to read and write my non-RNCryptor data format?

No. RNCryptor implements a specific data format. It is not a general-purpose encryption library. If you have created your own data format, you will need to write specific code to deal with whatever you created. Please make sure the data format you've invented is secure. (This is much harder than it sounds.)

If you're using the OpenSSL encryption format, see [RNOpenSSLCryptor](https://github.com/rnapier/RNOpenSSLCryptor).

### Can I change the parameters used (algorithm, iterations, etc)?

No. See previous question. The [v4 format](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/draft-RNCryptor-Spec-v4.0.md) will permit some control over PBKDF2 iterations, but the only thing configurable in the v3 format is whether a password or key is used. This keeps RNCryptor implementations dramatically simpler and interoperable.

### How do I manually set the IV?

You don't. See the last two questions.

Also note that if you ever reuse a key+IV combination, you risk attackers decrypting the beginning of your message. A static IV makes a key+IV reuse much more likely (guarenteed if you also have a static key). Wikipedia has a [quick overview of this problem](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_.28IV.29).

### How do I encrypt/decrypt a string?

AES encrypts bytes. It does not encrypt characters, letters, words, pictures, videos, cats, or ennui. It encrypts bytes. You need to convert other things (such as strings) to and from bytes in a consistent way. There are several ways to do that. Some of the most popular are UTF-8 encoding, Base-64 encoding, and Hex encoding. There are many other options. There is no good way for RNCryptor to guess which encoding you want, so it doesn't try. It accepts and returns bytes in the form of `NSData`.

To convert strings to data as UTF-8, use `dataUsingEncoding()` and `init(data:encoding:)`. To convert strings to data as Base-64, use `init(base64EncodedString:options:)` and `base64EncodedStringWithOptions()`.

### Does RNCryptor support random access decryption?

The usual use case for this is encrypting media files like video. RNCryptor uses CBC encryption, which prevents easy random-access. While other modes are better for random-access (CTR for instance), they are more complicated to implement correctly and CommonCrypto doesn't support using them for random access anyway.

It would be fairly easy to build a wrapper around RNCryptor that allowed random-access to blocks of some fixed size (say 64k), and that might work well for video with modest overhead (see [inferno](http://securitydriven.net/inferno/) for a similar idea in C#). Such a format would be fairly easy to port to other platforms that already support RNCryptor.

If there is interest, I may eventually build this as a separate framework.

See also [Issue #161](https://github.com/RNCryptor/RNCryptor/issues/161) for a much longer discussion of this topic.

## Design Considerations

`RNCryptor` has several design goals, in order of importance:

### Easy to use correctly for most common use cases

The most critical concern is that it be easy for non-experts to use `RNCryptor` correctly. A framework that is more secure, but requires a steep learning curve on the developer will either be not used, or used incorrectly. Whenever possible, a single line of code should "do the right thing" for the most common cases.

This also requires that it fail correctly and provide good errors.

### Reliance on CommonCryptor functionality

`RNCryptor` has very little "security" code. It relies as much as possible on the OS-provided CommonCryptor. If a feature does not exist in CommonCryptor, then it generally will not be provided in `RNCryptor`.

### Best practice security

Wherever possible within the above constraints, the best available algorithms
are applied. This means AES-256, HMAC+SHA256, and PBKDF2. (Note that several of these decisions were reasonable for v3, but may change for v4.)

* AES-256. While Bruce Schneier has made some interesting recommendations
regarding moving to AES-128 due to certain attacks on AES-256, my current
thinking is in line with [Colin
Percival](http://www.daemonology.net/blog/2009-07-31-thoughts-on-AES.html).
PBKDF2 output is effectively random, which should negate related-keys attacks
against the kinds of use cases we're interested in.

* AES-CBC mode. This was a somewhat complex decision, but the ubiquity of CBC
outweighs other considerations here. There are no major problems with CBC mode,
and nonce-based modes like CTR have other trade-offs. See ["Mode changes for
RNCryptor"](http://robnapier.net/mode-rncryptor) for more details on this
decision.

* Encrypt-then-MAC. If there were a good authenticated AES mode on iOS (GCM for
instance), I would probably use that for its simplicity. Colin Percival makes
[good arguments for hand-coding an encrypt-then-MAC](http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html) rather
than using an authenticated AES mode, but in RNCryptor mananging the HMAC
actually adds quite a bit of complexity. I'd rather the complexity at a more
broadly peer-reviewed layer like CommonCryptor than at the RNCryptor layer. But
this isn't an option, so I fall back to my own Encrypt-than-MAC.

* HMAC+SHA256. No surprises here.

* PBKDF2. While bcrypt and scrypt may be more secure than PBKDF2, CommonCryptor
only supports PBKDF2. [NIST also continues to recommend
PBKDF2](http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage). We use 10k rounds of PBKDF2
which represents about 80ms on an iPhone 4.

### Code simplicity

RNCryptor endeavors to be implemented as simply as possible, avoiding tricky code. It is designed to be easy to read and code review.

### Performance

Performance is a goal, but not the most important goal. The code must be secure
and easy to use. Within that, it is as fast and memory-efficient as possible.

### Portability

Without sacrificing other goals, it is preferable to read the output format of
`RNCryptor` on other platforms.

## License

Except where otherwise indicated in the source code, this code is licensed under
the MIT License:

>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. ```
