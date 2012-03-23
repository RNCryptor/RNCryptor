# Overview

Encryptor/Decryptor for iOS
 
Provides an easy-to-use, Objective-C interface to the AES functionality of CommonCrypto. Simplifies correct handling of
password stretching (PBKDF2), salting, and IV. For more information on these terms, see ["Properly encrypting with AES
with CommonCrypto,"](http://robnapier.net/blog/aes-commoncrypto-564) and [iOS 5 Programming Pushing the Limits](http://iosptl.com), Chapter 11.
Also includes automatic HMAC handling to integrity-check messages.

`RNCryptor` is immutable, stateless and thread-safe. A given cryptor object may be used simultaneously on multiple
threads, and can be reused to encrypt or decrypt an arbitrary number of independent messages.

# Use

The most common in-memory use case is as follows:

    NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *encrypted = [[RNCryptor AES256Cryptor] encryptData:data password:@"password" error:&error];

This generates an `NSData` including an encryption salt, an HMAC salt, an IV, the ciphertext, and an HMAC. To decrypt this bundle:

    NSData *decrypted = [[RNCryptor AES256Cryptor] decryptData:encrypted password:@"password" error:&error];

The same encryption and decryption can be processed from one `NSURL` or `NSStream` to another to minimize memory usage:

    BOOL result = [[RNCryptor AES256Cryptor] encryptFromURL:plaintextURL
              									      toURL:ciphertextURL 
												     append:NO 
												   password:password 
												      error:&error];

    BOOL result = [[RNCryptor AES256Cryptor] decryptFromURL:ciphertextURL
              									      toURL:plaintextURL
												     append:NO 
												   password:password 
												      error:&error];

# API Documentation

Full API information is available at http://rnapier.github.com/RNCryptor/doc/html/Classes/RNCryptor.html.

# Building

Comes packaged as a static library, but the `RNCryptor.h` and `RNCryptor.m` files can be dropped into any project.

Requires `Security.framework`.

NOTE: Mac support should be possible, but requires replacing `SecCopyRandomBytes()` and switching from AES-CTR to AES-CBC (at least in 10.7).

# Design considerations

`RNCryptor` has several design goals, in order of importance:

## Easy to use correctly for most common use cases

The most critical concern is that it be easy for non-experts to use `RNCryptor` correctly. A framework that is more secure, but requires a steep learning curve on the developer will either be not used, or used incorrectly. Whenever possible, a single line of code should "do the right thing" for the most common cases.

This also requires that it fail correctly and provide good errors.

## Reliance on CommonCryptor functionality

`RNCryptor` has very little "security" code. It relies as much as possible on the OS-provided CommonCryptor. If a feature does not exist in CommonCryptor, then it generally will not be provided in `RNCryptor`.

## Best practice security

Wherever possible within the above constraints, the best available algorithms are applied. This means AES-256, HMAC+SHA1, and PBKDF2:

* AES-256. While Bruce Schneier has made some interesting recommendations regarding moving to AES-128 due to certain attacks on AES-256, my current thinking is in line with Colin Percival here: http://www.daemonology.net/blog/2009-07-31-thoughts-on-AES.html. PBKDF2 output is effectively random, which should negate related-keys attacks against the kinds of use cases we're interested in.

* HMAC+SHA256. No surprises here.

* Encrypt-then-MAC. While `RNCryptor` does not exploit all the advantages of this approach (for instance, by design it cannot validate the HMAC prior to decrypting the stream), I still believe the Encrypt-then-MAC approach makes sense. For more discusion, see http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html.

* PBKDF2. While bcrypt and scrypt may be more secure than PBKDF2, CommonCryptor only supports PBKDF2. NIST also continues to recommend PBKDF2. http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage We use 10k rounds of PBKDF2 which represents about 80ms on an iPhone 4.

## Code simplicity

`RNCryptor` endeavors to be implemented as simply as possible, avoiding tricky code. It is designed to be easy to read and code review.

## Performance

Performance is a goal, but not the most important goal. The code must be secure and easy to use. Within that, it is as fast and memory-efficient as possible.

## Portability

Without sacrificing other goals, it is preferable to read the output format of `RNCryptor` on other platforms. It would be nice if the format were easy to read or write in PHP or Java. Similarly, it would be useful if `RNCryptor` could read and write common formats like OpenSSL's `enc` output. While OpenSSL has significant problems in how it implements AES encryption (for instance, it does not iterate its KDF), it is very common and it would be useful if `RNCryptor` could integrate into systems that use it.

# Roadmap

* v1.0 is complete and includes synchronous stream and data support.
* v1.1 will include the option of OpenSSL compatibility (at the cost of reduced security and removal of integrity checks). This may cause small cahgnes in the API
* v1.2 will add asynchronous modes. This may cause non-trivials changes in the API.



# LICENSE
This code is licensed under the MIT License:

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
