# Overview

Encryptor/Decryptor for iOS
 
Provides an easy-to-use, Objective-C interface to the AES functionality of CommonCrypto. Simplifies correct handling of
password stretching (PBKDF2), salting, and IV. For more information on these terms, see ["Properly encrypting with AES
with CommonCrypto,"](http://robnapier.net/blog/aes-commoncrypto-564) and [iOS 5 Programming Pushing the Limits](http://iosptl.com), Chapter 11.
Also includes automatic HMAC handling to integrity-check messages.

`RNCryptor` is an abstract class. Concrete subclasses include:

* `RNEncryptor`, `RNDecryptor` : Writer and reader for the [RNCryptor data format](https://github.com/rnapier/RNCryptor/wiki/Data-Format).
* `RNOpenSSLEncryptor`, `RNOpenSSLDecryptor` : Writer and reader for the OpenSSL format. This format is not recommended due to its weak
security settings, but is available for compatibility.

# Synchronous use

The most common in-memory use case is as follows:

    NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *encryptedData = [RNEncryptor encryptData:data
                                      withSettings:kRNCryptorAES256Settings
                                          password:aPassword
                                             error:&error];

This generates an `NSData` including a header, encryption salt, HMAC salt, IV, ciphertext, and HMAC. To decrypt this bundle:

    NSData *decryptedData = [RNDecryptor decryptData:encryptedData
                                        withPassword:aPassword
                                               error:&error];

Note that `RNDecryptor` does not require settings. These are read from the header.

# Asynchronous use

`RNCryptor` suports asynchronous use, specifically designed to work with `NSURLConnection`.
This is also useful for cases where the encrypted or decrypted data will not comfortably fit in memory.
If the data will comfortably fit in memory, ansynchronous operation is best acheived using `dispatch_async()`.

To operate in asynchronous mode, you create an `RNEncryptor` or `RNDecryptor`, providing it a handler. This handler will be
called as data is encrypted or decrypted. As data becomes available, call `addData:`. When you reach the end of the data
call `finish`.

    - (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
    {
      [self.cryptor addData:data];
    }

    - (void)connectionDidFinishLoading:(NSURLConnection *)connection
    {
      [self.cryptor finish];
    }

    // Other connection delegates

    - (void)decryptionDidFinish {
      if (self.cryptor.error) {
        // An error occurred. You cannot trust encryptedData at this point
      }
      else {
        // self.encryptedData is complete. Use it as you like
      }
      self.encryptedData = nil;
      self.cryptor = nil;
      self.connection = nil;
    }

    - (void)decryptRequest:(NSURLRequest *)request
    {
      self.connection = [[NSURLConnection alloc] initWithRequest:request delegate:self];
      self.cryptor = [[RNDecryptor alloc] initWithPassword:self.password
                                                   handler:^(RNCryptor *cryptor, NSData *data) {
                                                       [self.decryptedData appendData:data];
                                                       if (cryptor.isFinished) {
                                                         [self decryptionDidFinish];
                                                       }
                                                     }];
    }


# API Documentation

Full API information is available at http://rnapier.github.com/RNCryptor/doc/html/Classes/RNCryptor.html.

Details on the data format are available at https://github.com/rnapier/RNCryptor/wiki/Data-Format.

# Building

Comes packaged as a static library, but the source files can be dropped into any project. The OpenSSL files are not required.

Requires `Security.framework`.

Supports 10.7+ and iOS 5+. For more information on backporting, read and comment on Issue #22.

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

* AES-CBC mode. This was a somewhat complex decision, but the ubiquity of CBC outweighs other considerations here. There are no
major problems with CBC mode, and nonce-based modes like CTR have other trade-offs. See http://robnapier.net/blog/mode-rncryptor-767 for
more details on this decision.

* Encrypt-then-MAC. If there were a good authenticated AES mode on iOS (GCM for instance), I would probably use that for
its simplicity. Colin Percival makes [good arguments for hand-coding an encrypt-than-MAC](http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html) rather than using an authenticated
AES mode, but in RNCryptor mananging the HMAC actually adds quite a bit of complexity. I'd rather the complexity at a
more broadly peer-reviewed layer like CommonCryptor than at the RNCryptor layer. But this isn't an option, so I fall back
to my own Encrypt-than-MAC. 

* HMAC+SHA256. No surprises here.

* PBKDF2. While bcrypt and scrypt may be more secure than PBKDF2, CommonCryptor only supports PBKDF2. NIST also continues to recommend PBKDF2. http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage We use 10k rounds of PBKDF2 which represents about 80ms on an iPhone 4.

## Code simplicity

`RNCryptor` endeavors to be implemented as simply as possible, avoiding tricky code. It is designed to be easy to read and code review.

## Performance

Performance is a goal, but not the most important goal. The code must be secure and easy to use. Within that, it is as fast and memory-efficient as possible.

## Portability

Without sacrificing other goals, it is preferable to read the output format of `RNCryptor` on other platforms.

# Roadmap

* v2.0 adds asynchronous modes.
* v2.1 backports `RNCryptor` to older versions of Mac OS X (and possibly iOS).


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
