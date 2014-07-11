# RNCryptor

Cross-language AES Encryptor/Decryptor [data
format](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md).
 
The primary target is Objective-C, but implementations are available in
[C++](https://github.com/RNCryptor/RNCryptor-cpp),
[C#](https://github.com/RNCryptor/RNCryptor-cs),
[Java](https://github.com/RNCryptor/JNCryptor),
[PHP](https://github.com/RNCryptor/RNCryptor-php),
[Python](https://github.com/RNCryptor/RNCryptor-python),
[Javascript](https://github.com/RNCryptor/rncryptor-js),
and [Ruby](https://github.com/RNCryptor/ruby_rncryptor).

The data format includes all the metadata required to securely implement AES
encryption, as described in ["Properly encrypting with AES with
CommonCrypto,"](http://robnapier.net/aes-commoncrypto) and [*iOS 6
Programming Pushing the Limits*](http://iosptl.com), Chapter 15. Specifically,
it includes:

* AES-256 encryption
* CBC mode
* Password stretching with PBKDF2
* Password salting
* Random IV
* Encrypt-then-hash HMAC

## Basic Objective-C Usage

The most common in-memory use case is as follows:

``` objc
NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
NSError *error;
NSData *encryptedData = [RNEncryptor encryptData:data
                                   	withSettings:kRNCryptorAES256Settings
                                          password:aPassword
                                             error:&error];
```

This generates an `NSData` including a header, encryption salt, HMAC salt, IV,
ciphertext, and HMAC. To decrypt this bundle:

``` objc
NSData *decryptedData = [RNDecryptor decryptData:encryptedData
                                    withPassword:aPassword
                                           error:&error];
```

Note that `RNDecryptor` does not require settings. These are read from the
header.

## Asynchronous use

`RNCryptor suports asynchronous use, specifically designed to work with
`NSURLConnection. This is also useful for cases where the encrypted or decrypted
`data will not comfortably fit in memory. If the data will comfortably fit in
`memory, asynchronous operation is best acheived using dispatch_async().

To operate in asynchronous mode, you create an `RNEncryptor` or `RNDecryptor`,
providing it a handler. This handler will be called as data is encrypted or
decrypted. As data becomes available, call `addData:`. When you reach the end of
the data call `finish`.

``` objc
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
  [self.encryptedData addData:[self.cryptor addData:data]];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
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

- (void)decryptRequest:(NSURLRequest *)request {
  self.encryptedData = [NSMutableData data];
  self.connection = [[NSURLConnection alloc] initWithRequest:request delegate:self];
  self.cryptor = [[RNDecryptor alloc] initWithPassword:self.password
                                               handler:^(RNCryptor *cryptor, NSData *data) {
                                                   [self.decryptedData appendData:data];
                                                   if (cryptor.isFinished) {
                                                     [self decryptionDidFinish];
                                                   }
                                                 }];
}
```

## Async and Streams

When performing async operations on streams, the data can come very quickly
(particularly if you're reading from a local file). If you use RNCryptor in a
naïve way, you'll queue a work blocks faster than the engine can process them
and your memory usage will spike. This is particularly true if there's only one
core, such as on an iPad 1. The solution is to only dispatch new work blocks as
the previous work blocks complete.

``` objc
// Make sure that this number is larger than the header + 1 block.
// 33+16 bytes = 49 bytes. So it shouldn't be a problem.
int blockSize = 32 * 1024;

NSInputStream *cryptedStream = [NSInputStream inputStreamWithFileAtPath:@"C++ Spec.pdf"];
NSOutputStream *decryptedStream = [NSOutputStream outputStreamToFileAtPath:@"/tmp/C++.crypt" append:NO];

[cryptedStream open];
[decryptedStream open];

// We don't need to keep making new NSData objects. We can just use one repeatedly.
__block NSMutableData *data = [NSMutableData dataWithLength:blockSize];
__block RNEncryptor *decryptor = nil;

dispatch_block_t readStreamBlock = ^{
  [data setLength:blockSize];
  NSInteger bytesRead = [cryptedStream read:[data mutableBytes] maxLength:blockSize];
  if (bytesRead < 0) {
    // Throw an error
  }
  else if (bytesRead == 0) {
    [decryptor finish];
  }
  else {
    [data setLength:bytesRead];
    [decryptor addData:data];
    NSLog(@"Sent %ld bytes to decryptor", (unsigned long)bytesRead);
  }
};

decryptor = [[RNEncryptor alloc] initWithSettings:kRNCryptorAES256Settings
                                         password:@"blah"
                                          handler:^(RNCryptor *cryptor, NSData *data) {
                                            NSLog(@"Decryptor recevied %ld bytes", (unsigned long)data.length);
                                            [decryptedStream write:data.bytes maxLength:data.length];
                                            if (cryptor.isFinished) {
                                              [decryptedStream close];
                                              // call my delegate that I'm finished with decrypting
                                            }
                                            else {
                                              // Might want to put this in a dispatch_async(), but I don't think you need it.
                                              readStreamBlock();
                                            }
                                          }];

// Read the first block to kick things off    
readStreamBlock();
```

I'll eventually get this into the API to simplify things. See [Cyrille's SO
question](http://stackoverflow.com/a/14586231/97337) for more discussion. Pull
requests welcome.

## Building

Comes packaged as a static library, but the source files can be dropped into any
project. The OpenSSL files are not required.

Requires `Security.framework`.

Supports 10.6+ and iOS 4+.

The current file format is v3. To read v1 files (see Issue #44), you need to set the compile-time macro `RNCRYPTOR_ALLOW_V1_BAD_HMAC`. It is not possible to write v1 files anymore.

## Design considerations

`RNCryptor` has several design goals, in order of importance:

### Easy to use correctly for most common use cases

The most critical concern is that it be easy for non-experts to use `RNCryptor` correctly. A framework that is more secure, but requires a steep learning curve on the developer will either be not used, or used incorrectly. Whenever possible, a single line of code should "do the right thing" for the most common cases.

This also requires that it fail correctly and provide good errors.

### Reliance on CommonCryptor functionality

`RNCryptor` has very little "security" code. It relies as much as possible on the OS-provided CommonCryptor. If a feature does not exist in CommonCryptor, then it generally will not be provided in `RNCryptor`.

### Best practice security

Wherever possible within the above constraints, the best available algorithms
are applied. This means AES-256, HMAC+SHA1, and PBKDF2:

* AES-256. While Bruce Schneier has made some interesting recommendations
regarding moving to AES-128 due to certain attacks on AES-256, my current
thinking is in line with [Colin
Percival](http://www.daemonology.net/blog/2009-07-31-thoughts-on-AES.html).
PBKDF2 output is effectively random, which should negate related-keys attacks
against the kinds of use cases we're interested in.

* AES-CBC mode. This was a somewhat complex decision, but the ubiquity of CBC
outweighs other considerations here. There are no major problems with CBC mode,
and nonce-based modes like CTR have other trade-offs. See ["Mode changes for
RNCryptor"](http://robnapier.net/blog/mode-rncryptor) for more details on this
decision.

* Encrypt-then-MAC. If there were a good authenticated AES mode on iOS (GCM for
instance), I would probably use that for its simplicity. Colin Percival makes
[good arguments for hand-coding an encrypt-than-
MAC](http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html) rather
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

`RNCryptor endeavors to be implemented as simply as possible, avoiding tricky
`code. It is designed to be easy to read and code review.

### Performance

Performance is a goal, but not the most important goal. The code must be secure
and easy to use. Within that, it is as fast and memory-efficient as possible.

### Portability

Without sacrificing other goals, it is preferable to read the output format of
`RNCryptor` on other platforms.

## Version History

* v2.2 Switches to file format v3 to deal with Issue #77.
* v2.1 Switches to file format v2 to deal with Issue #44.
* v2.0 adds asynchronous modes.
* v2.1 backports `RNCryptor` to older versions of Mac OS X (and possibly iOS).


## LICENSE

Except where otherwise indicated in the source code, this code is licensed under
the MIT License:

```
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
```

Portions of this code, indicated in the source, are licensed under the following
license:

```
/*-
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
```

Portions of this code, indicated in the source, are licensed under the APSL
license:

```
/*
 * Copyright (c) 2006-2010 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
```
