# RNCryptor

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

## Basic Password Usage

### Swift

```swift
// Encryption
let data: NSData = ...
let password = "Secret password"
let ciphertext = RNCryptor.encryptData(data, password: password)

// Decryption
do {
    let originalData = try RNCryptor.decryptData(ciphertext, password: password)
    // ...
} catch {
    print(error)
}

```

### Obj-C

``` objc
// Encryption
NSData *data = ...
NSString *password = @"Secret password";
NSData *ciphertext = [RNCryptor encryptData:data password:password];

// Decryption
NSError *error = nil;
NSData *plaintext = [RNCryptor decryptData:ciphertext password:password error:&error];
if (error != nil) {
    NSLog(@"ERROR:", error);
    return
}
// ...
```

## Incremental use

RNCryptor suports incremental use, specifically designed to work with `NSURLSession`. This is also useful for cases where the encrypted or decrypted data will not comfortably fit in memory.

To operate in incremental mode, you create an `Encryptor` or `Decryptor`, call `updateWithData()` repeatedly, gathering its results, and then call `finalData()` and gather its result.

### Swift

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

### Obj-C

``` objc
//
// Encryption
//
NSString *password = @"Secret password";
RNEncryptor *encryptor = [[RNEncryptor alloc] initWithPassword:password];
NSMutableData *ciphertext = [NSMutableData new];

// ... Each time data comes in, update the encryptor and accumulate some ciphertext ...
[ciphertext appendData:[encryptor updateWithData:data]];

// ... When data is done, finish up ...
[ciphertext appendData:[encryptor finalData]];


//
// Decryption
//
RNDecryptor *decryptor = [[RNDecryptor alloc] initWithPassword:password];
NSMutableData *plaintext = [NSMutableData new];

// ... Each time data comes in, update the decryptor and accumulate some plaintext ...
NSError *error = nil;
NSData *partialPlaintext = [decryptor updateWithData:data error:&error];
if (error != nil) { 
    NSLog(@"FAILED DECRYPT: %@", error);
    return;
}
[plaintext appendData:partialPlaintext];

// ... When data is done, finish up ...
NSError *error = nil;
NSData *partialPlaintext = [decryptor finalDataAndReturnError:&error];
if (error != nil) { 
    NSLog(@"FAILED DECRYPT: %@", error);
    return;
}

[ciphertext appendData:partialPlaintext];

```

## Installation

### A word about CommonCrypto

CommonCrypto hates Swift. That may be an overstatment. CommonCrypto is...apathetic about Swift to the point of hostility. Apple only needs to do a few things to make CommonCrypto a fine Swift citizen, but as of Xcode 7.0, those things have not happened, and this makes it difficult to import CommonCrypto into Swift projects.

The most critical thing is that CommonCrypto is not a module, and Swift can't really handle things that aren't modules. The RNCryptor project comes with a `CommonCrypto.framework` which is basically a fake module. It's only function is to tell Swift where the CommonCrypto headers live. It doesn't contain any CommonCrypto code. You don't even need to link it. For maximum robustness across Xcode versions, `CommonCrypto.framework` points to `/usr/include`. The CommonCrypto headers change very rarely, so this shouldn't cause any problem. Hopefully Apple will finally make a module around CommonCrypto and this won't be necessary in the future.

### Installing as a subproject

The easiest way to use RNCryptor is as a subproject. This makes version control very simple if you use submodules, or checkin specific versions of RNCryptor to your repository.

This process works for almost any kind of target: iOS and OS X GUI apps, Swift frameworks, and OS X commandline apps. **It is not safe for ObjC frameworks or frameworks that may be imported into ObjC (since it would cause duplicate symbols if some other framework included RNCryptor).**

* Drag `RNCryptor.xcodeproj` into your project
* Drag `RNCryptor.swift` into your project and link it.
* In your target build settings, Build Phases, add `CommonCrypto.framework` as a build dependency (but don't link it).

You don't need to (and can't) `import RNCryptor` into your code. RNCryptor will be part of your module.


### Installing without a subproject

If you want to keep things as small and simple as possible, you don't need the full RNCryptor project. You just need two things: `RNCryptor.swift` and `CommonCrypto.framework`. You can just copy those into your project.

The same warnings apply as for subprojects: **It is not safe for ObjC frameworks or frameworks that may be imported into ObjC (since it would cause duplicate symbols if some other framework included RNCryptor).**

The easiest way to install RNCryptor is to just add it to your project. There's
no need for complicated package managers. 

* Copy or link `RNCryptor/RNCryptor.swift` into your project.
* Copy or link `CommonCrypto.framework` into your project.
* Go to your target build settings, Build Phases, and delete `CommonCrypto.framework`. You don't actually want to link it.

You don't need to (and can't) `import RNCryptor` into your code. RNCryptor will be part of your module.

### Carthage

"But I need a package manager!"

OK. You can use a package manager. I prefer [Carthage](https://github.com/Carthage/Carthage). See their site for how you import a module. You'll need to copy and link `RNCryptor.framework` and copy `CommonCrypto.framework`. (You can link this version of `CommonCrypto.framework` or not. It doesn't matter.)

    github "RNCryptor/RNCryptor" "~> 4.0"



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
