//
//  RNCryptor.m
//
//  Copyright (c) 2012 Rob Napier
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//
//

#import "RNCryptor.h"
#import "RNCryptor+Private.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/SecRandom.h>
#import <fcntl.h>

const RNCryptorSettings kRNCryptorAES256Settings = {
    .algorithm = kCCAlgorithmAES128,
    .blockSize = kCCBlockSizeAES128,
    .IVSize = kCCBlockSizeAES128,
    .options = kCCOptionPKCS7Padding,
    .HMACAlgorithm = kCCHmacAlgSHA256,
    .HMACLength = CC_SHA256_DIGEST_LENGTH,

    .keySettings = {
        .keySize = kCCKeySizeAES256,
        .saltSize = 8,
        .PBKDFAlgorithm = kCCPBKDF2,
        .PRF = kCCPRFHmacAlgSHA1,
        .rounds = 10000
    },

    .HMACKeySettings = {
        .keySize = kCCKeySizeAES256,
        .saltSize = 8,
        .PBKDFAlgorithm = kCCPBKDF2,
        .PRF = kCCPRFHmacAlgSHA1,
        .rounds = 10000
    }
};

// Provide internal symbols for 10.6. These were made available in 10.7.
#ifdef __MAC_OS_X_VERSION_MAX_ALLOWED
#if __MAC_OS_X_VERSION_MAX_ALLOWED <= 1060
extern int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) __attribute__((weak_import));
extern int
CCKeyDerivationPBKDF( CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen,
                     const uint8_t *salt, size_t saltLen,
                     CCPseudoRandomAlgorithm prf, uint rounds,
                     uint8_t *derivedKey, size_t derivedKeyLen) __attribute__((weak_import));
#endif
#endif

NSString *const kRNCryptorErrorDomain = @"net.robnapier.RNCryptManager";
const uint8_t kRNCryptorFileVersion = 3;

// TODO: This is a slightly expensive solution, but it's convenient. May want to create a "walkable" data object
@implementation NSMutableData (RNCryptor)
- (NSData *)_RNConsumeToIndex:(NSUInteger)index
{
  NSData *removed = [self subdataWithRange:NSMakeRange(0, index)];
  [self replaceBytesInRange:NSMakeRange(0, self.length - index) withBytes:([self mutableBytes] + index)];
  [self setLength:self.length - index];
  return removed;
}
@end


@implementation RNCryptor
@synthesize responseQueue = _responseQueue;
@synthesize engine = _engine;
@synthesize outData = __outData;
@synthesize queue = _queue;
@synthesize HMACLength = __HMACLength;
@synthesize error = _error;
@synthesize finished = _finished;
@synthesize options = _options;
@synthesize handler = _handler;

+ (NSData *)synchronousResultForCryptor:(RNCryptor *)cryptor data:(NSData *)inData error:(NSError **)anError
{
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  NSMutableData *data = [NSMutableData data];
  __block NSError *returnedError = nil;

  RNCryptorHandler handler = ^(RNCryptor *c, NSData *d) {
    [data appendData:d];
    if (c.isFinished) {
      returnedError = c.error;
      dispatch_semaphore_signal(sem);
    }
  };

  cryptor.handler = handler;

  dispatch_queue_t queue = dispatch_queue_create("net.robnapier.RNEncryptor.response", DISPATCH_QUEUE_SERIAL);
  cryptor.responseQueue = queue;
  [cryptor addData:inData];
  [cryptor finish];


  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

#if !OS_OBJECT_USE_OBJC
  dispatch_release(sem);
  if (queue) {
    dispatch_release(queue);
  }
#endif

  if (returnedError) {
    if (anError) {
      *anError = returnedError;
    }
    return nil;
  }
  else {
    return data;
  }
}

// For use with OS X 10.6
// Based on http://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/Source/API/CommonKeyDerivation.c
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
#define CC_MAX_PRF_WORKSPACE 128+4
#define kCCPRFHmacAlgSHA1hlen	CC_SHA1_DIGEST_LENGTH
#define kCCPRFHmacAlgSHA224hlen CC_SHA224_DIGEST_LENGTH
#define kCCPRFHmacAlgSHA256hlen CC_SHA256_DIGEST_LENGTH
#define kCCPRFHmacAlgSHA384hlen CC_SHA384_DIGEST_LENGTH
#define kCCPRFHmacAlgSHA512hlen CC_SHA512_DIGEST_LENGTH

static size_t
getPRFhlen(CCPseudoRandomAlgorithm prf)
{
	switch(prf) {
		case kCCPRFHmacAlgSHA1:		return kCCPRFHmacAlgSHA1hlen;
		case kCCPRFHmacAlgSHA224:	return kCCPRFHmacAlgSHA224hlen;
		case kCCPRFHmacAlgSHA256:	return kCCPRFHmacAlgSHA256hlen;
		case kCCPRFHmacAlgSHA384:	return kCCPRFHmacAlgSHA384hlen;
		case kCCPRFHmacAlgSHA512:	return kCCPRFHmacAlgSHA512hlen;
		default:
      NSCAssert(NO, @"Unknown prf: %d", prf);
      return 1;
	}
}

static void
PRF(CCPseudoRandomAlgorithm prf, const char *password, size_t passwordLen, u_int8_t *salt, size_t saltLen, u_int8_t *output)
{
	switch(prf) {
		case kCCPRFHmacAlgSHA1:
			CCHmac(kCCHmacAlgSHA1, password, passwordLen, salt, saltLen, output);
			break;
		case kCCPRFHmacAlgSHA224:
			CCHmac(kCCHmacAlgSHA224, password, passwordLen, salt, saltLen, output);
			break;
		case kCCPRFHmacAlgSHA256:
			CCHmac(kCCHmacAlgSHA256, password, passwordLen, salt, saltLen, output);
			break;
		case kCCPRFHmacAlgSHA384:
			CCHmac(kCCHmacAlgSHA384, password, passwordLen, salt, saltLen, output);
			break;
		case kCCPRFHmacAlgSHA512:
			CCHmac(kCCHmacAlgSHA512, password, passwordLen, salt, saltLen, output);
			break;
	}
}

static int
RN_CCKeyDerivationPBKDF( CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen,
                     const uint8_t *salt, size_t saltLen,
                     CCPseudoRandomAlgorithm prf, uint rounds,
                     uint8_t *derivedKey, size_t derivedKeyLen)
{
	u_int8_t oldbuffer[CC_MAX_PRF_WORKSPACE], newbuffer[CC_MAX_PRF_WORKSPACE],
  saltCopy[CC_MAX_PRF_WORKSPACE+4], collector[CC_MAX_PRF_WORKSPACE];
	int rawblock, i, j;
  size_t r, nblocks;
	size_t	hlen, offset;

	if(algorithm != kCCPBKDF2) return -1;

	/*
	 * Check initial parameters
	 */

	if (rounds < 1 || derivedKeyLen == 0)
		return -1; // bad parameters
	if (saltLen == 0 || saltLen > CC_MAX_PRF_WORKSPACE)
		return -1; // out of bounds parameters

	hlen = getPRFhlen(prf);

	/*
	 * FromSpec: Let l be the number of hLen-octet blocks in the derived key, rounding up,
	 * and let r be the number of octets in the last block:
	 */

	nblocks = (derivedKeyLen+hlen-1)/hlen; // in the spec nblocks is referred to as l
	r = derivedKeyLen % hlen;
  r = (r) ? r: hlen;

	/*
	 * Make a copy of the salt buffer so we can concatenate the
	 * block counter for each series of rounds.
	 */

	memcpy(saltCopy, salt, saltLen);
	bzero(derivedKey, derivedKeyLen);

	/*
	 * FromSpec:
	 *
	 * For each block of the derived key apply the function F defined below to the password P,
	 * the salt S, the iteration count c, and the block index to compute the block:
	 *
	 *           F(P,S,c,i)=U1 \xorU2 \xor⋅⋅⋅\xorUc
	 *
	 * where
	 *				U1 =PRF(P,S||INT (i)),
	 *				U2 =PRF(P,U1),
	 *				...
	 *				Uc = PRF (P, Uc-1) .
	 */

	for(rawblock = 0; rawblock < nblocks; rawblock++) {
		int block = rawblock+1;
		size_t copyLen;

		offset = rawblock * hlen;
		copyLen = (block != nblocks) ? hlen: r;

		/*
		 * FromSpec: Here, INT (i) is a four-octet encoding of the integer i, most significant octet first.
		 */

		for(i=0; i<4; i++) saltCopy[saltLen+i] = (block >> 8*(3-i)) & 0xff;

		PRF(prf, password, passwordLen, saltCopy, saltLen+4, oldbuffer);					// Initial PRF with the modified salt

		memcpy(collector, oldbuffer, hlen);												// Initial value for this block of the derived key.

		for(i = 1; i < rounds; i++) {
			PRF(prf, password, passwordLen, oldbuffer, hlen, newbuffer);						// Subsequent PRF with the previous result as the salt
			memcpy(oldbuffer, newbuffer, hlen);
			for(j = 0; j < hlen; j++) collector[j] ^= newbuffer[j];					// Xoring the round into the collector
		}
		memcpy(derivedKey+offset, collector, copyLen);
	}

	/*
	 * Clear temp buffers.
	 */

	bzero(oldbuffer, CC_MAX_PRF_WORKSPACE);
	bzero(newbuffer, CC_MAX_PRF_WORKSPACE);
	bzero(collector, CC_MAX_PRF_WORKSPACE);
	bzero(saltCopy, CC_MAX_PRF_WORKSPACE+4);
	
	return 0;
}

/* End code derived from CommonKeyDerivation.c */


+ (NSData *)keyForPassword:(NSString *)password salt:(NSData *)salt settings:(RNCryptorKeyDerivationSettings)keySettings
{
  NSMutableData *derivedKey = [NSMutableData dataWithLength:keySettings.keySize];

  // See Issue #77. V2 incorrectly calculated key for multi-byte characters.
  NSData *passwordData;
  if (keySettings.hasV2Password) {
    passwordData = [NSData dataWithBytes:[password UTF8String] length:[password length]];
  }
  else {
    passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
  }

  // Use the built-in PBKDF2 if it's available. Otherwise, we have our own. Hello crazy function pointer.
  int result;
  int (*PBKDF)(CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen,
               const uint8_t *salt, size_t saltLen,
               CCPseudoRandomAlgorithm prf, uint rounds,
               uint8_t *derivedKey, size_t derivedKeyLen);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
  PBKDF = CCKeyDerivationPBKDF ?: RN_CCKeyDerivationPBKDF;
#pragma clang diagnostic pop

  result = PBKDF(keySettings.PBKDFAlgorithm,         // algorithm
                 passwordData.bytes,                 // password
                 passwordData.length,                // passwordLength
                 salt.bytes,                         // salt
                 salt.length,                        // saltLen
                 keySettings.PRF,                    // PRF
                 keySettings.rounds,                 // rounds
                 derivedKey.mutableBytes,            // derivedKey
                 derivedKey.length);                 // derivedKeyLen

  // Do not log password here
  NSAssert(result == kCCSuccess, @"Unable to create AES key for password: %d", result);

  return derivedKey;
}

// For use on OS X 10.6
// Based on http://www.opensource.apple.com/source/Security/Security-55179.1/sec/Security/SecFramework.c
// Modified by Rob Napier April, 2013.
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
static int RN_SecRandomCopyBytes(void *rnd, size_t count, uint8_t *bytes) {
  static int kSecRandomFD;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    kSecRandomFD = open("/dev/random", O_RDONLY);
  });

  if (kSecRandomFD < 0)
    return -1;
  while (count) {
    ssize_t bytes_read = read(kSecRandomFD, bytes, count);
    if (bytes_read == -1) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (bytes_read == 0) {
      return -1;
    }
    bytes += bytes_read;
    count -= bytes_read;
  }

	return 0;
}
/* End code dervied from SecFramework.c */

+ (NSData *)randomDataOfLength:(size_t)length
{
  NSMutableData *data = [NSMutableData dataWithLength:length];

  int result;
  if (&SecRandomCopyBytes != NULL) {
    result = SecRandomCopyBytes(NULL, length, data.mutableBytes);
  }
  else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
    result = RN_SecRandomCopyBytes(NULL, length, data.mutableBytes);
#pragma clang diagnostic pop
  }
  NSAssert(result == 0, @"Unable to generate random bytes: %d", errno);

  return data;
}

- (id)initWithHandler:(RNCryptorHandler)handler
{
  NSParameterAssert(handler);
  self = [super init];
  if (self) {
    NSString *responseQueueName = [@"net.robnapier.response." stringByAppendingString:NSStringFromClass([self class])];
    _responseQueue = dispatch_queue_create([responseQueueName UTF8String], NULL);

    NSString *queueName = [@"net.robnapier." stringByAppendingString:NSStringFromClass([self class])];
    _queue = dispatch_queue_create([queueName UTF8String], DISPATCH_QUEUE_SERIAL);
    __outData = [NSMutableData data];

    _handler = [handler copy];
  }
  return self;
}

- (void)dealloc
{
  if (_responseQueue) {
#if !OS_OBJECT_USE_OBJC
    dispatch_release(_responseQueue);
#endif
    _responseQueue = NULL;
  }

  if (_queue) {
#if !OS_OBJECT_USE_OBJC
    dispatch_release(_queue);
#endif
    _queue = NULL;
  }
}

- (void)setResponseQueue:(dispatch_queue_t)aResponseQueue
{
  if (aResponseQueue) {
#if !OS_OBJECT_USE_OBJC
    dispatch_retain(aResponseQueue);
#endif
  }

  if (_responseQueue) {
#if !OS_OBJECT_USE_OBJC
    dispatch_release(_responseQueue);
#endif
  }

  _responseQueue = aResponseQueue;
}

- (void)addData:(NSData *)data
{

}

- (void)finish
{

}

- (void)cleanupAndNotifyWithError:(NSError *)error
{
  self.error = error;
  self.finished = YES;
  if (self.handler) {
    dispatch_sync(self.responseQueue, ^{
      self.handler(self, self.outData);
    });
    self.handler = nil;
  }
}

- (BOOL)hasHMAC
{
  return self.HMACLength > 0;
}


@end
