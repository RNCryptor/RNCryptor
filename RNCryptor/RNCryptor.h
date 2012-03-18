//
//  RNCryptor.h
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

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@protocol RNCryptorStream <NSObject>
@property (nonatomic, readonly) NSData *HMAC;
@end

@protocol RNCryptorInputStream <RNCryptorStream>
- (BOOL)getData:(NSData **)data shouldStop:(BOOL *)stop error:(NSError **)error;
@end

@protocol RNCryptorOutputStream <RNCryptorStream>
- (BOOL)writeData:(NSMutableData *)data error:(NSError **)error;
@end

extern NSString *const kRNCryptorErrorDomain;

/** AES Encryptor/Decryptor for Mac and iOS.
 
 Provides an easy-to-use, Objective-C interface to the AES functionality of
 CommonCrypto. Simplifies correct handling of password stretching (PBKDF2),
 salting, and IV. For more information on these terms, see "Properly encrypting
 with AES with CommonCrypto" http://robnapier.net/blog/aes-commoncrypto-564
 
 Requires Security.framework.
 */

typedef struct
{
  CCAlgorithm algorithm;  // kCCAlgorithmAES128
  size_t keySize;         // kCCKeySizeAES128
  size_t blockSize;       // kCCBlockSizeAES128
  size_t IVSize;          // kCCBlockSizeAES128
  size_t saltSize;        // 8
  uint PBKDFRounds;       // 10000 (~80ms on an iPhone 4)
  CCHmacAlgorithm HMACAlgorithm;  // kCCHmacAlgSHA256
  size_t HMACLength;  // CC_SHA1_DIGEST_LENGTH
} RNCryptorConfiguration;

//typedef BOOL (^RNCryptorReadBlock)(NSData **readData, BOOL *stop, NSError **error);
//typedef BOOL (^RNCryptorWriteBlock)(NSData *writeData, NSError **error);


@interface RNCryptor : NSObject

///---------------------------------------------------------------------------------------
/// @name Creating an RNCryptor
///---------------------------------------------------------------------------------------

/** Default cryptor - AES-128 + HMAC-SHA256
*/
+ (RNCryptor *)defaultCryptor;

/** AES 128-bit cryptor
* 8 byte salt. 10000 PBKDF rounds.
*/
+ (RNCryptor *)AES128Cryptor;

/** Creates a default RNCryptManager
*
* Default manager uses AES 128 with an 8 byte salt and 10000 PBKDF rounds.
*/
- (RNCryptor *)init;

/** Creates a configured RNCryptManager
* @param configuration Configuration structure. This cannot be changed once set.
*/
- (RNCryptor *)initWithConfiguration:(RNCryptorConfiguration)configuration;

/** Returns default configuration for AES-128. This can be modified and handed to initWithConfiguration:.
*/
+ (RNCryptorConfiguration)AES128Configuration;

///---------------------------------------------------------------------------------------
/// @name Encrypt/Decrypt with NSStream
///---------------------------------------------------------------------------------------

//- (BOOL)encryptWithReadBlock:(RNCryptorReadBlock)readBlock
//                  writeBlock:(RNCryptorWriteBlock)writeBlock
//               encryptionKey:(NSData *)encryptionKey
//                          IV:(NSData *)IV
//                     HMACKey:(NSData *)HMACKey
//                        HMAC:(NSData **)HMAC
//                       error:(NSError **)error;
//
//- (BOOL)decryptWithReadBlock:(RNCryptorReadBlock)readBlock
//                  writeBlock:(RNCryptorWriteBlock)writeBlock
//               encryptionKey:(NSData *)encryptionKey
//                          IV:(NSData *)IV
//                     HMACKey:(NSData *)HMACKey
//                        HMAC:(NSData **)HMAC
//                       error:(NSError **)error;

- (BOOL)encryptWithInput:(id<RNCryptorInputStream>)input
                  output:(id<RNCryptorOutputStream>)output
           encryptionKey:(NSData *)encryptionKey
                      IV:(NSData *)IV
                   error:(NSError **)error;

- (BOOL)decryptWithInput:(id<RNCryptorInputStream>)input
                  output:(id<RNCryptorOutputStream>)output
           encryptionKey:(NSData *)encryptionKey
                      IV:(NSData *)IV
                   error:(NSError **)error;


//- (RNCryptorReadBlock)readBlockForData:(NSData *)data;
//
//- (RNCryptorWriteBlock)writeBlockForData:(NSMutableData *)data;

///** Encrypts stream
//*
//* @param fromStream The stream to encrypt
//* @param toStream The stream to write encrypteddata to
//* @param encryptionKey Correctly sized encryption key. May not be nil
//* @param IV Initialization vector. May be `nil`, but this is strongly discouraged.
//* @param HMACKey If non-`nil`, an HMAC of the encrypted data will be appended to the stream
//* @param error Out parameter used if an error occurs. May be `NULL` if no error is required.
//*
//* @return Returns `YES` if successful. Return `NO` and sets `error` if there is an error.
//*
//*/
//- (BOOL)encryptFromStream:(NSInputStream *)fromStream
//                 toStream:(NSOutputStream *)toStream
//            encryptionKey:(NSData *)encryptionKey
//                       IV:(NSData *)IV
//                  HMACKey:(NSData *)HMACKey
//                    error:(NSError **)error;
//
///** Decrypts stream
//*
//* @param fromStream The stream to decrypt
//* @param toStream The stream to write decrypted data to
//* @param encryptionKey Correctly sized encryption key. May not be nil
//* @param IV Initialization vector. May be `nil`, but this is strongly discouraged.
//* @param HMACKey If non-`nil`, HMAC will be verified
//* @param error Out parameter used if an error occurs. May be `NULL` if no error is required.
//*
//* @return Returns `YES` if successful. Return `NO` and sets `error` if there is an error.
//*
//*/
//- (BOOL)decryptFromStream:(NSInputStream *)fromStream
//                 toStream:(NSOutputStream *)toStream
//            encryptionKey:(NSData *)encryptionKey
//                       IV:(NSData *)IV
//                  HMACKey:(NSData *)HMACKey
//                    error:(NSError **)error;
//
//
///** Encrypts stream against a password, with a randomly generated IV and salt. IV and salt will be prepended to resulting stream.
//
// @param fromStream The stream to encrypt
// @param toStream The stream to write encrypted data to
// @param password A password. Generally this is human-provided. An AES key will be generated from this.
// @param error Out parameter used if an error occurs. May be `NULL` if no error is required.
// @return Returns `YES` if successful. Return `NO` and sets `error` if there is an error.
// */
//
//- (BOOL)encryptFromStream:(NSInputStream *)fromStream
//                 toStream:(NSOutputStream *)toStream
//                 password:(NSString *)password
//                    error:(NSError **)error;
//
///** Decrypts data using a password. IV and salt must be at the beginning of the stream, as provided by encryptFromStream:toStream:password:error:.
//
// @param fromStream The stream to decrypt
// @param toStream The stream to write decrypted data to
// @param password A password. Generally this is human-provided. An AES key will be generated from this using the same algorithm as in the encrypt methods.
// @param error Out parameter used if an error occurs. May be `NULL` if no error is required.
// @return Returns `YES` if successful. Return `NO` and sets `error` if there is an error.
// */
//- (BOOL)decryptFromStream:(NSInputStream *)fromStream
//                 toStream:(NSOutputStream *)toStream
//                 password:(NSString *)password
//                    error:(NSError **)error;

//
/////---------------------------------------------------------------------------------------
///// @name Encrypt/Decrypt In Memory
/////---------------------------------------------------------------------------------------
//
///** Encrypts data against a password, with a randomly generated IV and salt
//
// @param data The data to encrypt
// @param password A password. Generally this is human-provided. An AES key will be generated from this.
// @param IV Out parameter set to the randomly generated IV. This may not be `NULL`.
// @param salt Out parameter set to the randomly generated salt. This may not be `NULL`.
// @param error Out parameter used if an error occurs. May be `NULL` if no error is required.
// @return Returns the encrypted data, or `nil` if there is an error.
// */
//
//- (NSData *)encryptedDataForData:(NSData *)data
//                        password:(NSString *)password
//                              IV:(NSData **)IV
//                            salt:(NSData **)salt
//                           error:(NSError **)error;
//
///** Decrypts data using a password, IV and salt
//
// @param data The data to decrypt
// @param password A password. Generally this is human-provided. An AES key will be generated from this using the same algorithm as in the encrypt methods.
// @param IV The IV (generally provided by encrypt methods)
// @param salt The salt (generally provided by encrypt methods)
// @param error Out parameter used if an error occurs. May be `NULL` if no error is required.
// @return Returns the decrypted data, or `nil` if there is an error.
// */
//
//- (NSData *)decryptedDataForData:(NSData *)data
//                        password:(NSString *)password
//                              IV:(NSData *)IV
//                            salt:(NSData *)salt
//                           error:(NSError **)error;
@end
