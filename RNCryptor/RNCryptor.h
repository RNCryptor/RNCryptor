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

@class RNCryptorSettings;

@protocol RNCryptorInput <NSObject>
@property (nonatomic, readonly) NSData *computedHMAC;
- (BOOL)getData:(NSData **)data shouldStop:(BOOL *)stop error:(NSError **)error;
@end

@protocol RNCryptorOutput <NSObject>
@property (nonatomic, readonly) NSData *computedHMAC;
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

@interface RNCryptor : NSObject

///---------------------------------------------------------------------------------------
/// @name Creating an RNCryptor
///---------------------------------------------------------------------------------------

- (RNCryptor *)initWithSettings:(RNCryptorSettings *)settings;

///---------------------------------------------------------------------------------------
/// @name Encrypt/Decrypt with NSStream
///---------------------------------------------------------------------------------------

typedef void (^RNCryptorReadCallback)(NSData *readData);
typedef void (^RNCryptorWriteCallback)(NSData *writeData);

@property (nonatomic, readonly) RNCryptorSettings *settings;

+ (RNCryptor *)AES256Cryptor;

- (NSData *)keyForPassword:(NSString *)password salt:(NSData *)salt;

- (BOOL)performOperation:(CCOperation)operation
              fromStream:(NSInputStream *)input
            readCallback:(RNCryptorReadCallback)readBlock
                toStream:(NSOutputStream *)output
           writeCallback:(RNCryptorWriteCallback)writeBlock
           encryptionKey:(NSData *)encryptionKey
                      IV:(NSData *)IV
             footerSize:(NSUInteger)footerSize
                 footer:(NSData **)footer
                   error:(NSError **)error;

- (NSData *)randomDataOfLength:(size_t)length;

- (BOOL)decryptFromStream:(NSInputStream *)input
                 toStream:(NSOutputStream *)output
            encryptionKey:(NSData *)encryptionKey
                       IV:(NSData *)IV
                  HMACKey:(NSData *)HMACKey
                    error:(NSError **)error;



- (BOOL)decryptFromStream:(NSInputStream *)input
                 toStream:(NSOutputStream *)output
                 password:(NSString *)password
                    error:(NSError **)error;

- (BOOL)decryptFromURL:(NSURL *)inURL
                 toURL:(NSURL *)outURL
                append:(BOOL)append
              password:(NSString *)password
                 error:(NSError **)error;

- (NSData *)decryptData:(NSData *)ciphertext password:(NSString *)password error:(NSError **)error;

- (BOOL)encryptFromStream:(NSInputStream *)input
                 toStream:(NSOutputStream *)output
            encryptionKey:(NSData *)encryptionKey
                       IV:(NSData *)IV
                  HMACKey:(NSData *)HMACKey
                    error:(NSError **)error;

- (BOOL)encryptFromStream:(NSInputStream *)input
                 toStream:(NSOutputStream *)output
                 password:(NSString *)password
                    error:(NSError **)error;

- (BOOL)encryptFromURL:(NSURL *)inURL
                 toURL:(NSURL *)outURL
                append:(BOOL)append
              password:(NSString *)password
                 error:(NSError **)error;

- (NSData *)encryptData:(NSData *)plaintext password:(NSString *)password error:(NSError **)error;

@end

@interface RNCryptorSettings : NSObject
@property (nonatomic, readonly) CCAlgorithm algorithm;  // kCCAlgorithmAES128
@property (nonatomic, readonly) size_t keySize;         // kCCKeySizeAES128
@property (nonatomic, readonly) size_t blockSize;       // kCCBlockSizeAES128
@property (nonatomic, readonly) size_t IVSize;          // kCCBlockSizeAES128
@property (nonatomic, readonly) size_t saltSize;        // 8
@property (nonatomic, readonly) uint PBKDFRounds;       // 10000 (~80ms on an iPhone 4)
@property (nonatomic, readonly) CCHmacAlgorithm HMACAlgorithm;  // kCCHmacAlgSHA256
@property (nonatomic, readonly) size_t HMACLength;  // CC_SHA256_DIGEST_LENGTH

+ (RNCryptorSettings *)AES256Settings;
@end
