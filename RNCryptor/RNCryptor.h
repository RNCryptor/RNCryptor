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

extern NSString *const kRNCryptorErrorDomain;

typedef void (^RNCryptorReadCallback)(NSData *readData);
typedef void (^RNCryptorWriteCallback)(NSData *writeData);

/** AES Encryptor/Decryptor for Mac and iOS.
 
 Provides an easy-to-use, Objective-C interface to the AES functionality of CommonCrypto. Simplifies correct handling of
 password stretching (PBKDF2), salting, and IV. For more information on these terms, see "Properly encrypting with AES
 with CommonCrypto" http://robnapier.net/blog/aes-commoncrypto-564

 RNCryptor is immutable, stateless and thread-safe. A given cryptor object may be used simultaneously on multiple
 threads, and can be reused to encrypt or decrypt an arbitrary number of independent messages.

 See Daemonic Dispatches for discussion of several algorithm choices:
   http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
   http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
 
 Requires Security.framework.
 */

@interface RNCryptor : NSObject

///---------------------------------------------------------------------------------------
/// @name Properties
///---------------------------------------------------------------------------------------

/** Immutable settings for cryptor.
*/
@property (nonatomic, readonly) RNCryptorSettings *settings;

///---------------------------------------------------------------------------------------
/// @name Creating an RNCryptor
///---------------------------------------------------------------------------------------

/** Shared AES-256 encryptor
 *
 * AES-CTR cryptor with 256-bit key. 8-byte salt. HMAC+SHA256 of ciphertext appended (Encrypt-then-MAC).
 * Appropriate for most uses.
 *
 */
+ (RNCryptor *)AES256Cryptor;

/** Create a customiced cryptor
 * @param settings Immutable settings for cryptor.
 */

- (RNCryptor *)initWithSettings:(RNCryptorSettings *)settings;


///---------------------------------------------------------------------------------------
/// @name Low-level encryption/decryption
///---------------------------------------------------------------------------------------

/** Most fundamental encryption/decryption method. Does nothing but encrypt or decrypt the data given the current settings.
*   Provides callbacks during reading and writing, and can exclude the end of the stream (the "footer") from processing.
* @param operation `CCEncrypt` or `CCDecrypt`
* @param fromStream Stream to read. May be opened or unopened.
* @param readCallback Block to call with data read from `fromStream`
* @param toStream Stream to write. May be opened or unopened.
* @param writeCallback Block to call with data successfully written to `toStream`.
* @param encryptionKey Encryption key of correct length for algorithm. This is not a password. No hashing or PBKDF will be applied.
* @param IV Initialization vector of correct length for algorithm. For "no IV," you must pass a zero-filled block of the correct length. This is strongly discouraged.
* @param footerSize Size in bytes of the footer. This is the end of the stream that should not be processed. May be 0.
* @param footer If `footerSize` > 0, then this will contain the footer data by reference.
* @param error If there is an error, this will contain the `NSError` by reference
* @returns `YES` on success. `NO` on failure, and `error` will contain the error object.
*/

- (BOOL)performOperation:(CCOperation)operation
              fromStream:(NSInputStream *)fromStream
            readCallback:(RNCryptorReadCallback)readCallback
                toStream:(NSOutputStream *)toStream
           writeCallback:(RNCryptorWriteCallback)writeCallback
           encryptionKey:(NSData *)encryptionKey
                      IV:(NSData *)IV
              footerSize:(NSUInteger)footerSize
                  footer:(NSData **)footer
                   error:(NSError **)error;

///---------------------------------------------------------------------------------------
/// @name Key-based stream operations
///---------------------------------------------------------------------------------------

/** Encrypt from a stream, to a stream, provided a key (not password), IV, and optional HMAC key.
*   The HMAC of the ciphertext will be written the the end of the stream.
*
* @param fromStream Stream to read. May be opened or unopened.
* @param toStream Stream to write. May be opened or unopened.
* @param encryptionKey Encryption key of correct length for algorithm. This is not a password. No hashing or PBKDF will be applied.
* @param IV Initialization vector of correct length for algorithm. For "no IV," you must pass a zero-filled block of the correct length. This is strongly discouraged.
* @param HMACKey HMAC key. This can be of any length. It is discouraged to make this the same as `encryptionKey`.
* @param error If there is an error, this will contain the `NSError` by reference
*/
- (BOOL)encryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
            encryptionKey:(NSData *)encryptionKey
                       IV:(NSData *)IV
                  HMACKey:(NSData *)HMACKey
                    error:(NSError **)error;

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
                 password:(NSString *)password
                    error:(NSError **)error;

- (BOOL)encryptFromURL:(NSURL *)inURL
                 toURL:(NSURL *)outURL
                append:(BOOL)append
              password:(NSString *)password
                 error:(NSError **)error;

- (NSData *)encryptData:(NSData *)plaintext password:(NSString *)password error:(NSError **)error;

- (NSData *)keyForPassword:(NSString *)password salt:(NSData *)salt;
- (NSData *)randomDataOfLength:(size_t)length;

@end

@interface RNCryptorSettings : NSObject
@property (nonatomic, readonly) CCAlgorithm algorithm;  // kCCAlgorithmAES128
@property (nonatomic, readonly) CCMode mode;            // kCCModeCTR
@property (nonatomic, readonly) CCModeOptions modeOptions;  // kCCModeOptionCTR_LE
@property (nonatomic, readonly) size_t keySize;         // kCCKeySizeAES256
@property (nonatomic, readonly) size_t blockSize;       // kCCBlockSizeAES128
@property (nonatomic, readonly) size_t IVSize;          // kCCBlockSizeAES128
@property (nonatomic, readonly) CCPadding padding;      // ccNoPadding
@property (nonatomic, readonly) size_t saltSize;        // 8
@property (nonatomic, readonly) uint PBKDFRounds;       // 10000 (~80ms on an iPhone 4)
@property (nonatomic, readonly) CCHmacAlgorithm HMACAlgorithm;  // kCCHmacAlgSHA256
@property (nonatomic, readonly) size_t HMACLength;  // CC_SHA256_DIGEST_LENGTH

+ (RNCryptorSettings *)AES256Settings;
@end
