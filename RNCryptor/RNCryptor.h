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

extern NSString *const kRNCryptorErrorDomain;

typedef struct _RNCryptorKeyDerivationSettings
{
  size_t keySize;
  size_t saltSize;
  CCPBKDFAlgorithm PBKDFAlgorithm;
  CCPseudoRandomAlgorithm PRF;
  uint rounds;
} RNCryptorKeyDerivationSettings;

typedef struct _RNCryptorSettings
{
  CCAlgorithm algorithm;
  size_t blockSize;
  size_t IVSize;
  CCOptions options;
  CCHmacAlgorithm HMACAlgorithm;
  size_t HMACLength;
  RNCryptorKeyDerivationSettings keySettings;
  RNCryptorKeyDerivationSettings HMACKeySettings;
} RNCryptorSettings;

static const RNCryptorSettings kRNCryptorAES256Settings = {
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

enum
{
  kRNCryptorErrorHMACMismatch = 1,
  kRNCryptorUnknownHeader = 2,
  kRNCryptorCouldNotCreateStream = 3,
  kRNCryptorCouldNotReadStream = 4,
  kRNCryptorCouldNotWriteStream = 5,
};

typedef void (^RNCryptorReadCallback)(NSData *readData);
typedef void (^RNCryptorWriteCallback)(NSData *writeData);

/** Encryptor/Decryptor for iOS

  Provides an easy-to-use, Objective-C interface to the AES functionality of CommonCrypto. Simplifies correct handling of
  password stretching (PBKDF2), salting, and IV. For more information on these terms, see "Properly encrypting with AES
  with CommonCrypto," and iOS 5 Programming Pushing the Limits, Chapter 11. Also includes automatic HMAC handling to integrity-check messages.

  RNCryptor is immutable, stateless and thread-safe. A given cryptor object may be used simultaneously on multiple threads,
  and can be reused to encrypt or decrypt an arbitrary number of independent messages.
 */

@interface RNCryptor : NSObject

///---------------------------------------------------------------------------------------
/// @name Properties
///---------------------------------------------------------------------------------------

/** Immutable settings for cryptor.
*/
@property (nonatomic, readonly) RNCryptorSettings settings;

///---------------------------------------------------------------------------------------
/// @name Creating an RNCryptor
///---------------------------------------------------------------------------------------

/** Shared AES-256 encryptor
 *
 * AES-CBC cryptor with 256-bit key. 8-byte salt. HMAC+SHA256 of ciphertext appended (Encrypt-then-MAC).
 * Appropriate for most uses.
 *
 */
+ (RNCryptor *)AES256Cryptor;

/** Create a customised cryptor
 * @param settings Immutable settings for cryptor.
 */

+ (NSError *)errorWithCode:(int)code localizedDescription:(NSString *)localizedDescription underlyingError:(NSError *)underlyingError;
- (RNCryptor *)initWithSettings:(RNCryptorSettings)settings;


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

/** Encrypt from a stream, to a stream, provided an encryption key and optional HMAC key.
*   A random IV will be written to the beginning of the stream. If an HMAC key is provided, the HMAC of the ciphertext
*   will be written the the end of the stream.
*
* @param fromStream Stream to read. May be opened or unopened.
* @param toStream Stream to write. May be opened or unopened.
* @param encryptionKey Encryption key of correct length for algorithm. This is not a password. No hashing or PBKDF will be applied.
* @param IV Initialization vector of correct length for algorithm. For "no IV," you must pass a zero-filled block of the correct length. This is strongly discouraged.
* @param HMACKey HMAC key. This can be of any length. It is discouraged to make this the same as `encryptionKey`. If HMACKey is `nil`, no HMAC will be written.
* @param error If there is an error, this will contain the `NSError` by reference
* @returns `YES` on success. `NO` on failure, and `error` will contain the error object.
* @returns `
*/
- (BOOL)encryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
            encryptionKey:(NSData *)encryptionKey
                  HMACKey:(NSData *)HMACKey
                    error:(NSError **)error;

/** Decrypt from a stream, to a stream, provided an encryption key (not password), and optional HMAC key.
*   The IV must be at the start of the stream
*   The HMAC of the ciphertext will be read from the end of the stream if an HMAC key is provided. If there is an HMAC,
*   then it must match, or this method will return `NO`.
*
* @param fromStream Stream to read. May be opened or unopened.
* @param toStream Stream to write. May be opened or unopened.
* @param encryptionKey Encryption key of correct length for algorithm. This is not a password. No hashing or PBKDF will be applied.
* @param IV Initialization vector of correct length for algorithm. For "no IV," you must pass a zero-filled block of the correct length. This is strongly discouraged.
* @param HMACKey HMAC key, matching the encryption key.
* @param error If there is an error, this will contain the `NSError` by reference
* @returns `YES` on success. `NO` on failure (including HMAC mismatch), and `error` will contain the error object.
*/
- (BOOL)decryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
            encryptionKey:(NSData *)encryptionKey
                  HMACKey:(NSData *)HMACKey
                    error:(NSError **)error;


///---------------------------------------------------------------------------------------
/// @name Password-based operations
///---------------------------------------------------------------------------------------

/** Encrypt from a stream, to a stream, provided a password.
*   Automatically generates required salts and IV. Prepends header and appends HMAC.
*   Full format is described at https://github.com/rnapier/RNCryptor/wiki/Data-Format
*
* @param fromStream Stream to read. May be opened or unopened.
* @param toStream Stream to write. May be opened or unopened.
* @param password Password to use for encryption
* @param error If there is an error, this will contain the `NSError` by reference
* @returns `YES` on success. `NO` on failure, and `error` will contain the error object.
*/
- (BOOL)encryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
                 password:(NSString *)password
                    error:(NSError **)error;

/** Encrypt from a URL, to a URL, provided a password.
*   Automatically generates required salts and IV. Prepends header and appends HMAC.
*   Full format is described at https://github.com/rnapier/RNCryptor/wiki/Data-Format
*
* @param fromURL URL to read.
* @param toURL URL to write.
* @param append Should output be appended rather than overwritng?
* @param password Password to use for encryption
* @param error If there is an error, this will contain the `NSError` by reference
* @returns `YES` on success. `NO` on failure, and `error` will contain the error object.
*/
- (BOOL)encryptFromURL:(NSURL *)fromURL
                 toURL:(NSURL *)toURL
                append:(BOOL)append
              password:(NSString *)password
                 error:(NSError **)error;

/** Encrypt data, provided a password.
*   Automatically generates required salts and IV. Prepends header and appends HMAC.
*   Full format is described at https://github.com/rnapier/RNCryptor/wiki/Data-Format
*
* @param plaintext Data to encrypt
* @param password Password to use for encryption
* @param error If there is an error, this will contain the `NSError` by reference
* @returns Encrypted data, or `nil` if there was an error.
*/
- (NSData *)encryptData:(NSData *)plaintext password:(NSString *)password error:(NSError **)error;

/** Decrypt from a stream, to a stream, provided a password.
*   Stream must be in format described at https://github.com/rnapier/RNCryptor/wiki/Data-Format, with header,
*   required salts and IV prepended, and HMAC appended.
*
* @param fromStream Stream to read. May be opened or unopened.
* @param toStream Stream to write. May be opened or unopened.
* @param password Password to use for decryption
* @returns `YES` on success. `NO` on failure, and `error` will contain the error object.
* @param error If there is an error, this will contain the `NSError` by reference
*/
- (BOOL)decryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
                 password:(NSString *)password
                    error:(NSError **)error;

/** Decrypt from a URL, to a URL, provided a password.
*   URL contents must be in format described at https://github.com/rnapier/RNCryptor/wiki/Data-Format, with header,
*   required salts and IV prepended, and HMAC appended.
*
* @param fromURL URL to read.
* @param toURL URL to write.
* @param append Should output be appended rather than overwritng?
* @param password Password to use for decryption
* @param error If there is an error, this will contain the `NSError` by reference
* @returns `YES` on success. `NO` on failure, and `error` will contain the error object.
*/
- (BOOL)decryptFromURL:(NSURL *)fromURL
                 toURL:(NSURL *)toURL
                append:(BOOL)append
              password:(NSString *)password
                 error:(NSError **)error;

/** Decrypt data, provided a password.
*   Data must be in format described at https://github.com/rnapier/RNCryptor/wiki/Data-Format, with header,
*   required salts and IV prepended, and HMAC appended.
*
* @param ciphertext Data to decrypt
* @param password Password to use for decryption
* @param error If there is an error, this will contain the `NSError` by reference
* @returns Decrypted data, or `nil` if there was an error.
*/
- (NSData *)decryptData:(NSData *)ciphertext password:(NSString *)password error:(NSError **)error;

/** Generate key given a password and salt using a PBKDF
*
* @param password Password to use for PBKDF
* @param salt Salt for password
* @param keySettings Settings for the derivation (RNCryptorKeyDerivationSettings)
* @returns Key
*/
- (NSData *)keyForPassword:(NSString *)password withSalt:(NSData *)salt andSettings:(RNCryptorKeyDerivationSettings)keySettings;

+ (NSData *)randomDataOfLength:(size_t)length;

@end
