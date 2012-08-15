//
//  RNOpenSSLCryptor
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

#import "RNOpenSSLDecryptor.h"
#import "RNOpenSSLEncryptor.h"


extern NSString *const kRNCryptorOpenSSLSaltedString;

NSData *RNOpenSSLCryptorGetKey(NSString *password, NSData *salt, RNCryptorKeyDerivationSettings keySettings);
NSData *RNOpenSSLCryptorGetIV(NSData *key, NSString *password, NSData *salt, RNCryptorKeyDerivationSettings keySettings);


//
//#import "RNCryptor.h"
//
//
//@interface RNOpenSSLCryptor : NSObject
//+ (RNOpenSSLCryptor *)openSSLCryptor;
//
//- (BOOL)encryptFromStream:(NSInputStream *)fromStream
//                 toStream:(NSOutputStream *)toStream
//                 password:(NSString *)password
//                    error:(NSError **)error;
//
//- (BOOL)decryptFromStream:(NSInputStream *)fromStream
//                 toStream:(NSOutputStream *)toStream
//                 password:(NSString *)password
//                    error:(NSError **)error;
//
//@end
//
//static const RNCryptorSettings kRNCryptorOpenSSLSettings = {
//    .algorithm = kCCAlgorithmAES128,
//    .mode = kCCModeCBC,
//    .blockSize = kCCBlockSizeAES128,
//    .IVSize = kCCBlockSizeAES128,
//    .padding = ccPKCS7Padding,
//
//    .keySettings = {
//        .keySize = kCCKeySizeAES256,
//        .saltSize = 8,
//        .rounds = 1,
//        .PRF = kCCPRFHmacAlgSHA1
//    },
//};
