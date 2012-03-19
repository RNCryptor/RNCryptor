//
//  RNCryptorSettings
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
#import <CommonCrypto/CommonHMAC.h>

@interface RNCryptorSettings : NSObject
@property (nonatomic, readonly) CCAlgorithm algorithm;  // kCCAlgorithmAES128
@property (nonatomic, readonly) size_t keySize;         // kCCKeySizeAES128
@property (nonatomic, readonly) size_t blockSize;       // kCCBlockSizeAES128
@property (nonatomic, readonly) size_t IVSize;          // kCCBlockSizeAES128
@property (nonatomic, readonly) size_t saltSize;        // 8
@property (nonatomic, readonly) uint PBKDFRounds;       // 10000 (~80ms on an iPhone 4)
@property (nonatomic, readonly) CCHmacAlgorithm HMACAlgorithm;  // kCCHmacAlgSHA256
@property (nonatomic, readonly) size_t HMACLength;  // CC_SHA256_DIGEST_LENGTH

+ (RNCryptorSettings *)defaultSettings;
+ (RNCryptorSettings *)AES128Settings;
@end