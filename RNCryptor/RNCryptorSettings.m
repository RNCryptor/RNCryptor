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

#import "RNCryptorSettings.h"

@interface RNCryptorSettings ()
@end

@implementation RNCryptorSettings
@synthesize algorithm = algorithm_;
@synthesize keySize = keySize_;
@synthesize blockSize = blockSize_;
@synthesize IVSize = IVSize_;
@synthesize saltSize = saltSize_;
@synthesize PBKDFRounds = PBKDFRounds_;
@synthesize HMACAlgorithm = HMACAlgorithm_;
@synthesize HMACLength = HMACLength_;

+ (RNCryptorSettings *)defaultSettings
{
  return [self AES128Settings];

}

+ (RNCryptorSettings *)AES128Settings
{
  static dispatch_once_t once;
  static RNCryptorSettings *AES128Settings;

  dispatch_once(&once, ^{
    AES128Settings = [[self alloc] init];
    AES128Settings->algorithm_ = kCCAlgorithmAES128;
    AES128Settings->keySize_ = kCCKeySizeAES128;
    AES128Settings->blockSize_ = kCCBlockSizeAES128;
    AES128Settings->IVSize_ = kCCBlockSizeAES128;
    AES128Settings->saltSize_ = 8;
    AES128Settings->PBKDFRounds_ = 10000; // ~80ms on an iPhone 4
    AES128Settings->HMACAlgorithm_ = kCCHmacAlgSHA256;
    AES128Settings->HMACLength_= CC_SHA256_DIGEST_LENGTH;
  });
  return AES128Settings;
}


@end