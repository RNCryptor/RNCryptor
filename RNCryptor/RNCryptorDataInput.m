//
//  RNCryptorDataInputStream
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
//#import "RNCryptorDataInputStream.h"

#import <CommonCrypto/CommonHMAC.h>
#import "RNCryptorDataInput.h"

@interface RNCryptorDataInput ()
@property (nonatomic, readwrite, copy) NSData *data;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@end

@implementation RNCryptorDataInput
@synthesize data = data_;
@synthesize HMACKey = HMACKey_;


- (id)initWithData:(NSData *)data HMACKey:(NSData *)HMACKey
{
  self = [super init];
  if (self)
  {
    data_ = [data copy];
    HMACKey_ = [HMACKey copy];
  }
  return self;
}

- (BOOL)getData:(NSData **)data shouldStop:(BOOL *)stop error:(NSError **)error
{
  *data = self.data;
  *stop = YES;
  return YES;
}

- (NSData *)HMAC
{
  NSMutableData *HMAC = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA1, [self.HMACKey bytes], [self.HMACKey length], [self.data bytes], [self.data length], [HMAC mutableBytes]);
  return HMAC;
}


@end