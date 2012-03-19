//
//  RNDecryptor
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

#import "RNDecryptor.h"
#import "RNCryptorSettings.h"

@interface NSInputStream (RNCryptor)
- (BOOL)_RNGetData:(NSData **)data maxLength:(NSUInteger)maxLength error:(NSError **)error;
@end

@implementation NSInputStream (RNCryptor)
- (BOOL)_RNGetData:(NSData **)data
         maxLength:(NSUInteger)maxLength
             error:(NSError **)error
{
  NSMutableData *buffer = [NSMutableData dataWithLength:maxLength];
  if ([self read:buffer.mutableBytes maxLength:maxLength] < 0)
  {
    if (error)
    {
      *error = [self streamError];
      return NO;
    }
  }

  *data = buffer;
  return YES;
}
@end


@interface RNDecryptor ()
@end

@implementation RNDecryptor
+ (RNDecryptor *)defaultDecryptor
{
  static dispatch_once_t once;
  static RNDecryptor *defaultDecryptor = nil;

  dispatch_once(&once, ^{ defaultDecryptor = [[self alloc] init]; }); // No default configuration. Read it from the data, or pass it to us.
  return defaultDecryptor;

}

- (BOOL)decryptFromStream:(NSInputStream *)input toStream:(NSOutputStream *)output encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV HMACKey:(NSData *)HMACKey error:(NSError **)error
{
  RNCryptorWriteCallback readCallback = nil;
  __block CCHmacContext HMACContext;

  if (HMACKey)
  {
    CCHmacInit(&HMACContext, kCCHmacAlgSHA1, HMACKey.bytes, HMACKey.length);

    readCallback = ^void(NSData *readData) {
      CCHmacUpdate(&HMACContext, readData.bytes, readData.length);
    };
  }

  NSData *streamHMACData;
  BOOL result = [self performOperation:kCCDecrypt
                              fromStream:input
                            readCallback:readCallback
                                toStream:output
                           writeCallback:nil
                           encryptionKey:encryptionKey
                                      IV:IV
                              footerSize:HMACKey ? self.settings.HMACLength : 0
                                  footer:&streamHMACData
                                   error:error];

  if (result && HMACKey)
  {
    NSMutableData *computedHMACData = [NSMutableData dataWithLength:self.settings.HMACLength];
    CCHmacFinal(&HMACContext, [computedHMACData mutableBytes]);

    if (! [computedHMACData isEqualToData:streamHMACData])
    {
      result = NO;
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:1 userInfo:nil]; // FIXME: Better error reports
    }
  }

  return result;
}


- (BOOL)decryptFromStream:(NSInputStream *)input toStream:(NSOutputStream *)output password:(NSString *)password error:(NSError **)error
{
  NSData *encryptionKeySalt;
  NSData *HMACKeySalt;
  NSData *IV;

  [input open];
  if (! [input _RNGetData:&encryptionKeySalt maxLength:self.settings.saltSize error:error] ||
      ! [input _RNGetData:&HMACKeySalt maxLength:self.settings.saltSize error:error] ||
      ! [input _RNGetData:&IV maxLength:self.settings.blockSize error:error])
  {
    return NO;
  }

  NSData *encryptionKey = [self keyForPassword:password salt:encryptionKeySalt];
  NSData *HMACKey = [self keyForPassword:password salt:HMACKeySalt];

  return [self decryptFromStream:input toStream:output encryptionKey:encryptionKey IV:IV HMACKey:HMACKey error:error];
}

- (BOOL)decryptFromURL:(NSURL *)inURL toURL:(NSURL *)outURL append:(BOOL)append password:(NSString *)password error:(NSError **)error
{
  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithURL:inURL];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamWithURL:outURL append:append];

  BOOL result = [self decryptFromStream:decryptInputStream toStream:decryptOutputStream password:password error:error];

  [decryptOutputStream close];
  [decryptInputStream close];

  return result;
}


- (NSData *)decryptData:(NSData *)ciphertext password:(NSString *)password error:(NSError **)error
{
  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:ciphertext];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  BOOL result = [self decryptFromStream:decryptInputStream toStream:decryptOutputStream password:password error:error];

  [decryptOutputStream close];
  [decryptInputStream close];

  if (result)
  {
    return [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  }
  else
  {
    return nil;
  }
}
@end