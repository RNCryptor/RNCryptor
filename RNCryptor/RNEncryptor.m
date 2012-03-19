//
//  RNEncryptor
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

#import "RNEncryptor.h"
#import "RNCryptorSettings.h"

@interface NSOutputStream (RNCryptor)
- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error;
@end

@implementation NSOutputStream (RNCryptor)
- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error
{
  // Writing 0 bytes will close the output stream.
  // This is an undocumented side-effect. radar://9930518
  if (data.length > 0)
  {
    NSInteger bytesWritten = [self write:data.bytes
                               maxLength:data.length];
    if (bytesWritten != data.length)
    {
      if (error)
      {
        *error = [self streamError];
      }
      return NO;
    }
  }
  return YES;
}
@end

@interface RNEncryptor ()
@end

@implementation RNEncryptor

+ (RNEncryptor *)defaultEncryptor
{
  static dispatch_once_t once;
  static RNEncryptor *defaultEncryptor = nil;

  dispatch_once(&once, ^{ defaultEncryptor = [[self alloc] initWithSettings:[RNCryptorSettings defaultSettings]]; });
  return defaultEncryptor;
}

- (BOOL)encryptFromStream:(NSInputStream *)input toStream:(NSOutputStream *)output encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV HMACKey:(NSData *)HMACKey error:(NSError **)error
{
  RNCryptorWriteCallback writeCallback = nil;
  __block CCHmacContext HMACContext;

  if (HMACKey)
  {
    CCHmacInit(&HMACContext, kCCHmacAlgSHA1, HMACKey.bytes, HMACKey.length);

    writeCallback = ^void(NSData *writeData) {
      CCHmacUpdate(&HMACContext, writeData.bytes, writeData.length);
    };
  }

  BOOL result = [self performOperation:kCCEncrypt
                              fromStream:input
                            readCallback:nil
                                toStream:output
                           writeCallback:writeCallback
                           encryptionKey:encryptionKey
                                      IV:IV
                              footerSize:0
                                  footer:nil
                                   error:error];

  if (HMACKey && result)
  {
    NSMutableData *HMACData = [NSMutableData dataWithLength:self.settings.HMACLength];
    CCHmacFinal(&HMACContext, [HMACData mutableBytes]);

    if (! [output _RNWriteData:HMACData error:error])
    {
      return NO;
    }
  }

  return result;
}
- (BOOL)encryptFromStream:(NSInputStream *)input toStream:(NSOutputStream *)output password:(NSString *)password error:(NSError **)error
{
  NSData *encryptionKeySalt = [self randomDataOfLength:self.settings.saltSize];
  NSData *encryptionKey = [self keyForPassword:password salt:encryptionKeySalt];

  NSData *HMACKeySalt = [self randomDataOfLength:self.settings.saltSize];
  NSData *HMACKey = [self keyForPassword:password salt:HMACKeySalt];

  NSData *IV = [self randomDataOfLength:self.settings.blockSize];

  [output open];
  if (! [output _RNWriteData:encryptionKeySalt error:error] ||
      ! [output _RNWriteData:HMACKeySalt error:error] ||
      ! [output _RNWriteData:IV error:error]
    )
  {
    return NO;
  }

  return [self encryptFromStream:input toStream:output encryptionKey:encryptionKey IV:IV HMACKey:HMACKey error:error];
}


- (NSData *)encryptData:(NSData *)plaintext password:(NSString *)password error:(NSError **)error
{
  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:plaintext];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  BOOL result = [self encryptFromStream:encryptInputStream toStream:encryptOutputStream password:password error:error];

  [encryptOutputStream close];
  [encryptInputStream close];

  if (result)
  {
    return [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  }
  else
  {
    return nil;
  }
}


@end