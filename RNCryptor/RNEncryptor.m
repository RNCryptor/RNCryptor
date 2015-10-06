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
#import "RNCryptor+Private.h"
#import "RNCryptorEngine.h"

#import <CommonCrypto/CommonHMAC.h>

@interface RNEncryptor ()
@property (nonatomic, readwrite, strong) NSData *encryptionSalt;
@property (nonatomic, readwrite, strong) NSData *HMACSalt;
@property (nonatomic, readwrite, strong) NSData *IV;
@property (nonatomic, readwrite, assign) BOOL haveWrittenHeader;
@end

@implementation RNEncryptor
{
  CCHmacContext _HMACContext;
}
@synthesize encryptionSalt = _encryptionSalt;
@synthesize HMACSalt = _HMACSalt;
@synthesize IV = _IV;
@synthesize haveWrittenHeader = _haveWrittenHeader;

+ (void)ansychronouslyEncryptDataFromPath:(NSString *)fromPath
                                   toPath:(NSString *)toPath
                                 password:(NSString *)aPassword
                             successBlock:(void (^)(NSString *toPath))successBlock
                             failureBlock:(void (^)(NSError *error))failureBlock {
    // Make sure that this number is larger than the header + 1 block.
    // 33+16 bytes = 49 bytes. So it shouldn't be a problem.
    int blockSize = 32 * 1024;
    
    NSInputStream *cryptedStream = [NSInputStream inputStreamWithFileAtPath:fromPath];
    NSOutputStream *encryptedStream = [NSOutputStream outputStreamToFileAtPath:toPath append:NO];
    
    [cryptedStream open];
    [encryptedStream open];
    
    // We don't need to keep making new NSData objects. We can just use one repeatedly.
    __block NSMutableData *data = [NSMutableData dataWithLength:blockSize];
    __block RNEncryptor *encryptor = nil;
    
    dispatch_block_t readStreamBlock = ^{
        [data setLength:blockSize];
        NSInteger bytesRead = [cryptedStream read:[data mutableBytes] maxLength:blockSize];
        if (bytesRead < 0) {
            // Throw an error
            NSError *error = [NSError errorWithDomain:kRNCryptorErrorDomain
                                                 code:0
                                             userInfo:@{NSLocalizedDescriptionKey:
                                                            @"Cannot Read from provide fromPath."}];
            if (failureBlock) {
                failureBlock(error);
            }
        }
        else if (bytesRead == 0) {
            [encryptor finish];
        }
        else {
            [data setLength:bytesRead];
            [encryptor addData:data];
            NSLog(@"Sent %ld bytes to decryptor", (unsigned long)bytesRead);
        }
    };
    
    encryptor = [[RNEncryptor alloc] initWithSettings:kRNCryptorAES256Settings
                                             password:aPassword
                                              handler:^(RNCryptor *cryptor, NSData *data) {
                                                  NSLog(@"Decryptor recevied %ld bytes", (unsigned long)data.length);
                                                  if (cryptor.error == nil) {
                                                      [encryptedStream write:data.bytes maxLength:data.length];
                                                      if (cryptor.isFinished) {
                                                          [encryptedStream close];
                                                          // call my delegate that I'm finished with decrypting
                                                          if (successBlock) {
                                                              successBlock(toPath);
                                                          }
                                                      }
                                                      else {
                                                          // Might want to put this in a dispatch_async(), but I don't think you need it.
                                                          readStreamBlock();
                                                      }
                                                  } else {
                                                      if (failureBlock) {
                                                          failureBlock(cryptor.error);
                                                      }
                                                  }
                                              }];
    
    // Read the first block to kick things off
    readStreamBlock();
}

+ (NSData *)encryptData:(NSData *)thePlaintext withSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword error:(NSError **)anError
{
  RNEncryptor *cryptor = [[self alloc] initWithSettings:theSettings
                                               password:aPassword
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext error:anError];
}

+ (NSData *)encryptData:(NSData *)thePlaintext
           withSettings:(RNCryptorSettings)theSettings
               password:(NSString *)aPassword
                     IV:(NSData *)anIV
         encryptionSalt:(NSData *)anEncryptionSalt
               HMACSalt:(NSData *)anHMACSalt
                  error:(NSError **)anError
{
  RNEncryptor *cryptor = [[self alloc] initWithSettings:theSettings
                                               password:aPassword
                                                     IV:anIV
                                         encryptionSalt:anEncryptionSalt
                                               HMACSalt:anHMACSalt
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext error:anError];
}

+ (NSData *)encryptData:(NSData *)thePlaintext withSettings:(RNCryptorSettings)theSettings encryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey error:(NSError **)anError {
  RNEncryptor *cryptor = [[self alloc] initWithSettings:theSettings
                                          encryptionKey:anEncryptionKey
                                                HMACKey:anHMACKey
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext error:anError];
}


+ (NSData *)encryptData:(NSData *)thePlaintext
           withSettings:(RNCryptorSettings)theSettings
          encryptionKey:(NSData *)anEncryptionKey
                HMACKey:(NSData *)anHMACKey
                     IV:(NSData *)anIV
                  error:(NSError **)anError
{
  RNEncryptor *cryptor = [[self alloc] initWithSettings:theSettings
                                          encryptionKey:anEncryptionKey
                                                HMACKey:anHMACKey
                                                     IV:anIV
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:thePlaintext error:anError];
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings
                    encryptionKey:(NSData *)anEncryptionKey
                          HMACKey:(NSData *)anHMACKey
                          handler:(RNCryptorHandler)aHandler {
  return [self initWithSettings:kRNCryptorAES256Settings
                  encryptionKey:anEncryptionKey
                        HMACKey:anHMACKey
                             IV:[[self class] randomDataOfLength:theSettings.IVSize]
                        handler:aHandler];
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings
                    encryptionKey:(NSData *)anEncryptionKey
                          HMACKey:(NSData *)anHMACKey
                               IV:(NSData *)anIV
                          handler:(RNCryptorHandler)aHandler
{
  self = [super initWithHandler:aHandler];
  if (self) {
    self.IV = anIV;

    if (anHMACKey) {
      CCHmacInit(&_HMACContext, theSettings.HMACAlgorithm, anHMACKey.bytes, anHMACKey.length);
      self.HMACLength = theSettings.HMACLength;
    }

    NSError *error = nil;
    self.engine = [[RNCryptorEngine alloc] initWithOperation:kCCEncrypt
                                                    settings:theSettings
                                                         key:anEncryptionKey
                                                          IV:self.IV
                                                       error:&error];
    if (!self.engine) {
      [self cleanupAndNotifyWithError:error];
      self = nil;
      return nil;
    }
  }

  return self;
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword handler:(RNCryptorHandler)aHandler {
    return [self initWithSettings:theSettings
                password:aPassword
                      IV:[[self class] randomDataOfLength:theSettings.IVSize]
          encryptionSalt:[[self class] randomDataOfLength:theSettings.keySettings.saltSize]
                HMACSalt:[[self class] randomDataOfLength:theSettings.HMACKeySettings.saltSize]
                 handler:aHandler];
}


- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings
                         password:(NSString *)aPassword
                               IV:(NSData *)anIV
                   encryptionSalt:(NSData *)anEncryptionSalt
                         HMACSalt:(NSData *)anHMACSalt
                          handler:(RNCryptorHandler)aHandler;
{
  NSParameterAssert(aPassword.length > 0);  // We'll go forward, but this is undefined behavior for RNCryptor
  NSParameterAssert(anIV);
  NSParameterAssert(anEncryptionSalt);
  NSParameterAssert(anHMACSalt);

  NSData *encryptionKey = [[self class] keyForPassword:aPassword salt:anEncryptionSalt settings:theSettings.keySettings];
  NSData *HMACKey = [[self class] keyForPassword:aPassword salt:anHMACSalt settings:theSettings.HMACKeySettings];

  self = [self initWithSettings:theSettings
                  encryptionKey:encryptionKey
                        HMACKey:HMACKey
                             IV:anIV
                        handler:aHandler];
  if (self) {
    self.options |= kRNCryptorOptionHasPassword;
    self.encryptionSalt = anEncryptionSalt;
    self.HMACSalt = anHMACSalt;
  }
  return self;
}

- (NSData *)header
{
  uint8_t header[2] = {kRNCryptorFileVersion, self.options};
  NSMutableData *headerData = [NSMutableData dataWithBytes:header length:sizeof(header)];
  if (self.options & kRNCryptorOptionHasPassword) {
    [headerData appendData:self.encryptionSalt];
    [headerData appendData:self.HMACSalt];
  }
  [headerData appendData:self.IV];
  return headerData;
}

- (void)addData:(NSData *)data
{
  if (self.isFinished) {
    return;
  }

  dispatch_async(self.queue, ^{
    if (!self.haveWrittenHeader) {
      NSData *header = [self header];
      [self.outData setData:header];
      if (self.hasHMAC) {
        CCHmacUpdate(&_HMACContext, [header bytes], [header length]);
      }
      self.haveWrittenHeader = YES;
    }

    NSError *error = nil;
    NSData *encryptedData = [self.engine addData:data error:&error];
    if (!encryptedData) {
      [self cleanupAndNotifyWithError:error];
    }
    if (self.hasHMAC) {
      CCHmacUpdate(&_HMACContext, encryptedData.bytes, encryptedData.length);
    }

    [self.outData appendData:encryptedData];

    dispatch_sync(self.responseQueue, ^{
      self.handler(self, self.outData);
    });
    [self.outData setLength:0];
  });
}

- (void)finish
{
  if (self.isFinished) {
    return;
  }

  dispatch_async(self.queue, ^{
    NSError *error = nil;
    NSData *encryptedData = [self.engine finishWithError:&error];
    [self.outData appendData:encryptedData];
    if (self.hasHMAC) {
      CCHmacUpdate(&_HMACContext, encryptedData.bytes, encryptedData.length);
      NSMutableData *HMACData = [NSMutableData dataWithLength:self.HMACLength];
      CCHmacFinal(&_HMACContext, [HMACData mutableBytes]);
      [self.outData appendData:HMACData];
    }
    [self cleanupAndNotifyWithError:error];
  });
}

@end
