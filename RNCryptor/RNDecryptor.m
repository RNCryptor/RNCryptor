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


#import "RNCryptor+Private.h"
#import "RNDecryptor.h"
#import "RNCryptorEngine.h"

static const NSUInteger kPreambleSize = 2;

@interface RNDecryptor ()
@property (nonatomic, readonly, strong) NSMutableData *inData;
@property (nonatomic, readwrite, copy) NSData *encryptionKey;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@property (nonatomic, readwrite, copy) NSString *password;
@end

@implementation RNDecryptor
{
  CCHmacContext _HMACContext;
  NSMutableData *__inData;
}
@synthesize encryptionKey = _encryptionKey;
@synthesize HMACKey = _HMACKey;
@synthesize password = _password;

+ (NSData *)decryptData:(NSData *)theCipherText withPassword:(NSString *)aPassword error:(NSError **)anError
{
  RNDecryptor *cryptor = [[self alloc] initWithPassword:aPassword
                                                handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:theCipherText error:anError];
}

+ (NSData *)decryptData:(NSData *)theCipherText withEncryptionKey:(NSData *)encryptionKey HMACKey:(NSData *)HMACKey error:(NSError **)anError;
{
  RNDecryptor *cryptor = [[self alloc] initWithEncryptionKey:encryptionKey
                                                     HMACKey:HMACKey
                                                     handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:theCipherText error:anError];

}

- (RNDecryptor *)initWithEncryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey handler:(RNCryptorHandler)aHandler
{
  self = [super initWithHandler:aHandler];
  if (self) {
    _encryptionKey = [anEncryptionKey copy];
    _HMACKey = [anHMACKey copy];
  }

  return self;
}

- (RNDecryptor *)initWithPassword:(NSString *)aPassword handler:(RNCryptorHandler)aHandler
{
  NSParameterAssert(aPassword != nil);

  self = [self initWithEncryptionKey:nil HMACKey:nil handler:aHandler];
  if (self) {
    _password = aPassword;
  }
  return self;
}

- (NSMutableData *)inData
{
  if (!__inData) {
    __inData = [NSMutableData data];
  }
  return __inData;
}

- (void)decryptData:(NSData *)data
{
  dispatch_async(self.queue, ^{
    if (self.hasHMAC) {
      CCHmacUpdate(&_HMACContext, data.bytes, data.length);
    }

    NSError *error;
    NSData *decryptedData = [self.engine addData:data error:&error];

    if (!decryptedData) {
      [self cleanupAndNotifyWithError:error];
      return;
    }

    [self.outData appendData:decryptedData];

    dispatch_sync(self.responseQueue, ^{
      self.handler(self, self.outData);
    });
    [self.outData setLength:0];
  });
}

- (void)addData:(NSData *)theData
{
  if (self.isFinished) {
    return;
  }

  [self.inData appendData:theData];
  if (!self.engine) {
    [self consumeHeaderFromData:self.inData];
  }
  if (self.engine) {
    NSUInteger HMACLength = self.HMACLength;
    if (self.inData.length > HMACLength) {
      NSData *data = [self.inData _RNConsumeToIndex:self.inData.length - HMACLength];
      [self decryptData:data];
    }
  }
}

- (BOOL)getSettings:(RNCryptorSettings *)settings forPreamble:(NSData *)preamble
{
  const uint8_t *bytes = [preamble bytes];
  if (bytes[0] == kRNCryptorFileVersion) {
    *settings = kRNCryptorAES256Settings;

    self.options = bytes[1];

    return YES;
  }

  return NO;
}

- (void)consumeHeaderFromData:(NSMutableData *)data
{
  if (data.length < kPreambleSize) {
    return;
  }

  RNCryptorSettings settings;
  if (![self getSettings:&settings forPreamble:[data subdataWithRange:NSMakeRange(0, kPreambleSize)]]) {
    [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
                                                        code:kRNCryptorUnknownHeader
                                                    userInfo:[NSDictionary dictionaryWithObject:@"Unknown header" /* DNL */
                                                                                         forKey:NSLocalizedDescriptionKey]]];
  }

  NSUInteger headerSize = kPreambleSize + settings.IVSize;
  if (self.options & kRNCryptorOptionHasPassword) {
    headerSize += settings.keySettings.saltSize + settings.HMACKeySettings.saltSize;
  }

  if (data.length < headerSize) {
    return;
  }

  [data _RNConsumeToIndex:kPreambleSize]; // Throw away the preamble

  NSError *error;
  if (self.options & kRNCryptorOptionHasPassword) {
    NSAssert(!self.encryptionKey && !self.HMACKey, @"Both password and the key (%d) or HMACKey (%d) are set.", self.encryptionKey != nil, self.HMACKey != nil);

    NSData *encryptionKeySalt = [data _RNConsumeToIndex:settings.keySettings.saltSize];
    NSData *HMACKeySalt = [data _RNConsumeToIndex:settings.HMACKeySettings.saltSize];

    self.encryptionKey = [[self class] keyForPassword:self.password salt:encryptionKeySalt settings:settings.keySettings];
    self.HMACKey = [[self class] keyForPassword:self.password salt:HMACKeySalt settings:settings.HMACKeySettings];

    self.password = nil;  // Don't need this anymore.
  }

  NSData *IV = [data _RNConsumeToIndex:settings.IVSize];

  self.engine = [[RNCryptorEngine alloc] initWithOperation:kCCDecrypt settings:settings key:self.encryptionKey IV:IV error:&error];
  self.encryptionKey = nil; // Don't need this anymore
  if (!self.engine) {
    [self cleanupAndNotifyWithError:error];
    return;
  }

  if (self.HMACKey) {
    CCHmacInit(&_HMACContext, settings.HMACAlgorithm, self.HMACKey.bytes, self.HMACKey.length);
    self.HMACLength = settings.HMACLength;
    self.HMACKey = nil; // Don't need this anymore
  }
}

- (void)finish
{
  if (self.isFinished) {
    return;
  }

  dispatch_async(self.queue, ^{
    NSError *error;
    NSData *decryptedData = [self.engine finishWithError:&error];

    if (!decryptedData) {
      [self cleanupAndNotifyWithError:error];
      return;
    }
    [self.outData appendData:decryptedData];

    if (self.hasHMAC) {
      NSMutableData *HMACData = [NSMutableData dataWithLength:self.HMACLength];
      CCHmacFinal(&_HMACContext, [HMACData mutableBytes]);

      if (![HMACData isEqualToData:self.inData]) {
        [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
                                                            code:kRNCryptorHMACMismatch
                                                        userInfo:[NSDictionary dictionaryWithObject:@"HMAC Mismatch" /* DNL */
                                                                                             forKey:NSLocalizedDescriptionKey]]];
        return;
      }
    }

    [self cleanupAndNotifyWithError:nil];
  });
}

@end