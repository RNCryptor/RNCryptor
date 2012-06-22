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

@interface NSMutableData (RNCryptor)
- (NSData *)_RNConsumeToIndex:(NSUInteger)index;
@end

// TODO: This is a slightly expensive solution, but it's convenient. May want to create a "walkable" data object
@implementation NSMutableData (RNCryptor)
- (NSData *)_RNConsumeToIndex:(NSUInteger)index
{
  NSData *removed = [self subdataWithRange:NSMakeRange(0, index)];
  [self replaceBytesInRange:NSMakeRange(0, self.length - index) withBytes:([self mutableBytes] + index)];
  [self setLength:self.length - index];
  return removed;
}
@end

@interface RNDecryptor ()
@property (nonatomic, readwrite, strong) NSMutableData *inData;
@property (nonatomic, readwrite, copy) NSData *encryptionKey;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@property (nonatomic, readwrite, copy) NSString *password;
@end

@implementation RNDecryptor
{
  CCHmacContext _HMACContext;
}
@synthesize inData = _inData;
@synthesize encryptionKey = _encryptionKey;
@synthesize HMACKey = _HMACKey;
@synthesize password = _password;

+ (NSData *)decryptData:(NSData *)theCipherText withPassword:(NSString *)aPassword error:(NSError **)anError
{
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  __block NSData *decryptedData;
  __block NSError *returnedError;
  RNDecryptor *cryptor = [[self alloc] initWithPassword:aPassword
                                                handler:nil completion:^(NSData *d, NSError *e) {
        decryptedData = d;
        returnedError = e;
        dispatch_semaphore_signal(sem);
      }];
  dispatch_queue_t queue = dispatch_queue_create("net.robnapier.RNDecryptor.response", DISPATCH_QUEUE_SERIAL);
  cryptor.responseQueue = queue;
  [cryptor addData:theCipherText];
  [cryptor finish];

  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

  dispatch_release(sem);
  dispatch_release(queue);

  if (returnedError) {
    if (anError) {
      *anError = returnedError;
    }
    return nil;
  }
  else {
    return decryptedData;
  }
}

- (RNDecryptor *)initWithEncryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey handler:(RNCryptorHandler)aHandler completion:(RNCryptorCompletion)aCompletion
{
  self = [super initWithHandler:aHandler completion:aCompletion];
  if (self) {
    _encryptionKey = [anEncryptionKey copy];
    _HMACKey = [anHMACKey copy];

    _inData = [NSMutableData data];
  }

  return self;
}

- (RNDecryptor *)initWithPassword:(NSString *)aPassword handler:(RNCryptorHandler)aHandler completion:(RNCryptorCompletion)aCompletion
{
  NSParameterAssert(aPassword != nil);

  self = [self initWithEncryptionKey:nil HMACKey:nil handler:aHandler
                          completion:aCompletion];
  if (self) {
    _password = aPassword;
  }
  return self;
}

- (void)decryptData:(NSData *)data
{
  dispatch_async(self.queue, ^{
    CCHmacUpdate(&_HMACContext, data.bytes, data.length);

    NSError *error;
    NSData *decryptedData = [self.engine addData:data error:&error];

    if (!decryptedData) {
      [self cleanupAndNotifyWithError:error];
      return;
    }

    [self.outData appendData:decryptedData];

    if (self.handler) {
      dispatch_sync(self.responseQueue, ^{
        self.handler(self.outData);
      });
      [self.outData setLength:0];
    }
  });
}

- (void)addData:(NSData *)theData
{
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

- (NSUInteger)headerSizeForSettings:(RNCryptorSettings)settings
{
  if (self.password) {
    return kPreambleSize + settings.keySettings.saltSize + settings.HMACKeySettings.saltSize + settings.IVSize;
  }
  else {
    return settings.IVSize;
  }
}

- (BOOL)getSettings:(RNCryptorSettings *)settings forPreamble:(NSData *)preamble
{
  const uint8_t *bytes = [preamble bytes];
  if (bytes[0] == kRNCryptorFileVersion && bytes[1] == 0) { // Version 0, no options
    *settings = kRNCryptorAES256Settings;
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

  NSUInteger headerSize = [self headerSizeForSettings:settings];
  if (data.length < headerSize) {
    return;
  }

  [data _RNConsumeToIndex:kPreambleSize]; // Throw away the preamble

  NSError *error;
  if (self.password) {
    NSAssert(!self.encryptionKey && !self.HMACKey, @"Both password and the key (%d) or HMACKey (%d) are set.", self.encryptionKey != nil, self.HMACKey != nil);

    NSData *encryptionKeySalt = [data _RNConsumeToIndex:settings.keySettings.saltSize];
    NSData *HMACKeySalt = [data _RNConsumeToIndex:settings.HMACKeySettings.saltSize];

    self.encryptionKey = [[self class] keyForPassword:self.password withSalt:encryptionKeySalt andSettings:settings.keySettings];
    self.HMACKey = [[self class] keyForPassword:self.password withSalt:HMACKeySalt andSettings:settings.HMACKeySettings];

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
  // FIXME: Deal correctly with 0-length data
//  NSAssert(self.engine != NULL, @"Cryptor has be completed");

  dispatch_async(self.queue, ^{
    NSError *error;
    NSData *decryptedData = [self.engine finishWithError:&error];

    if (!decryptedData) {
      [self cleanupAndNotifyWithError:error];
      return;
    }
    [self.outData appendData:decryptedData];

    NSMutableData *HMACData = [NSMutableData dataWithLength:self.HMACLength];
    CCHmacFinal(&_HMACContext, [HMACData mutableBytes]);

    if (![HMACData isEqualToData:self.inData]) {
      [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
                                                          code:kRNCryptorHMACMismatch
                                                      userInfo:[NSDictionary dictionaryWithObject:@"HMAC Mismatch" /* DNL */
                                                                                           forKey:NSLocalizedDescriptionKey]]];
      return;
    }

    [self cleanupAndNotifyWithError:nil];
  });
}

- (void)cleanupAndNotifyWithError:(NSError *)error
{
  if (self.completion) {
    dispatch_sync(self.responseQueue, ^{
      self.completion(self.outData, error);
    });
  }
  [self cleanup];
}

@end