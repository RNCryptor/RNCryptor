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


#import "RNDecryptor.h"

static const uint8_t kCurrentFileVersion = 0; // FIXME: Move to superclass
static const NSUInteger kPreambleSize = 2;

// TODO: Refactor; we don't really need a stream here. We could just work on the data? Or build a NSData reader?
@interface NSInputStream (RNCryptor)
- (BOOL)_RNGetData:(NSData **)data maxLength:(NSUInteger)maxLength error:(NSError **)error;
@end

@implementation NSInputStream (RNCryptor)
- (BOOL)_RNGetData:(NSData **)data maxLength:(NSUInteger)maxLength error:(NSError **)error
{
  NSMutableData *buffer = [NSMutableData dataWithLength:maxLength];
  if ([self read:buffer.mutableBytes maxLength:maxLength] < 0) {
    if (error) {
      *error = [RNCryptor errorWithCode:kRNCryptorCouldNotReadStream localizedDescription:@"Could not read from stream" underlyingError:[self streamError]];
      return NO;
    }
  }

  *data = buffer;
  return YES;
}
@end

@interface NSMutableData (RNCryptor)
- (NSData *)_RNDataRemovedToIndex:(NSUInteger)index;
@end

@implementation NSMutableData (RNCryptor)
- (NSData *)_RNDataRemovedToIndex:(NSUInteger)index
{
  NSData *removed = [self subdataWithRange:NSMakeRange(0, index)];
  [self replaceBytesInRange:NSMakeRange(0, self.length - index) withBytes:([self mutableBytes] + index)];
  [self setLength:self.length - index];
  return removed;
}
@end

@interface RNDecryptor ()
@property (nonatomic, readwrite, strong) NSMutableData *inData;
@property (nonatomic, readonly) NSMutableData *outData;
@property (nonatomic, readwrite, assign) CCCryptorRef cryptor;
@property (nonatomic, readwrite, assign) NSUInteger HMACLength;
@property (nonatomic, readwrite, copy) RNCryptorHandler handler;
@property (nonatomic, readwrite, copy) RNCryptorCompletion completion;
@property (nonatomic, readwrite, assign) dispatch_queue_t queue;
@property (nonatomic, readonly) NSMutableData *buffer;
@property (nonatomic, readwrite, copy) NSData *encryptionKey;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@property (nonatomic, readwrite, copy) NSString *password;
@end

@implementation RNDecryptor
{
  CCHmacContext _HMACContext;
}
@synthesize cryptor = _cryptor;
@synthesize outData = __outData;
@synthesize handler = _handler;
@synthesize completion = _completion;
@synthesize queue = _queue;
@synthesize HMACLength = _HMACLength;
@synthesize buffer = __buffer;
@synthesize responseQueue = _responseQueue;
@synthesize encryptionKey = _encryptionKey;
@synthesize HMACKey = _HMACKey;

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

  if (anError) {
    *anError = returnedError;
  }

  dispatch_release(sem);
  dispatch_release(queue);

  return decryptedData;
}

- (RNDecryptor *)initWithEncryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey handler:(RNCryptorHandler)aHandler completion:(RNCryptorCompletion)aCompletion
{
  self = [super init];
  if (self) {
    _encryptionKey = [anEncryptionKey copy];
    _HMACKey = [anHMACKey copy];
    _handler = [aHandler copy];
    _completion = [aCompletion copy];

    _queue = dispatch_queue_create("net.robnapier.RNDecryptor", DISPATCH_QUEUE_SERIAL);
    __buffer = [NSMutableData data];
    _inData = [NSMutableData data];
    __outData = [NSMutableData data];
    _responseQueue = dispatch_get_current_queue();
    dispatch_retain(_responseQueue);
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

- (void)cleanup
{
  if (_cryptor) {
    CCCryptorRelease(_cryptor);
    _cryptor = NULL;
  }

  __outData = nil;
  _inData = nil;
  _handler = nil;
  _completion = nil;

  __buffer = nil;

  if (_responseQueue) {
    dispatch_release(_responseQueue);
    _responseQueue = NULL;
  }
}

- (void)dealloc
{
  [self cleanup];
  if (_queue) {
    dispatch_release(_queue);
    _queue = NULL;
  }
}

- (void)setResponseQueue:(dispatch_queue_t)aResponseQueue
{
  if (aResponseQueue) {
    dispatch_retain(aResponseQueue);
  }

  if (_responseQueue) {
    dispatch_release(_responseQueue);
  }

  _responseQueue = aResponseQueue;
}

- (void)decryptData:(NSData *)data
{
  dispatch_async(self.queue, ^{
    NSMutableData *buffer = self.buffer;
    [buffer setLength:CCCryptorGetOutputLength(self.cryptor, [data length], true)]; // We'll reuse the buffer in -finish

    CCHmacUpdate(&_HMACContext, data.bytes, data.length);

    size_t dataOutMoved;
    CCCryptorStatus
        cryptorStatus = CCCryptorUpdate(self.cryptor,       // cryptor
                                        data.bytes,      // dataIn
                                        data.length,     // dataInLength (verified > 0 above)
                                        buffer.mutableBytes,      // dataOut
                                        buffer.length, // dataOutAvailable
                                        &dataOutMoved);   // dataOutMoved

    if (cryptorStatus != kCCSuccess) {
      [self cleanupAndNotifyWithStatus:cryptorStatus];
      return;
    }

    [self.outData appendData:[buffer subdataWithRange:NSMakeRange(0, dataOutMoved)]];

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
  if (!self.cryptor) {
    [self parseHeaderFromData:self.inData];
  }
  if (self.cryptor) {
    NSUInteger HMACLength = self.HMACLength;
    if (self.inData.length > HMACLength) {
      NSData *data = [self.inData _RNDataRemovedToIndex:self.inData.length - HMACLength];
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
  if (bytes[0] == kCurrentFileVersion && bytes[1] == 0) { // Version 0, no options
    *settings = kRNCryptorAES256Settings;
    return YES;
  }

  return NO;
}

- (void)parseHeaderFromData:(NSMutableData *)data
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

  NSData *header = [data _RNDataRemovedToIndex:headerSize];
  header = [header subdataWithRange:NSMakeRange(kPreambleSize, headerSize - kPreambleSize)]; // Don't need the preamble anymore

  NSInputStream *input = [[NSInputStream alloc] initWithData:header];
  [input open];
  NSError *error;
  if (self.password) {
    NSAssert(!self.encryptionKey && !self.HMACKey, @"Both password and the key (%d) or HMACKey (%d) are set. This should never happen.", self.encryptionKey != nil, self.HMACKey != nil);

    NSData *encryptionKeySalt;
    NSData *HMACKeySalt;

    if (![input _RNGetData:&encryptionKeySalt maxLength:settings.keySettings.saltSize error:&error] ||
        ![input _RNGetData:&HMACKeySalt maxLength:settings.HMACKeySettings.saltSize error:&error]
        ) {
      [self cleanupAndNotifyWithError:error];
      return;
    }

    self.encryptionKey = [[self class] keyForPassword:self.password withSalt:encryptionKeySalt andSettings:settings.keySettings];
    self.HMACKey = [[self class] keyForPassword:self.password withSalt:HMACKeySalt andSettings:settings.HMACKeySettings];

    self.password = nil;  // Don't need this anymore.
  }

  NSData *IV;
  if (![input _RNGetData:&IV maxLength:settings.IVSize error:&error]) {
    [self cleanupAndNotifyWithError:error];
    return;
  }

  CCCryptorStatus
      cryptorStatus = CCCryptorCreateWithMode(kCCDecrypt,
                                              settings.mode,
                                              settings.algorithm,
                                              settings.padding,
                                              IV.bytes,
                                              self.encryptionKey.bytes,
                                              self.encryptionKey.length,
      NULL, // tweak
                                              0, // tweakLength
                                              0, // numRounds (0=default)
                                              settings.modeOptions,
                                              &_cryptor);

  self.encryptionKey = nil; // Don't need this anymore

  if (cryptorStatus != kCCSuccess || _cryptor == NULL) {
    [self cleanupAndNotifyWithStatus:cryptorStatus];
    return;
  }

  if (self.HMACKey) {
    CCHmacInit(&_HMACContext, settings.HMACAlgorithm, self.HMACKey.bytes, self.HMACKey.length);
    self.HMACLength = settings.HMACLength;
    self.HMACKey = nil; // Don't need this anymore
  }
  [input close];
}

- (void)finish
{
  NSAssert(self.cryptor != NULL, @"Cryptor has be completed");

  dispatch_async(self.queue, ^{
    NSMutableData *buffer = self.buffer;

    size_t dataOutMoved;
    CCCryptorStatus
        cryptorStatus = CCCryptorFinal(self.cryptor,        // cryptor
                                       buffer.mutableBytes,       // dataOut
                                       buffer.length,  // dataOutAvailable
                                       &dataOutMoved);    // dataOutMoved

    if (cryptorStatus != kCCSuccess) {
      [self cleanupAndNotifyWithStatus:cryptorStatus];
      return;
    }

    [buffer setLength:dataOutMoved];
    [self.outData appendData:buffer];

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

- (void)cleanupAndNotifyWithStatus:(CCCryptorStatus)status
{
  [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain code:status userInfo:nil]];
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