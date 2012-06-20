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

@interface RNEncryptor ()
@property (nonatomic, readonly) NSMutableData *outData;
@property (nonatomic, readwrite, assign) CCCryptorRef cryptor;
@property (nonatomic, readwrite, assign) CCHmacContext HMACContext;
@property (nonatomic, readonly) NSUInteger HMACLength;
@property (nonatomic, readwrite, copy) RNCryptorHandler handler;
@property (nonatomic, readwrite, copy) RNCryptorCompletion completion;
@property (nonatomic, readwrite, assign) dispatch_queue_t queue;
@property (nonatomic, readonly, strong) NSMutableData *buffer;
@end

@implementation RNEncryptor
@synthesize cryptor = _cryptor;
@synthesize outData = __outData;
@synthesize handler = _handler;
@synthesize completion = _completion;
@synthesize queue = _queue;
@synthesize HMACContext = _HMACContext;
@synthesize HMACLength = __HMACLength;
@synthesize buffer = __buffer;


- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings encryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey handler:(RNCryptorHandler)aHandler completion:(RNCryptorCompletion)aCompletion
{
  self = [super init];
  if (self) {
    NSData *IV = [[self class] randomDataOfLength:theSettings.IVSize];
    __outData = [IV mutableCopy];

    CCCryptorStatus
        cryptorStatus = CCCryptorCreateWithMode(kCCEncrypt,
                                                theSettings.mode,
                                                theSettings.algorithm,
                                                theSettings.padding,
                                                IV.bytes,
                                                anEncryptionKey.bytes,
                                                anEncryptionKey.length,
        NULL, // tweak
                                                0, // tweakLength
                                                0, // numRounds (0=default)
                                                theSettings.modeOptions,
                                                &_cryptor);

    if (cryptorStatus != kCCSuccess || _cryptor == NULL) {
      self = nil;
      NSAssert(NO, @"Could not create cryptor: %d", cryptorStatus);
      return nil;
    }

    if (anHMACKey) {
      CCHmacInit(&_HMACContext, theSettings.HMACAlgorithm, anHMACKey.bytes, anHMACKey.length);
      __HMACLength = theSettings.HMACLength;
    }

    _handler = [aHandler copy];
    _completion = [aCompletion copy];
    _queue = dispatch_queue_create("net.robnapier.rncryptor", DISPATCH_QUEUE_SERIAL);
    __buffer = [NSMutableData data];
  }

  return self;
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword handler:(RNCryptorHandler)aHandler completion:(RNCryptorCompletion)aCompletion
{
  NSParameterAssert(aPassword != nil);

  NSData *encryptionKeySalt = [[self class] randomDataOfLength:theSettings.keySettings.saltSize];
  NSData *encryptionKey = [[self class] keyForPassword:aPassword withSalt:encryptionKeySalt andSettings:theSettings.keySettings];

  NSData *HMACKeySalt = [[self class] randomDataOfLength:theSettings.HMACKeySettings.saltSize];
  NSData *HMACKey = [[self class] keyForPassword:aPassword withSalt:HMACKeySalt andSettings:theSettings.HMACKeySettings];

  uint8_t header[2] = {0, 0};
  NSMutableData *headerData = [NSMutableData dataWithBytes:header length:sizeof(header)];
  [headerData appendData:encryptionKeySalt];
  [headerData appendData:HMACKeySalt];

  self = [self initWithSettings:theSettings
                  encryptionKey:encryptionKey
                        HMACKey:HMACKey
                        handler:aHandler
                     completion:aCompletion];
  if (self) {
    // Prepend our header
    [headerData appendData:__outData];
    __outData = headerData;
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
  _handler = nil;
  _completion = nil;

  if (_queue) {
    dispatch_release(_queue);
    _queue = NULL;
  }

  __buffer = nil;
}

- (void)dealloc
{
  [self cleanup];
}

- (void)addData:(NSData *)data
{
  NSAssert(self.cryptor != NULL, @"Cryptor has be completed");

  NSMutableData *buffer = self.buffer;
  [buffer setLength:CCCryptorGetOutputLength(self.cryptor, [data length], true)]; // We'll reuse the buffer in -finish

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

  CCHmacUpdate(&_HMACContext, buffer.bytes, dataOutMoved);

  [self.outData appendData:[self.buffer subdataWithRange:NSMakeRange(0, dataOutMoved)]];

  if (self.handler) {
    self.handler(self.outData);
    [self.outData setLength:0];
  }
}

- (void)finish
{
  NSAssert(self.cryptor != NULL, @"Cryptor has be completed");

  NSMutableData *buffer = self.buffer;

  size_t dataOutMoved;
  CCCryptorStatus
      cryptorStatus = CCCryptorFinal(self.cryptor,        // cryptor
                                     buffer.mutableBytes,       // dataOut
                                     buffer.length,  // dataOutAvailable
                                     &dataOutMoved);    // dataOutMoved
  [buffer setLength:dataOutMoved];
  [self.outData appendData:buffer];

  CCHmacUpdate(&_HMACContext, buffer.bytes, dataOutMoved);

  NSMutableData *HMACData = [NSMutableData dataWithLength:self.HMACLength];
  CCHmacFinal(&_HMACContext, [HMACData mutableBytes]);

  [self.outData appendData:HMACData];

  [self cleanupAndNotifyWithStatus:cryptorStatus];
}

- (void)cleanupAndNotifyWithStatus:(CCCryptorStatus)cryptorStatus
{
  if (self.completion) {
    NSError *error = nil;
    if (cryptorStatus != kCCSuccess) {
      error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    self.completion(self.outData, error);
  }

  [self cleanup];
}

@end