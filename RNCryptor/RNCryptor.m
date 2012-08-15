//
//  RNCryptor.m
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
//
#import "RNCryptor.h"
#import "RNCryptor+Private.h"

NSString *const kRNCryptorErrorDomain = @"net.robnapier.RNCryptManager";
const uint8_t kRNCryptorFileVersion = 1;

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


@implementation RNCryptor
@synthesize responseQueue = _responseQueue;
@synthesize engine = _engine;
@synthesize outData = __outData;
@synthesize queue = _queue;
@synthesize HMACLength = __HMACLength;
@synthesize error = _error;
@synthesize finished = _finished;
@synthesize options = _options;
@synthesize handler = _handler;

+ (NSData *)synchronousResultForCryptor:(RNCryptor *)cryptor data:(NSData *)inData error:(NSError **)anError
{
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  NSMutableData *data = [NSMutableData data];
  __block NSError *returnedError;

  RNCryptorHandler handler = ^(RNCryptor *c, NSData *d) {
    [data appendData:d];
    if (c.isFinished) {
      returnedError = c.error;
      dispatch_semaphore_signal(sem);
    }
  };

  cryptor.handler = handler;

  dispatch_queue_t queue = dispatch_queue_create("net.robnapier.RNEncryptor.response", DISPATCH_QUEUE_SERIAL);
  cryptor.responseQueue = queue;
  [cryptor addData:inData];
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
    return data;
  }
}


+ (NSData *)keyForPassword:(NSString *)password salt:(NSData *)salt settings:(RNCryptorKeyDerivationSettings)keySettings
{
  NSMutableData *derivedKey = [NSMutableData dataWithLength:keySettings.keySize];

  int result = CCKeyDerivationPBKDF(keySettings.PBKDFAlgorithm,         // algorithm
                                    password.UTF8String,                // password
                                    password.length,                    // passwordLength
                                    salt.bytes,                         // salt
                                    salt.length,                        // saltLen
                                    keySettings.PRF,                    // PRF
                                    keySettings.rounds,                 // rounds
                                    derivedKey.mutableBytes,            // derivedKey
                                    derivedKey.length);                 // derivedKeyLen

  // Do not log password here
  // TODO: Is is safe to assert here? We read salt from a file (but salt.length is internal).
  NSAssert(result == kCCSuccess, @"Unable to create AES key for password: %d", result);

  return derivedKey;
}

+ (NSData *)randomDataOfLength:(size_t)length
{
  NSMutableData *data = [NSMutableData dataWithLength:length];

  int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
  NSAssert(result == 0, @"Unable to generate random bytes: %d", errno);

  return data;
}

- (id)initWithHandler:(RNCryptorHandler)handler
{
  NSParameterAssert(handler);
  self = [super init];
  if (self) {
    _responseQueue = dispatch_get_current_queue();
    dispatch_retain(_responseQueue);

    NSString *queueName = [@"net.robnapier." stringByAppendingString:NSStringFromClass([self class])];
    _queue = dispatch_queue_create([queueName UTF8String], DISPATCH_QUEUE_SERIAL);
    __outData = [NSMutableData data];

    _handler = [handler copy];
  }
  return self;
}

- (void)dealloc
{
  if (_responseQueue) {
    dispatch_release(_responseQueue);
    _responseQueue = NULL;
  }

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

- (void)addData:(NSData *)data
{

}

- (void)finish
{

}

- (void)cleanupAndNotifyWithError:(NSError *)error
{
  self.error = error;
  self.finished = YES;
  if (self.handler) {
    dispatch_sync(self.responseQueue, ^{
      self.handler(self, self.outData);
    });
    self.handler = nil;
  }
}

- (BOOL)hasHMAC
{
  return self.HMACLength > 0;
}


@end