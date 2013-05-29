//
//  RNCryptorEngine
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


#import "RNCryptorEngine.h"

@interface RNCryptorEngine ()
@property (nonatomic, readonly) CCCryptorRef cryptor;
@property (nonatomic, readonly) NSMutableData *buffer;
@end

@implementation RNCryptorEngine
@synthesize cryptor = __cryptor;
@synthesize buffer = __buffer;


- (RNCryptorEngine *)initWithOperation:(CCOperation)operation settings:(RNCryptorSettings)settings key:(NSData *)key IV:(NSData *)IV error:(NSError **)error
{
  self = [super init];
  if (self) {
    CCCryptorStatus
        cryptorStatus = CCCryptorCreate(operation,
                                        settings.algorithm,
                                        settings.options,
                                        key.bytes,
                                        key.length,
                                        IV.bytes,
                                        &__cryptor);
    if (cryptorStatus != kCCSuccess || __cryptor == NULL) {
      if (error) {
        *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
      }
      self = nil;
      return nil;
    }

    __buffer = [NSMutableData data];
  }
  return self;
}

- (void)dealloc
{
  if (__cryptor) {
    CCCryptorRelease(__cryptor);
  }
}

- (NSData *)addData:(NSData *)data error:(NSError **)error
{
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
    if (error) {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    return nil;
  }

  return [buffer subdataWithRange:NSMakeRange(0, dataOutMoved)];
}

- (NSData *)finishWithError:(NSError **)error
{
  NSMutableData *buffer = self.buffer;
  size_t dataOutMoved;
  CCCryptorStatus
      cryptorStatus = CCCryptorFinal(self.cryptor,        // cryptor
                                     buffer.mutableBytes,       // dataOut
                                     buffer.length,  // dataOutAvailable
                                     &dataOutMoved);    // dataOutMoved
  if (cryptorStatus != kCCSuccess) {
    if (error) {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    return nil;
  }

  return [buffer subdataWithRange:NSMakeRange(0, dataOutMoved)];
}

@end
