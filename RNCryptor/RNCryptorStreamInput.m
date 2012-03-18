//
//  RNCryptorStreamInput
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

#import "RNCryptorStreamInput.h"

const NSUInteger kBufferSize = 1024;

@interface RNCryptorStreamInput ()
@property (nonatomic, readwrite, assign) CCHmacContext *HMACContext;
@property (nonatomic, readwrite, strong) NSInputStream *stream;
@property (nonatomic, readwrite, assign) RNCryptorHMACLocation HMACLocation;
@property (nonatomic, readwrite, strong) NSData *expectedHMAC;
@property (nonatomic, readwrite, strong) NSMutableData *readBuffer;
@property (nonatomic, readwrite, strong) NSMutableData *readAheadBuffer;
@end

@implementation RNCryptorStreamInput
@synthesize stream = stream_;
@synthesize HMACContext = HMACContext_;
@synthesize HMACLocation = HMACLocation_;
@synthesize expectedHMAC = expectedHMAC_;
@synthesize readBuffer = readBuffer_;
@synthesize readAheadBuffer = readAheadBuffer_;


- (id)initWithStream:(NSInputStream *)stream HMACKey:(NSData *)HMACKey HMACLocation:(RNCryptorHMACLocation)location
{
  self = [super init];
  if (self)
  {
    stream_ = stream;
    [stream open];
    if (HMACKey)
    {
      HMACContext_ = malloc(sizeof(CCHmacContext));
      CCHmacInit(HMACContext_, kCCHmacAlgSHA256, [HMACKey bytes], [HMACKey length]);
    }
    HMACLocation_ = location;
    if (location == kRNCryptorHMACLocationStart)
    {
      NSMutableData *HMAC = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
      [stream read:[HMAC mutableBytes] maxLength:[HMAC length]];
      expectedHMAC_ = HMAC;
      [self loadReadAhead];
    }
  }
  return self;
}

- (void)dealloc
{
  if (HMACContext_)
  {
    free(HMACContext_);
  }
}

- (NSData *)computedHMAC
{
  NSMutableData *HMAC;
  if (self.HMACContext)
  {
    HMAC = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CCHmacFinal(self.HMACContext, [HMAC mutableBytes]);
  }
  return HMAC;
}

- (void)loadReadAhead
{
  NSMutableData *buffer = [NSMutableData dataWithLength:kBufferSize];
  NSInteger length = [self.stream read:[buffer mutableBytes] maxLength:[buffer length]];
  if (length >= 0)
  {
    [buffer setLength:(NSUInteger)length];
  }
  self.readAheadBuffer = buffer;
//  if (length >= 0)
//  {
//    [self.readBuffer setLength:(NSUInteger)length];
//    *data = self.readBuffer;
//    if (self.HMACContext)
//    {
//      CCHmacUpdate(self.HMACContext, [self.readBuffer bytes], [self.readBuffer length]);
//    }
//  }
//
//  if (length < kBufferSize) // Short block
//  {
//    *stop = YES;
//    [self.stream close];
//  }
//
//  if (length < 0)
//  {
//    *error = [self.stream streamError];
//    [self.stream close];
//  }
//
//  return (length >= 0);
}

- (BOOL)getData:(NSData **)data shouldStop:(BOOL *)stop error:(NSError **)error
{
  // Error
  if ([self.stream streamStatus] == NSStreamStatusError)
  {
    *stop = YES;
    *error = [self.stream streamError];
    return NO;
  }

  // Not at end (read-ahead has a full block). Read another block.
  if ([self.stream streamStatus] != NSStreamStatusAtEnd)
  {
    self.readBuffer = self.readAheadBuffer;
    [self loadReadAhead];
  }

  // At end now?
  if ([self.stream streamStatus] == NSStreamStatusAtEnd)
  {
      // Put everything together
    [self.readBuffer appendData:self.readAheadBuffer];
    self.readAheadBuffer = nil;
    *stop = YES;
    if (self.HMACLocation == kRNCryptorHMACLocationEnd)
    {
      self.expectedHMAC = [self.readBuffer subdataWithRange:NSMakeRange([self.readBuffer length] - CC_SHA1_DIGEST_LENGTH - 1, CC_SHA1_DIGEST_LENGTH)];
      [self.readBuffer setLength:[self.readBuffer length] - CC_SHA1_DIGEST_LENGTH];
    }
  }

  *data = self.readBuffer;
  return YES;
}

@end