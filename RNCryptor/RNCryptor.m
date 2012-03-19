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

#import "RNCryptor.h"
#import "RNCryptorSettings.h"

NSUInteger kSmallestBlockSize = 1024;

// According to Apple documentation, you can use a single buffer
// to do in-place encryption or decryption. This does not work
// in cases where you call CCCryptUpdate multiple times and you
// have padding enabled. radar://9930555
#define RNCRYPTOR_USE_SAME_BUFFER 0

NSString *const kRNCryptorErrorDomain = @"net.robnapier.RNCryptManager";

@interface RNCryptor ()
@end

@implementation RNCryptor
@synthesize settings = settings_;

- (RNCryptor *)init
{
  return [self initWithSettings:[RNCryptorSettings defaultSettings]];
}

- (RNCryptor *)initWithSettings:(RNCryptorSettings *)settings
{
  self = [super init];
  if (self)
  {
    settings_ = settings;
  }
  return self;
}

- (NSData *)randomDataOfLength:(size_t)length
{
  NSMutableData *data = [NSMutableData dataWithLength:length];

  int result = SecRandomCopyBytes(kSecRandomDefault,
                                  length,
                                  data.mutableBytes);
  NSAssert(result == 0, @"Unable to generate random bytes: %d",
  errno);

  return data;
}

- (NSData *)keyForPassword:(NSString *)password
                      salt:(NSData *)salt
{
  NSMutableData *
      derivedKey = [NSMutableData dataWithLength:self.settings.keySize];

  int
      result = CCKeyDerivationPBKDF(kCCPBKDF2,            // algorithm
                                    password.UTF8String,  // password
                                    password.length,  // passwordLength
                                    salt.bytes,           // salt
                                    salt.length,          // saltLen
                                    kCCPRFHmacAlgSHA1,    // PRF
                                    self.settings.PBKDFRounds,         // rounds
                                    derivedKey.mutableBytes, // derivedKey
                                    derivedKey.length); // derivedKeyLen

  // Do not log password here
  NSAssert(result == kCCSuccess,
  @"Unable to create AES key for password: %d", result);

  return derivedKey;
}

- (BOOL)processResult:(CCCryptorStatus)cryptorStatus
                data:(NSMutableData *)outData
               length:(size_t)length
             callback:(RNCryptorWriteCallback)writeCallback
               output:(NSOutputStream *)output
                error:(NSError **)error
{
  if (cryptorStatus != kCCSuccess)
  {
    if (error)
    {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    NSLog(@"%s Could not process data: %d", __PRETTY_FUNCTION__, cryptorStatus);
    return NO;
  }

  if (length > 0)
  {
    [outData setLength:length];

    [output open];
    NSInteger bytesWritten = [output write:outData.bytes
                                 maxLength:outData.length];
    if (bytesWritten != outData.length)
    {
      if (error)
      {
        *error = [output streamError];
      }
      return NO;
    }

    if (writeCallback)
    {
      writeCallback(outData);
    }
  }
  return YES;
}

NSUInteger NextMultipleOfUnit(NSUInteger size, NSUInteger unit)
{
  return ((size + unit - 1) / unit) * unit;
}

- (BOOL)performOperation:(CCOperation)operation
              fromStream:(NSInputStream *)input
            readCallback:(RNCryptorReadCallback)readCallback
                toStream:(NSOutputStream *)output
           writeCallback:(RNCryptorWriteCallback)writeCallback
           encryptionKey:(NSData *)encryptionKey
                      IV:(NSData *)IV
             footerSize:(NSUInteger)footerSize
                 footer:(NSData **)footer
                   error:(NSError **)error
{
 // Create the cryptor
  CCCryptorRef cryptor = NULL;
  CCCryptorStatus cryptorStatus;
  cryptorStatus = CCCryptorCreate(operation,             // operation
                                  self.settings.algorithm,            // algorithm
                                  kCCOptionPKCS7Padding, // options
                                  encryptionKey.bytes,             // key
                                  encryptionKey.length,            // key length
                                  IV.bytes,              // IV
                                  &cryptor);             // OUT cryptorRef

  if (cryptorStatus != kCCSuccess || cryptor == NULL)
  {
    if (error)
    {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    NSAssert(NO, @"Could not create cryptor: %d", cryptorStatus);
    return NO;
  }

  const NSUInteger bufferSize = NextMultipleOfUnit(MAX(footerSize + 1, kSmallestBlockSize), self.settings.blockSize);
  NSMutableData *readBuffer = [NSMutableData data];

  // Read ahead
  NSMutableData *readAheadBuffer = [NSMutableData dataWithLength:bufferSize];
  [input open];
  NSInteger length = [input read:[readAheadBuffer mutableBytes] maxLength:[readAheadBuffer length]];
  if (length >= 0)
  {
    [readAheadBuffer setLength:(NSUInteger)length];
  }

  NSMutableData *outData = [NSMutableData data];
  BOOL stop = NO;
  size_t dataOutMoved;
  while (!stop)
  {
    // Error
    if ([input streamStatus] == NSStreamStatusError)
    {
      *error = [input streamError];
      CCCryptorRelease(cryptor);
      return NO;
    }

    // Not at end (read-ahead has a full block). Read another block.
    if ([input streamStatus] != NSStreamStatusAtEnd)
    {
      readBuffer = readAheadBuffer;
      readAheadBuffer = [NSMutableData dataWithLength:bufferSize];
      length = [input read:[readAheadBuffer mutableBytes] maxLength:bufferSize];
      if (length >= 0)
      {
        [readAheadBuffer setLength:(NSUInteger)length];
      }
    }

    // At end now?
    if ([input streamStatus] == NSStreamStatusAtEnd)
    {
      // Put everything together
      [readBuffer appendData:readAheadBuffer];
      readAheadBuffer = nil;
      stop = YES;
      if (footer && footerSize > 0)
      {
        *footer = [readBuffer subdataWithRange:NSMakeRange([readBuffer length] - footerSize, footerSize)];
        [readBuffer setLength:[readBuffer length] - footerSize];
      }
    }

    if (readCallback)
    {
      readCallback(readBuffer);
    }
    [outData setLength:CCCryptorGetOutputLength(cryptor, [readBuffer length], true)];
    cryptorStatus = CCCryptorUpdate(cryptor,       // cryptor
                                    readBuffer.bytes,      // dataIn
                                    readBuffer.length,     // dataInLength (verified > 0 above)
                                    outData.mutableBytes,      // dataOut
                                    outData.length, // dataOutAvailable
                                    &dataOutMoved);   // dataOutMoved
    if (![self processResult:cryptorStatus data:outData length:dataOutMoved callback:writeCallback output:output error:error])
    {
      CCCryptorRelease(cryptor);
      return NO;
    }
  }

  [outData setLength:CCCryptorGetOutputLength(cryptor, bufferSize, true)];

   // Write the final block
   cryptorStatus = CCCryptorFinal(cryptor,        // cryptor
                                  outData.mutableBytes,       // dataOut
                                  outData.length,  // dataOutAvailable
                                  &dataOutMoved);    // dataOutMoved
  if (![self processResult:cryptorStatus data:outData length:dataOutMoved callback:writeCallback output:output error:error])
   {
     CCCryptorRelease(cryptor);
     return NO;
   }

   CCCryptorRelease(cryptor);
   return YES;
}

@end
