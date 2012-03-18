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

// According to Apple documentation, you can use a single buffer
// to do in-place encryption or decryption. This does not work
// in cases where you call CCCryptUpdate multiple times and you
// have padding enabled. radar://9930555
#define RNCRYPTOR_USE_SAME_BUFFER 0

NSString *const kRNCryptorErrorDomain = @"net.robnapier.RNCryptManager";

//@interface NSOutputStream (Data)
//- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error;
//@end
//
//@implementation NSOutputStream (Data)
//- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error
//{
//  // Writing 0 bytes will close the output stream.
//  // This is an undocumented side-effect. radar://9930518
//  if (data.length > 0)
//  {
//    NSInteger bytesWritten = [self write:data.bytes
//                               maxLength:data.length];
//    if (bytesWritten != data.length)
//    {
//      if (error)
//      {
//        *error = [self streamError];
//      }
//      return NO;
//    }
//  }
//  return YES;
//}
//
//@end

//@interface NSInputStream (Data)
//- (BOOL)_RNGetData:(NSData **)data
//         maxLength:(NSUInteger)maxLength
//             error:(NSError **)error;
//@end
//
//@implementation NSInputStream (Data)
//
//- (BOOL)_RNGetData:(NSData **)data
//         maxLength:(NSUInteger)maxLength
//             error:(NSError **)error
//{
//
//  NSMutableData *buffer = [NSMutableData dataWithLength:maxLength];
//  if ([self read:buffer.mutableBytes maxLength:maxLength] < 0)
//  {
//    if (error)
//    {
//      *error = [self streamError];
//      return NO;
//    }
//  }
//
//  *data = buffer;
//  return YES;
//}
//
//@end

@interface RNCryptor ()
@property (nonatomic, readonly, assign) RNCryptorConfiguration configuration;

@end

@implementation RNCryptor
@synthesize configuration = configuration_;


+ (RNCryptor *)defaultCryptor
{
  return [self AES128Cryptor];
}

+ (id)AES128Cryptor
{
  static dispatch_once_t once;
  static id sharedInstance = nil;

  dispatch_once(&once, ^{
    sharedInstance = [[self alloc] initWithConfiguration:[self AES128Configuration]];
  });
  return sharedInstance;
}

- (RNCryptor *)init
{
  return [self initWithConfiguration:[RNCryptor AES128Configuration]];
}

- (RNCryptor *)initWithConfiguration:(RNCryptorConfiguration)configuration
{
  self = [super init];
  if (self)
  {
    configuration_ = configuration;
  }
  return self;
}

+ (RNCryptorConfiguration)AES128Configuration
{
  RNCryptorConfiguration configuration = {
      .algorithm = kCCAlgorithmAES128,
      .keySize = kCCKeySizeAES128,
      .blockSize = kCCBlockSizeAES128,
      .IVSize = kCCBlockSizeAES128,
      .saltSize = 8,
      .PBKDFRounds = 10000, // ~80ms on an iPhone 4
      .HMACAlgorithm = kCCHmacAlgSHA256,
      .HMACLength = CC_SHA1_DIGEST_LENGTH,
  };
  return configuration;
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
      derivedKey = [NSMutableData dataWithLength:self.configuration.keySize];

  int
      result = CCKeyDerivationPBKDF(kCCPBKDF2,            // algorithm
                                    password.UTF8String,  // password
                                    password.length,  // passwordLength
                                    salt.bytes,           // salt
                                    salt.length,          // saltLen
                                    kCCPRFHmacAlgSHA1,    // PRF
                                    self.configuration.PBKDFRounds,         // rounds
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
    NSInteger wroteLength = [output write:[outData bytes] maxLength:[outData length]];
    if (wroteLength < 0)
    {
      *error = [output streamError];
    }

    return (wroteLength >= 0);
  }
  return YES;
}

- (BOOL)performOperation:(CCOperation)operation
              fromStream:(NSInputStream *)input
            readCallback:(RNCryptorReadCallback)readBlock
                toStream:(NSOutputStream *)output
           writeCallback:(RNCryptorWriteCallback)writeBlock
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
                                  self.configuration.algorithm,            // algorithm
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

  const NSUInteger kBufferSize = 1024;  // FIXME: Adapt to footer size
  NSMutableData *readBuffer = [NSMutableData data];

  // Read ahead
  NSMutableData *readAheadBuffer = [NSMutableData dataWithLength:kBufferSize];   // FIXME: Pull out duplicate below?
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
      stop = YES;
      *error = [input streamError];
      CCCryptorRelease(cryptor);
      return NO;
    }

    // Not at end (read-ahead has a full block). Read another block.
    if ([input streamStatus] != NSStreamStatusAtEnd)
    {
      readBuffer = readAheadBuffer;
      readAheadBuffer = [NSMutableData dataWithLength:kBufferSize];
      length = [input read:[readAheadBuffer mutableBytes] maxLength:kBufferSize];
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
      if (footer)
      {
        *footer = [readBuffer subdataWithRange:NSMakeRange([readBuffer length] - footerSize - 1, footerSize)];
        [readBuffer setLength:[readBuffer length] - footerSize];
      }
    }

    [outData setLength:CCCryptorGetOutputLength(cryptor, [readBuffer length], true)];
    cryptorStatus = CCCryptorUpdate(cryptor,       // cryptor
                                    readBuffer.bytes,      // dataIn
                                    readBuffer.length,     // dataInLength (verified > 0 above)
                                    outData.mutableBytes,      // dataOut
                                    outData.length, // dataOutAvailable
                                    &dataOutMoved);   // dataOutMoved
    if (![self processResult:cryptorStatus data:outData length:dataOutMoved output:output error:error])
    {
      CCCryptorRelease(cryptor);
      return NO;
    }
  }

  [outData setLength:CCCryptorGetOutputLength(cryptor, kBufferSize, true)];

   // Write the final block
   cryptorStatus = CCCryptorFinal(cryptor,        // cryptor
                                  outData.mutableBytes,       // dataOut
                                  outData.length,  // dataOutAvailable
                                  &dataOutMoved);    // dataOutMoved
  if (![self processResult:cryptorStatus data:outData length:dataOutMoved output:output error:error])
   {
     CCCryptorRelease(cryptor);
     return NO;
   }

   CCCryptorRelease(cryptor);
   return YES;
}

//- (BOOL)encryptFromStream:(NSInputStream *)input
//                readCallback:(RNCryptorReadCallback)readBlock
//                  toStream:(NSOutputStream *)output
//               writeCallback:(RNCryptorWriteCallback)writeBlock
//           encryptionKey:(NSData *)encryptionKey
//                      IV:(NSData *)IV
//                   error:(NSError **)error;
//{
//  return [self performOperation:kCCEncrypt fromStream:input readCallback:readBlock toStream:output writeCallback:writeBlock encryptionKey:encryptionKey IV:IV error:error];
//}
//
//- (BOOL)decryptWithInput:(id<RNCryptorInput>)input output:(id<RNCryptorOutput>)output encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV error:(NSError **)error
//{
//  return [self performOperation:kCCDecrypt input:input output:output encryptionKey:encryptionKey IV:IV error:error];
//}

@end
