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
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
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

//static const NSUInteger kMaxReadSize = 1024;

NSString *const kRNCryptorErrorDomain = @"net.robnapier.RNCryptManager";

@interface NSOutputStream (Data)
- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error;
@end

@implementation NSOutputStream (Data)
- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error
{
  // Writing 0 bytes will close the output stream.
  // This is an undocumented side-effect. radar://9930518
  if (data.length > 0)
  {
    NSInteger bytesWritten = [self write:data.bytes
                               maxLength:data.length];
    if (bytesWritten != data.length)
    {
      if (error)
      {
        *error = [self streamError];
      }
      return NO;
    }
  }
  return YES;
}

@end

@interface NSInputStream (Data)
- (BOOL)_RNGetData:(NSData **)data
         maxLength:(NSUInteger)maxLength
             error:(NSError **)error;
@end

@implementation NSInputStream (Data)

- (BOOL)_RNGetData:(NSData **)data
         maxLength:(NSUInteger)maxLength
             error:(NSError **)error
{

  NSMutableData *buffer = [NSMutableData dataWithLength:maxLength];
  if ([self read:buffer.mutableBytes maxLength:maxLength] < 0)
  {
    if (error)
    {
      *error = [self streamError];
      return NO;
    }
  }

  *data = buffer;
  return YES;
}

@end

@interface RNCryptor ()
@property (nonatomic, readonly, assign) RNCryptorConfiguration configuration;

@end

@implementation RNCryptor
@synthesize configuration = configuration_;


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
      .readBlockSize = 1024,
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

- (NSData *)AESKeyForPassword:(NSString *)password
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

- (BOOL)processResult:(CCCryptorStatus)result
                bytes:(uint8_t *)bytes
               length:(size_t)length
             toStream:(NSOutputStream *)outStream
                error:(NSError **)error
{

  if (result != kCCSuccess)
  {
    if (error)
    {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain
                                   code:result
                               userInfo:nil];
    }
    // Don't assert here. It could just be a bad password
    NSLog(@"Could not process data: %d", result);
    return NO;
  }

  if (length > 0)
  {
    if ([outStream write:bytes maxLength:length] != length)
    {
      if (error)
      {
        *error = [outStream streamError];
      }
      return NO;
    }
  }
  return YES;
}

- (BOOL)applyOperation:(CCOperation)operation
            fromStream:(NSInputStream *)inStream
              toStream:(NSOutputStream *)outStream
              password:(NSString *)password
                 error:(NSError **)error
{

  NSAssert([inStream streamStatus] != NSStreamStatusNotOpen,
  @"fromStream must be open");
  NSAssert([outStream streamStatus] != NSStreamStatusNotOpen,
  @"toStream must be open");
  NSAssert([password length] > 0,
  @"Can't proceed with no password");

  // Generate the IV and salt, or read them from the stream
  NSData *iv;
  NSData *salt;
  switch (operation)
  {
    case kCCEncrypt:
      // Generate a random IV for this file.
      iv = [self randomDataOfLength:self.configuration.IVSize];
      salt = [self randomDataOfLength:self.configuration.saltSize];

      if (![outStream _RNWriteData:iv error:error] ||
          ![outStream _RNWriteData:salt error:error])
      {
        return NO;
      }
      break;
    case kCCDecrypt:
      // Read the IV and salt from the encrypted file
      if (![inStream _RNGetData:&iv
                      maxLength:self.configuration.IVSize
                          error:error] ||
          ![inStream _RNGetData:&salt
                      maxLength:self.configuration.saltSize
                          error:error])
      {
        return NO;
      }
      break;
    default:
      NSAssert(NO, @"Unknown operation: %d", operation);
      break;
  }

  NSData *key = [self AESKeyForPassword:password salt:salt];

  // Create the cryptor
  CCCryptorRef cryptor = NULL;
  CCCryptorStatus result;
  result = CCCryptorCreate(operation,             // operation
                           self.configuration.algorithm,            // algorithm
                           kCCOptionPKCS7Padding, // options
                           key.bytes,             // key
                           key.length,            // key length
                           iv.bytes,              // IV
                           &cryptor);             // OUT cryptorRef

  if (result != kCCSuccess || cryptor == NULL)
  {
    if (error)
    {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain
                                   code:result
                               userInfo:nil];
    }
    NSAssert(NO, @"Could not create cryptor: %d", result);
    return NO;
  }

  // Calculate the buffer size and create the buffers.
  // The MAX() check isn't really necessary, but is a safety in 
  // case RNCRYPTMANAGER_USE_SAME_BUFFER is enabled, since both
  // buffers will be the same. This just guarantees the the read
  // buffer will always be large enough, even during decryption.
  const size_t readBlockSize = self.configuration.readBlockSize;
  size_t dstBufferSize = MAX(CCCryptorGetOutputLength(cryptor, // cryptor
                                                      readBlockSize, // input length
                                                      true), // final
  readBlockSize);

  NSMutableData *dstData = [NSMutableData dataWithLength:dstBufferSize];

  NSMutableData *
#if RNCRYPTOR_USE_SAME_BUFFER
  srcData = dstData;
#else
      // See explanation at top of file
      srcData = [NSMutableData dataWithLength:readBlockSize];
#endif

  uint8_t *srcBytes = srcData.mutableBytes;
  uint8_t *dstBytes = dstData.mutableBytes;

  // Read and write the data in blocks
  ssize_t srcLength;
  size_t dstLength = 0;

  while ((srcLength = [inStream read:srcBytes maxLength:readBlockSize]) > 0)
  {
    result = CCCryptorUpdate(cryptor,       // cryptor
                             srcBytes,      // dataIn
                             (size_t)srcLength,     // dataInLength (verified > 0 above)
                             dstBytes,      // dataOut
                             dstBufferSize, // dataOutAvailable
                             &dstLength);   // dataOutMoved

    if (![self processResult:result
                       bytes:dstBytes
                      length:dstLength
                    toStream:outStream
                       error:error])
    {
      CCCryptorRelease(cryptor);
      return NO;
    }
  }
  if (srcLength != 0)
  {
    if (error)
    {
      *error = [inStream streamError];
      return NO;
    }
  }

  // Write the final block
  result = CCCryptorFinal(cryptor,        // cryptor
                          dstBytes,       // dataOut
                          dstBufferSize,  // dataOutAvailable
                          &dstLength);    // dataOutMoved
  if (![self processResult:result
                     bytes:dstBytes
                    length:dstLength
                  toStream:outStream
                     error:error])
  {
    CCCryptorRelease(cryptor);
    return NO;
  }

  CCCryptorRelease(cryptor);
  return YES;
}

- (BOOL)encryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
                 password:(NSString *)password
                    error:(NSError **)error
{
  return [self applyOperation:kCCEncrypt
                   fromStream:fromStream
                     toStream:toStream
                     password:password
                        error:error];
}

- (BOOL)decryptFromStream:(NSInputStream *)fromStream
                 toStream:(NSOutputStream *)toStream
                 password:(NSString *)password
                    error:(NSError **)error
{
  return [self applyOperation:kCCDecrypt
                   fromStream:fromStream
                     toStream:toStream
                     password:password
                        error:error];
}

//- (NSData *)encryptedDataForData:(NSData *)data
//                        password:(NSString *)password
//                              IV:(NSData **)IV
//                            salt:(NSData **)salt
//                           error:(NSError **)error
//{
//  NSAssert(IV, @"IV must not be NULL");
//  NSAssert(salt, @"salt must not be NULL");
//
//  *IV = [self randomDataOfLength:self.configuration.IVSize];
//  *salt = [self randomDataOfLength:self.configuration.saltSize];
//
//  NSData *key = [self AESKeyForPassword:password salt:*salt];
//
//  size_t outLength;
//  NSMutableData *
//      cipherData = [NSMutableData dataWithLength:data.length + self.configuration.blockSize];
//
//  CCCryptorStatus
//      result = CCCrypt(kCCEncrypt, // operation
//                       self.configuration.algorithm, // Algorithm
//                       kCCOptionPKCS7Padding, // options
//                       key.bytes, // key
//                       key.length, // key length
//                       (*IV).bytes,// iv
//                       data.bytes, // dataIn
//                       data.length, // dataInLength,
//                       cipherData.mutableBytes, // dataOut
//                       cipherData.length, // dataOutAvailable
//                       &outLength); // dataOutMoved
//
//  if (result == kCCSuccess)
//  {
//    cipherData.length = outLength;
//  }
//  else
//  {
//    if (error)
//    {
//      *error = [NSError errorWithDomain:kRNCryptorErrorDomain
//                                   code:result
//                               userInfo:nil];
//    }
//    return nil;
//  }
//
//  return cipherData;
//}
//
//- (NSData *)decryptedDataForData:(NSData *)data
//                        password:(NSString *)password
//                              IV:(NSData *)IV
//                            salt:(NSData *)salt
//                           error:(NSError **)error
//{
//
//  NSData *key = [self AESKeyForPassword:password salt:salt];
//
//  size_t outLength;
//  NSMutableData *
//      decryptedData = [NSMutableData dataWithLength:data.length];
//  CCCryptorStatus
//      result = CCCrypt(kCCDecrypt, // operation
//                       self.configuration.algorithm, // Algorithm
//                       kCCOptionPKCS7Padding, // options
//                       key.bytes, // key
//                       key.length, // key length
//                       IV.bytes,// iv
//                       data.bytes, // dataIn
//                       data.length, // dataInLength,
//                       decryptedData.mutableBytes, // dataOut
//                       decryptedData.length, // dataOutAvailable
//                       &outLength); // dataOutMoved
//
//  if (result == kCCSuccess)
//  {
//    [decryptedData setLength:outLength];
//  }
//  else
//  {
//    if (result != kCCSuccess)
//    {
//      if (error)
//      {
//        *error = [NSError
//            errorWithDomain:kRNCryptorErrorDomain
//                       code:result
//                   userInfo:nil];
//      }
//      return nil;
//    }
//  }
//
//  return decryptedData;
//}


@end
