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

//- (BOOL)processResult:(CCCryptorStatus)result
//                bytes:(uint8_t *)bytes
//               length:(size_t)length
//             toStream:(NSOutputStream *)outStream
//                error:(NSError **)error
//{
//
//  if (result != kCCSuccess)
//  {
//    if (error)
//    {
//      *error = [NSError errorWithDomain:kRNCryptorErrorDomain
//                                   code:result
//                               userInfo:nil];
//    }
//    // Don't assert here. It could just be a bad password
//    NSLog(@"Could not process data: %d", result);
//    return NO;
//  }
//
//  if (length > 0)
//  {
//    if ([outStream write:bytes maxLength:length] != length)
//    {
//      if (error)
//      {
//        *error = [outStream streamError];
//      }
//      return NO;
//    }
//  }
//  return YES;
//}
//
//- (BOOL)applyOperation:(CCOperation)operation
//            fromStream:(NSInputStream *)inStream
//              toStream:(NSOutputStream *)outStream
//         encryptionKey:(NSData *)key
//                    IV:(NSData *)iv
//               HMACKey:(NSData *)HMACKey
//                 error:(NSError **)error
//{
//  // FIXME: Implement HMAC checking
//  NSAssert([inStream streamStatus] != NSStreamStatusNotOpen, @"fromStream must be open");
//  NSAssert([outStream streamStatus] != NSStreamStatusNotOpen, @"toStream must be open");
//
//  // Create the cryptor
//  CCCryptorRef cryptor = NULL;
//  CCCryptorStatus result;
//  result = CCCryptorCreate(operation,             // operation
//                           self.configuration.algorithm,            // algorithm
//                           kCCOptionPKCS7Padding, // options
//                           key.bytes,             // key
//                           key.length,            // key length
//                           iv.bytes,              // IV
//                           &cryptor);             // OUT cryptorRef
//
//  if (result != kCCSuccess || cryptor == NULL)
//  {
//    if (error)
//    {
//      *error = [NSError errorWithDomain:kRNCryptorErrorDomain
//                                   code:result
//                               userInfo:nil];
//    }
//    NSAssert(NO, @"Could not create cryptor: %d", result);
//    return NO;
//  }
//
//  // Calculate the buffer size and create the buffers.
//  // The MAX() check isn't really necessary, but is a safety in
//  // case RNCRYPTOR_USE_SAME_BUFFER is enabled, since both
//  // buffers will be the same. This just guarantees the the read
//  // buffer will always be large enough, even during decryption.
//  const size_t readBlockSize = self.configuration.readBlockSize;
//  size_t dstBufferSize = MAX(CCCryptorGetOutputLength(cryptor, // cryptor
//                                                      readBlockSize, // input length
//                                                      true), // final
//  readBlockSize);
//
//  NSMutableData *dstData = [NSMutableData dataWithLength:dstBufferSize];
//
//  NSMutableData *
//#if RNCRYPTOR_USE_SAME_BUFFER
//  srcData = dstData;
//#else
//      // See explanation at top of file
//      srcData = [NSMutableData dataWithLength:readBlockSize];
//#endif
//
//  uint8_t *srcBytes = srcData.mutableBytes;
//  uint8_t *dstBytes = dstData.mutableBytes;
//
//  // Read and write the data in blocks
//  ssize_t srcLength;
//  size_t dstLength = 0;
//
//  while ((srcLength = [inStream read:srcBytes maxLength:readBlockSize]) > 0)
//  {
//    result = CCCryptorUpdate(cryptor,       // cryptor
//                             srcBytes,      // dataIn
//                             (size_t)srcLength,     // dataInLength (verified > 0 above)
//                             dstBytes,      // dataOut
//                             dstBufferSize, // dataOutAvailable
//                             &dstLength);   // dataOutMoved
//
//    if (![self processResult:result bytes:dstBytes length:dstLength toStream:outStream error:error])
//    {
//      CCCryptorRelease(cryptor);
//      return NO;
//    }
//  }
//  if (srcLength != 0)
//  {
//    if (error)
//    {
//      *error = [inStream streamError];
//      return NO;
//    }
//  }
//
//  // Write the final block
//  result = CCCryptorFinal(cryptor,        // cryptor
//                          dstBytes,       // dataOut
//                          dstBufferSize,  // dataOutAvailable
//                          &dstLength);    // dataOutMoved
//  if (![self processResult:result
//                     bytes:dstBytes
//                    length:dstLength
//                  toStream:outStream
//                     error:error])
//  {
//    CCCryptorRelease(cryptor);
//    return NO;
//  }
//
//  CCCryptorRelease(cryptor);
//  return YES;
//}

//- (BOOL)processResult:(CCCryptorStatus)cryptorStatus
//                data:(NSMutableData *)outData
//               length:(size_t)length
//             writeBlock:(RNCryptorWriteBlock)writeBlock
//                error:(NSError **)error
//{
//  if (cryptorStatus != kCCSuccess)
//  {
//    if (error)
//    {
//      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
//    }
//    NSLog(@"[%s] Could not process data: %d", __PRETTY_FUNCTION__, cryptorStatus);
//    return NO;
//  }
//
//  if (length > 0)
//  {
//    [outData setLength:length];
//
//    if (! writeBlock(outData, error))
//    {
//      return NO;
//    }
//  }
//  return YES;
//}
//
//- (BOOL)performOperation:(CCOperation)operation readBlock:(RNCryptorReadBlock)readBlock writeBlock:(RNCryptorWriteBlock)writeBlock encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV HMACKey:(NSData *)HMACKey HMAC:(NSData **)HMAC error:(NSError **)error
//{
//// Create the cryptor
//  CCCryptorRef cryptor = NULL;
//  CCCryptorStatus cryptorStatus;
//  cryptorStatus = CCCryptorCreate(operation,             // operation
//                                  self.configuration.algorithm,            // algorithm
//                                  kCCOptionPKCS7Padding, // options
//                                  encryptionKey.bytes,             // key
//                                  encryptionKey.length,            // key length
//                                  IV.bytes,              // IV
//                                  &cryptor);             // OUT cryptorRef
//
//  if (cryptorStatus != kCCSuccess || cryptor == NULL)
//  {
//    if (error)
//    {
//      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
//    }
//    NSAssert(NO, @"Could not create cryptor: %d", cryptorStatus);
//    return NO;
//  }
//
//  NSData *inData;
//  BOOL stop = NO;
//  NSMutableData *outData = [NSMutableData data];
//  size_t dataOutMoved;
//
//  CCHmacContext HmacContext;
//  if (HMACKey)
//  {
//    CCHmacInit(&HmacContext, self.configuration.HMACAlgorithm, [HMACKey bytes], [HMACKey length]);
//  }
//
//  while (!stop)
//  {
//    BOOL readResult = readBlock(&inData, &stop, error);
//    if (! readResult)
//    {
//      CCCryptorRelease(cryptor);
//      return NO;
//    }
//
//    if (HMACKey && operation == kCCDecrypt)
//    {
//      CCHmacUpdate(&HmacContext, [inData bytes], [inData length]);
//    }
//
//    [outData setLength:CCCryptorGetOutputLength(cryptor, [inData length], true)];
//    cryptorStatus = CCCryptorUpdate(cryptor,       // cryptor
//                                    inData.bytes,      // dataIn
//                                    inData.length,     // dataInLength (verified > 0 above)
//                                    outData.mutableBytes,      // dataOut
//                                    outData.length, // dataOutAvailable
//                                    &dataOutMoved);   // dataOutMoved
//    if (![self processResult:cryptorStatus data:outData length:dataOutMoved writeBlock:writeBlock error:error])
//    {
//      CCCryptorRelease(cryptor);
//      return NO;
//    }
//
//    if (HMACKey && operation == kCCEncrypt)
//    {
//      CCHmacUpdate(&HmacContext, [outData bytes], [outData length]);
//    }
//  }
//
//  // Write the final block
//  cryptorStatus = CCCryptorFinal(cryptor,        // cryptor
//                                 outData.mutableBytes,       // dataOut
//                                 outData.length,  // dataOutAvailable
//                                 &dataOutMoved);    // dataOutMoved
//  if (![self processResult:cryptorStatus data:outData length:dataOutMoved writeBlock:writeBlock error:error])
//  {
//    CCCryptorRelease(cryptor);
//    return NO;
//  }
//
//  if (HMACKey && operation == kCCEncrypt)
//  {
//    CCHmacUpdate(&HmacContext, [outData bytes], [outData length]);
//  }
//
//  if (HMACKey)
//  {
//    *HMAC = [NSMutableData dataWithLength:self.configuration.HMACLength];
//    CCHmacFinal(&HmacContext, [(NSMutableData *)*HMAC mutableBytes]);
//  }
//
//  CCCryptorRelease(cryptor);
//  return YES;
//}
//
//- (BOOL)encryptWithReadBlock:(RNCryptorReadBlock)readBlock writeBlock:(RNCryptorWriteBlock)writeBlock encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV HMACKey:(NSData *)HMACKey HMAC:(NSData **)HMAC error:(NSError **)error
//{
//  return [self performOperation:kCCEncrypt readBlock:readBlock writeBlock:writeBlock encryptionKey:encryptionKey IV:IV HMACKey:HMACKey HMAC:HMAC error:error];
//}
//
//- (BOOL)decryptWithReadBlock:(RNCryptorReadBlock)readBlock writeBlock:(RNCryptorWriteBlock)writeBlock encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV HMACKey:(NSData *)HMACKey HMAC:(NSData **)HMAC error:(NSError **)error
//{
//  return [self performOperation:kCCDecrypt readBlock:readBlock writeBlock:writeBlock encryptionKey:encryptionKey IV:IV HMACKey:HMACKey HMAC:HMAC error:error];
//}
//
//- (RNCryptorReadBlock)readBlockForData:(NSData *)data
//{
//  return ^BOOL(NSData **readData, BOOL *stop, NSError **error) {
//    *readData = data;
//    *stop = YES;
//    return YES;
//  };
//}
//
//- (RNCryptorWriteBlock)writeBlockForData:(NSMutableData *)data
//{
//  return ^BOOL(NSData *encryptedData, NSError **error) {
//      [data appendData:encryptedData];
//      return YES;
//    };
//}

- (BOOL)processResult:(CCCryptorStatus)cryptorStatus
                data:(NSMutableData *)outData
               length:(size_t)length
             output:(id<RNCryptorOutputStream>)output
                error:(NSError **)error
{
  if (cryptorStatus != kCCSuccess)
  {
    if (error)
    {
      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:cryptorStatus userInfo:nil];
    }
    NSLog(@"[%s] Could not process data: %d", __PRETTY_FUNCTION__, cryptorStatus);
    return NO;
  }

  if (length > 0)
  {
    [outData setLength:length];

    if (! [output writeData:outData error:error])
    {
      return NO;
    }
  }
  return YES;
}

- (BOOL)performOperation:(CCOperation)operation input:(id<RNCryptorInputStream>)input output:(id<RNCryptorOutputStream>)output encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV error:(NSError **)error
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

   NSData *inData;
   BOOL stop = NO;
   NSMutableData *outData = [NSMutableData data];
   size_t dataOutMoved;

   while (!stop)
   {
     BOOL readResult = [input getData:&inData shouldStop:&stop error:error];
     if (! readResult)
     {
       CCCryptorRelease(cryptor);
       return NO;
     }

     [outData setLength:CCCryptorGetOutputLength(cryptor, [inData length], true)];
     cryptorStatus = CCCryptorUpdate(cryptor,       // cryptor
                                     inData.bytes,      // dataIn
                                     inData.length,     // dataInLength (verified > 0 above)
                                     outData.mutableBytes,      // dataOut
                                     outData.length, // dataOutAvailable
                                     &dataOutMoved);   // dataOutMoved
     if (![self processResult:cryptorStatus data:outData length:dataOutMoved output:output error:error])
     {
       CCCryptorRelease(cryptor);
       return NO;
     }
   }

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

- (BOOL)encryptWithInput:(id<RNCryptorInputStream>)input output:(id<RNCryptorOutputStream>)output encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV error:(NSError **)error
{
  return [self performOperation:kCCEncrypt input:input output:output encryptionKey:encryptionKey IV:IV error:error];
}

- (BOOL)decryptWithInput:(id<RNCryptorInputStream>)input output:(id<RNCryptorOutputStream>)output encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV error:(NSError **)error
{
  return [self performOperation:kCCDecrypt input:input output:output encryptionKey:encryptionKey IV:IV error:error];
}



//- (BOOL)encryptFromStream:(NSInputStream *)inStream toStream:(NSOutputStream *)outStream encryptionKey:(NSData *)key IV:(NSData *)iv HMACKey:(NSData *)HMACKey error:(NSError **)error
//{
//  return [self applyOperation:kCCEncrypt fromStream:inStream toStream:outStream encryptionKey:key IV:iv HMACKey:HMACKey error:error];
//}
//
//- (BOOL)decryptFromStream:(NSInputStream *)inStream
//                 toStream:(NSOutputStream *)outStream
//            encryptionKey:(NSData *)encryptionKey
//                       IV:(NSData *)IV
//                  HMACKey:(NSData *)HMACKey
//                    error:(NSError **)error
//{
//  return [self applyOperation:kCCDecrypt fromStream:inStream toStream:outStream encryptionKey:encryptionKey IV:IV HMACKey:HMACKey error:error];
//}
//
//- (BOOL)encryptFromStream:(NSInputStream *)inStream
//                 toStream:(NSOutputStream *)outStream
//                 password:(NSString *)password
//                    error:(NSError **)error
//{
//  // Generate a random IV and salts and write them to stream
//  NSData *iv = [self randomDataOfLength:self.configuration.IVSize];
//  NSData *encryptionSalt = [self randomDataOfLength:self.configuration.saltSize];
//  NSData *encryptionKey = [self keyForPassword:password salt:encryptionSalt];
//  NSData *HMACSalt = [self randomDataOfLength:self.configuration.saltSize];
//  NSData *HMACKey = [self keyForPassword:password salt:HMACSalt];
//
//  if (![outStream _RNWriteData:iv error:error] ||
//      ![outStream _RNWriteData:encryptionSalt error:error] ||
//      ![outStream _RNWriteData:HMACSalt error:error])
//  {
//    return NO;
//  }
//
//  return [self encryptFromStream:inStream toStream:outStream encryptionKey:encryptionKey IV:iv HMACKey:HMACKey error:error];
//}
//
//- (BOOL)decryptFromStream:(NSInputStream *)inStream
//                 toStream:(NSOutputStream *)outStream
//                 password:(NSString *)password
//                    error:(NSError **)error
//{
//  NSData *iv;
//  NSData *encryptionSalt;
//  NSData *HMACSalt;
//  // Read the IV and salts from the encrypted file
//  if (![inStream _RNGetData:&iv maxLength:self.configuration.IVSize error:error] ||
//      ![inStream _RNGetData:&encryptionSalt maxLength:self.configuration.saltSize error:error] ||
//      ![inStream _RNGetData:&HMACSalt maxLength:self.configuration.saltSize error:error])
//  {
//    return NO;
//  }
//
//  NSData *encryptionKey = [self keyForPassword:password salt:encryptionSalt];
//  NSData *HMACKey = [self keyForPassword:password salt:HMACSalt];
//
//  return [self decryptFromStream:inStream toStream:outStream encryptionKey:encryptionKey IV:iv HMACKey:HMACKey error:error];
//}

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
