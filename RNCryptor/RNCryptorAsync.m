//
//  RNCryptorAsync
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


#import "RNCryptorAsync.h"

//@interface RNCryptorAsync ()
//@property (nonatomic, readwrite, assign) CCOperation operation;
//@property (nonatomic, readonly) NSMutableData *outData;
//@property (nonatomic, readwrite, assign) CCCryptorRef cryptor;
//@property (nonatomic, readwrite, assign) CCHmacContext HMACContext;
//@property (nonatomic, readonly) NSMutableData *readBuffer;
//@property (nonatomic, readwrite, copy) RNCryptorHandler handler;
//@property (nonatomic, readwrite, copy) RNCryptorHandler completion;
//@property (nonatomic, readwrite, assign) dispatch_queue_t queue;
//@end
//
@implementation RNCryptorAsync
//@synthesize cryptor = _cryptor;
//@synthesize outData = __outData;
//@synthesize handler = _handler;
//@synthesize completion = _completion;
//@synthesize queue = _queue;
//@synthesize HMACContext = _HMACContext;
//@synthesize readBuffer = __readBuffer;
//@synthesize operation = _operation;
//
//
//- (RNCryptorAsync *)initWithSettings:(RNCryptorSettings)theSettings operation:(CCOperation)anOperation encryptionKey:(NSData *)anEncryptionKey HMACKey:(NSData *)anHMACKey handler:(RNCryptorHandler)aHandler completion:(RNCryptorHandler)aCompletion
//{
//  self = [super init];
//  if (self) {
//    _operation = anOperation;
//
//    if (_operation == kCCEncrypt) {
//      NSData *IV = [[self class] randomDataOfLength:theSettings.IVSize];
//      __outData = [IV mutableCopy];
//    }
//
//    CCCryptorStatus
//        cryptorStatus = CCCryptorCreateWithMode(anOperation,
//                                                theSettings.mode,
//                                                theSettings.algorithm,
//                                                theSettings.padding,
//                                                IV.bytes,
//                                                anEncryptionKey.bytes,
//                                                anEncryptionKey.length,
//                                                NULL, // tweak
//                                                0, // tweakLength
//                                                0, // numRounds (0=default)
//                                                theSettings.modeOptions,
//                                                &_cryptor);
//
//    if (cryptorStatus != kCCSuccess || _cryptor == NULL) {
//      self = nil;
//      NSAssert(NO, @"Could not create cryptor: %d", cryptorStatus);
//      return nil;
//    }
//
//    if (anHMACKey) {
//      CCHmacInit(&_HMACContext, theSettings.HMACAlgorithm, anHMACKey.bytes, anHMACKey.length);
//    }
//
//    __readBuffer = [NSMutableData data];
//    _handler = [aHandler copy];
//    _completion = [aCompletion copy];
//    _queue = dispatch_queue_create("net.robnapier.rncryptor", DISPATCH_QUEUE_SERIAL);
//  }
//
//  return self;
//}
//
//- (RNCryptorAsync *)initWithSettings:(RNCryptorSettings)theSettings operation:(CCOperation)anOperation password:(NSString *)aPassword handler:(RNCryptorHandler)aHandler completion:(RNCryptorHandler)aCompletion
//{
//  NSParameterAssert(aPassword != nil);
//
//  NSData *encryptionKeySalt = [[self class] randomDataOfLength:theSettings.keySettings.saltSize];
//  NSData *encryptionKey = [self keyForPassword:aPassword withSalt:encryptionKeySalt andSettings:theSettings.keySettings];
//
//  NSData *HMACKeySalt = [[self class] randomDataOfLength:theSettings.HMACKeySettings.saltSize];
//  NSData *HMACKey = [self keyForPassword:aPassword withSalt:HMACKeySalt andSettings:theSettings.HMACKeySettings];
//
//  uint8_t header[2] = {1, 0};
//  NSMutableData *headerData = [NSMutableData dataWithBytes:header length:sizeof(header)];
//  [headerData appendData:encryptionKeySalt];
//  [headerData appendData:HMACKeySalt];
//
//  self = [self initWithSettings:theSettings
//                      operation:anOperation
//                  encryptionKey:encryptionKey
//                        HMACKey:HMACKey
//                        handler:aHandler
//                     completion:aCompletion];
//  if (self)
//  {
//    // Prepend our header
//    [headerData appendData:__outData];
//    __outData = headerData;
//  }
//  return self;
//}
//
//- (void)dealloc {
//  if (_cryptor) {
//    CCCryptorRelease(_cryptor);
//    _cryptor = NULL;
//  }
//  if (_queue) {
//    dispatch_release(_queue);
//    _queue = NULL;
//  }
//}
//
//- (NSData *)keyForPassword:(NSString *)password withSalt:(NSData *)salt andSettings:(RNCryptorKeyDerivationSettings)keySettings
//{
//  NSMutableData *derivedKey = [NSMutableData dataWithLength:keySettings.keySize];
//
//  int result = CCKeyDerivationPBKDF(keySettings.PBKDFAlgorithm,              // algorithm
//                                    password.UTF8String,                // password
//                                    password.length,                    // passwordLength
//                                    salt.bytes,                         // salt
//                                    salt.length,                        // saltLen
//                                    keySettings.PRF,                    // PRF
//                                    keySettings.rounds,                 // rounds
//                                    derivedKey.mutableBytes,            // derivedKey
//                                    derivedKey.length);                 // derivedKeyLen
//
//  // Do not log password here
//  NSAssert(result == kCCSuccess, @"Unable to create AES key for password: %d", result);
//
//  return derivedKey;
//}
//
//- (void)addData:(NSData *)data
//{
//
//}

+ (NSData *)keyForPassword:(NSString *)password withSalt:(NSData *)salt andSettings:(RNCryptorKeyDerivationSettings)keySettings
{
  NSMutableData *derivedKey = [NSMutableData dataWithLength:keySettings.keySize];

  int result = CCKeyDerivationPBKDF(keySettings.PBKDFAlgorithm,              // algorithm
                                    password.UTF8String,                // password
                                    password.length,                    // passwordLength
                                    salt.bytes,                         // salt
                                    salt.length,                        // saltLen
                                    keySettings.PRF,                    // PRF
                                    keySettings.rounds,                 // rounds
                                    derivedKey.mutableBytes,            // derivedKey
                                    derivedKey.length);                 // derivedKeyLen

  // Do not log password here
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

@end