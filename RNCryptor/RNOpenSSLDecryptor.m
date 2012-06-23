//
//  RNOpenSSLDecryptor
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


#import "RNOpenSSLDecryptor.h"

@interface RNDecryptor (Private)
@property (nonatomic, readwrite, strong) NSMutableData *inData;
@property (nonatomic, readwrite, copy) NSData *encryptionKey;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@property (nonatomic, readwrite, copy) NSString *password;
@end

@interface RNOpenSSLDecryptor ()
@end

@implementation RNOpenSSLDecryptor

- (RNDecryptor *)initWithEncryptionKey:(NSData *)encryptionKey
                               HMACKey:(NSData *)HMACKey
                               handler:(RNCryptorHandler)handler
{
  NSAssert(NO, @"%s -- Cannot be used in OpenSSL mode. An IV or password is required", __func__);
  return nil;
}

- (RNDecryptor *)initWithPassword:(NSString *)password
                          handler:(RNCryptorHandler)handler
{
  NSAssert(NO, @"%s -- Cannot be used in OpenSSL mode. Settings are required", __func__);
  return nil;
}

+ (NSData *)decryptData:(NSData *)data withPassword:(NSString *)password error:(NSError **)error
{
  NSAssert(NO, @"%s -- Cannot be used in OpenSSL mode. Settings are required", __func__);
  return nil;

}

+ (NSData *)decryptData:(NSData *)data withEncryptionKey:(NSData *)encryptionKey HMACKey:(NSData *)HMACKey error:(NSError **)error
{
  NSAssert(NO, @"%s -- Cannot be used in OpenSSL mode. Settings are required", __func__);
  return nil;
}


- (void)consumeHeaderFromData:(NSMutableData *)data
{
  // HERE
  NSAssert(NO, @"Implement");
//  if (self.password) {
//    if (data.length < [kRNCryptorOpenSSLSaltedString length] + )
//  }
//
//  if (data.length < kPreambleSize) {
//    return;
//  }
//
//  RNCryptorSettings settings;
//  if (![self getSettings:&settings forPreamble:[data subdataWithRange:NSMakeRange(0, kPreambleSize)]]) {
//    [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
//                                                        code:kRNCryptorUnknownHeader
//                                                    userInfo:[NSDictionary dictionaryWithObject:@"Unknown header" /* DNL */
//                                                                                         forKey:NSLocalizedDescriptionKey]]];
//  }
//
//  NSUInteger headerSize = kPreambleSize + settings.IVSize;
//  if (self.options & kRNCryptorOptionHasPassword) {
//    headerSize += settings.keySettings.saltSize + settings.HMACKeySettings.saltSize;
//  }
//
//  if (data.length < headerSize) {
//    return;
//  }
//
//  [data _RNConsumeToIndex:kPreambleSize]; // Throw away the preamble
//
//  NSError *error;
//  if (self.password) {
//    NSAssert(!self.encryptionKey && !self.HMACKey, @"Both password and the key (%d) or HMACKey (%d) are set.", self.encryptionKey != nil, self.HMACKey != nil);
//
//    NSData *encryptionKeySalt = [data _RNConsumeToIndex:settings.keySettings.saltSize];
//    NSData *HMACKeySalt = [data _RNConsumeToIndex:settings.HMACKeySettings.saltSize];
//
//    self.encryptionKey = [[self class] keyForPassword:self.password salt:encryptionKeySalt settings:settings.keySettings];
//    self.HMACKey = [[self class] keyForPassword:self.password salt:HMACKeySalt settings:settings.HMACKeySettings];
//
//    self.password = nil;  // Don't need this anymore.
//  }
//
//  NSData *IV = [data _RNConsumeToIndex:settings.IVSize];
//
//  self.engine = [[RNCryptorEngine alloc] initWithOperation:kCCDecrypt settings:settings key:self.encryptionKey IV:IV error:&error];
//  self.encryptionKey = nil; // Don't need this anymore
//  if (!self.engine) {
//    [self cleanupAndNotifyWithError:error];
//    return;
//  }
//
//  if (self.HMACKey) {
//    CCHmacInit(&_HMACContext, settings.HMACAlgorithm, self.HMACKey.bytes, self.HMACKey.length);
//    self.HMACLength = settings.HMACLength;
//    self.HMACKey = nil; // Don't need this anymore
//  }
}

@end