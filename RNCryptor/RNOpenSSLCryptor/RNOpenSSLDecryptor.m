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
#import "RNCryptor+Private.h"
#import "RNCryptorEngine.h"
#import "RNOpenSSLCryptor.h"

@interface RNDecryptor (Private)
@property (nonatomic, readwrite, strong) NSMutableData *inData;
@property (nonatomic, readwrite, copy) NSData *encryptionKey;
@property (nonatomic, readwrite, copy) NSData *HMACKey;
@property (nonatomic, readwrite, copy) NSString *password;
@end

@interface RNOpenSSLDecryptor ()
@property (nonatomic, readwrite, assign) RNCryptorSettings settings;
@property (nonatomic, readwrite, copy) NSString *password;
@end

@implementation RNOpenSSLDecryptor
@synthesize password = _password;
@synthesize settings = _settings;

+ (NSData *)decryptData:(NSData *)data withSettings:(RNCryptorSettings)settings password:(NSString *)password error:(NSError **)error
{
  RNDecryptor *cryptor = [[self alloc] initWithSettings:settings password:password handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:data error:error];
}

+ (NSData *)decryptData:(NSData *)data withSettings:(RNCryptorSettings)settings encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV error:(NSError **)error
{
  RNDecryptor *cryptor = [[self alloc] initWithSettings:settings encryptionKey:encryptionKey IV:IV handler:^(RNCryptor *c, NSData *d) {}];
  return [self synchronousResultForCryptor:cryptor data:data error:error];
}

- (RNDecryptor *)initWithSettings:(RNCryptorSettings)theSettings encryptionKey:(NSData *)anEncryptionKey IV:(NSData *)anIV handler:(RNCryptorHandler)aHandler
{
  NSParameterAssert(anEncryptionKey != nil);

  self = [super initWithHandler:aHandler];
  if (self) {
    NSError *error = nil;
    self.engine = [[RNCryptorEngine alloc] initWithOperation:kCCDecrypt
                                                    settings:theSettings
                                                         key:anEncryptionKey
                                                          IV:anIV
                                                       error:&error];
    if (!self.engine) {
      [self cleanupAndNotifyWithError:error];
      self = nil;
      return nil;
    }
    self.HMACLength = 0;
    self.settings = theSettings;
  }

  return self;
}

- (RNDecryptor *)initWithSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword handler:(RNCryptorHandler)aHandler
{
  NSParameterAssert(aPassword != nil);

  self = [super initWithHandler:aHandler];
  if (self) {
    self.HMACLength = 0;
    self.password = aPassword;
    self.settings = theSettings;
  }

  return self;
}

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
  RNCryptorSettings settings = self.settings;
  if (data.length < [kRNCryptorOpenSSLSaltedString length] + settings.keySettings.saltSize) {
    return;
  }

  NSString *saltedPrefix = [[NSString alloc] initWithData:[data _RNConsumeToIndex:[kRNCryptorOpenSSLSaltedString length]] encoding:NSUTF8StringEncoding];
  if (![kRNCryptorOpenSSLSaltedString isEqualToString:saltedPrefix]) {
    [self cleanupAndNotifyWithError:[NSError errorWithDomain:kRNCryptorErrorDomain
                                                        code:kRNCryptorUnknownHeader
                                                    userInfo:[NSDictionary dictionaryWithObject:@"Unknown header" /* DNL */
                                                                                         forKey:NSLocalizedDescriptionKey]]];
  }

  NSData *salt = [data _RNConsumeToIndex:settings.keySettings.saltSize];
  NSData *key = RNOpenSSLCryptorGetKey(self.password, salt, settings.keySettings);
  NSData *IV = RNOpenSSLCryptorGetIV(key, self.password, salt, settings.keySettings);
  NSError *error = nil;

  self.engine = [[RNCryptorEngine alloc] initWithOperation:kCCDecrypt
                                                  settings:settings
                                                       key:key
                                                        IV:IV
                                                     error:&error];
  if (!self.engine) {
    [self cleanupAndNotifyWithError:error];
    return;
  }
}

@end