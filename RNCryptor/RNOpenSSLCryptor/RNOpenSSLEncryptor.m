//
//  RNOpenSSLEncryptor
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

// For aes-128:
//
// key = MD5(password + salt)
// IV = MD5(Key + password + salt)

//
// For aes-256:
//
// Hash0 = ''
// Hash1 = MD5(Hash0 + Password + Salt)
// Hash2 = MD5(Hash1 + Password + Salt)
// Hash3 = MD5(Hash2 + Password + Salt)
// Hash4 = MD5(Hash3 + Password + Salt)
//
// Key = Hash1 + Hash2
// IV = Hash3 + Hash4
//

// File Format:
//
// |Salted___|<salt>|<ciphertext>|

#import "RNOpenSSLEncryptor.h"
#import "RNCryptor+Private.h"
#import "RNCryptorEngine.h"
#import "RNOpenSSLCryptor.h"

@interface RNOpenSSLEncryptor ()
@property (nonatomic, readwrite, strong) NSData *encryptionSalt;
@end

@implementation RNOpenSSLEncryptor
@synthesize encryptionSalt = _encryptionSalt;

+ (NSData *)encryptData:(NSData *)data withSettings:(RNCryptorSettings)settings encryptionKey:(NSData *)encryptionKey IV:(NSData *)IV error:(NSError **)error
{
    RNEncryptor *cryptor = [[self alloc] initWithSettings:settings encryptionKey:encryptionKey IV:IV handler:^(RNCryptor *c, NSData *d) {}];
    return [self synchronousResultForCryptor:cryptor data:data error:error];
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)settings encryptionKey:(NSData *)encryptionKey HMACKey:(NSData *)HMACKey handler:(RNCryptorHandler)handler
{
  NSAssert(NO, @"%s -- Cannot be used in OpenSSL mode. An IV or password is required", __func__);
  return nil;
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings encryptionKey:(NSData *)anEncryptionKey IV:(NSData *)anIV handler:(RNCryptorHandler)aHandler
{
  self = [super initWithHandler:aHandler];
  if (self) {
    NSError *error = nil;
    self.engine = [[RNCryptorEngine alloc] initWithOperation:kCCEncrypt
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
  }

  return self;
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings password:(NSString *)aPassword handler:(RNCryptorHandler)aHandler
{
  NSParameterAssert(aPassword != nil);

  NSData *encryptionSalt = [[self class] randomDataOfLength:theSettings.keySettings.saltSize];
  NSData *encryptionKey = RNOpenSSLCryptorGetKey(aPassword, encryptionSalt, theSettings.keySettings);
  NSData *IV = RNOpenSSLCryptorGetIV(encryptionKey, aPassword, encryptionSalt, theSettings.keySettings);
  self = [self initWithSettings:theSettings
                  encryptionKey:encryptionKey
                             IV:IV
                        handler:aHandler];
  if (self) {
    self.options |= kRNCryptorOptionHasPassword;
    self.encryptionSalt = encryptionSalt;
  }
  return self;
}

- (NSData *)header
{
    NSMutableData *headerData = [NSMutableData data];
    if (kRNCryptorOptionHasPassword == (self.options & kRNCryptorOptionHasPassword)) {
        [headerData appendData:[kRNCryptorOpenSSLSaltedString dataUsingEncoding:NSUTF8StringEncoding]];
        [headerData appendData:self.encryptionSalt];
    }
  return headerData;
}

@end