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

//// For aes-128:
////
//// key = MD5(password + salt)
//// IV = MD5(Key + password + salt)
//
////
//// For aes-256:
////
//// Hash0 = ''
//// Hash1 = MD5(Hash0 + Password + Salt)
//// Hash2 = MD5(Hash1 + Password + Salt)
//// Hash3 = MD5(Hash2 + Password + Salt)
//// Hash4 = MD5(Hash3 + Password + Salt)
////
//// Key = Hash1 + Hash2
//// IV = Hash3 + Hash4
////
//
//// File Format:
////
//// |Salted___|<salt>|<ciphertext>|

#import "RNOpenSSLEncryptor.h"
#import "RNCryptor+Private.h"
#import "RNCryptorEngine.h"

const NSUInteger kSaltSize = 8;
NSString *const kSaltedString = @"Salted__";

@interface RNOpenSSLEncryptor ()
@property (nonatomic, readwrite, strong) NSData *encryptionSalt;
@end

@implementation RNOpenSSLEncryptor

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)settings encryptionKey:(NSData *)encryptionKey HMACKey:(NSData *)HMACKey handler:(RNCryptorHandler)handler
{
  NSAssert(NO, @"%s -- Cannot be used in OpenSSL mode. An IV or password is required", __func__);
  return nil;
}

- (RNEncryptor *)initWithSettings:(RNCryptorSettings)theSettings encryptionKey:(NSData *)anEncryptionKey IV:(NSData *)anIV handler:(RNCryptorHandler)aHandler
{
  self = [super initWithHandler:aHandler];
  if (self) {
    NSError *error;
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
  NSData *encryptionKey = [[self class] keyForPassword:aPassword withSalt:encryptionSalt andSettings:theSettings.keySettings];

  self = [self initWithSettings:theSettings
                  encryptionKey:encryptionKey
                             IV:[[self class] IVForKey:encryptionKey password:aPassword salt:encryptionSalt]
      handler:aHandler];
  if (self) {
    self.options |= kRNCryptorOptionHasPassword;
    self.encryptionSalt = encryptionSalt;
  }
  return self;
}

+ (NSData *)hashForHash:(NSData *)hash passwordSalt:(NSData *)passwordSalt
{
  unsigned char md[CC_MD5_DIGEST_LENGTH];

  NSMutableData *hashMaterial = [NSMutableData dataWithData:hash];
  [hashMaterial appendData:passwordSalt];
  CC_MD5([hashMaterial bytes], [hashMaterial length], md);

  return [NSData dataWithBytes:md length:sizeof(md)];
}

+ (NSData *)keyForPassword:(NSString *)password withSalt:(NSData *)salt andSettings:(RNCryptorKeyDerivationSettings)keySettings
{
  // FIXME: This is all very inefficient; we repeat ourselves in IVForKey:...

  // Hash0 = ''
  // Hash1 = MD5(Hash0 + Password + Salt)
  // Hash2 = MD5(Hash1 + Password + Salt)
  // Hash3 = MD5(Hash2 + Password + Salt)
  // Hash4 = MD5(Hash3 + Password + Salt)
  //
  // Key = Hash1 + Hash2
  // IV = Hash3 + Hash4

  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [passwordSalt appendData:salt];

  NSData *hash1 = [self hashForHash:nil passwordSalt:passwordSalt];
  NSData *hash2 = [self hashForHash:hash1 passwordSalt:passwordSalt];

  NSMutableData *key = [hash1 mutableCopy];
  [key appendData:hash2];

  return key;
}

+ (NSData *)IVForKey:(NSData *)key password:(NSString *)password salt:(NSData *)salt
{
  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [passwordSalt appendData:salt];

  NSData *hash1 = [self hashForHash:nil passwordSalt:passwordSalt];
  NSData *hash2 = [self hashForHash:hash1 passwordSalt:passwordSalt];
  NSData *hash3 = [self hashForHash:hash2 passwordSalt:passwordSalt];
  NSData *hash4 = [self hashForHash:hash3 passwordSalt:passwordSalt];

  NSMutableData *IV = [hash3 mutableCopy];
  [IV appendData:hash4];

  return IV;
}

- (NSData *)header
{
  NSMutableData *headerData = [[kSaltedString dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [headerData appendData:self.encryptionSalt];
  return headerData;
}

@end