////
////  RNOpenSSLCryptor
////
////  Copyright (c) 2012 Rob Napier
////
////  This code is licensed under the MIT License:
////
////  Permission is hereby granted, free of charge, to any person obtaining a
////  copy of this software and associated documentation files (the "Software"),
////  to deal in the Software without restriction, including without limitation
////  the rights to use, copy, modify, merge, publish, distribute, sublicense,
////  and/or sell copies of the Software, and to permit persons to whom the
////  Software is furnished to do so, subject to the following conditions:
////
////  The above copyright notice and this permission notice shall be included in
////  all copies or substantial portions of the Software.
////
////  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
////  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
////  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
////  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
////  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
////  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
////  DEALINGS IN THE SOFTWARE.
////


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
//

#import "RNOpenSSLCryptor.h"

NSString *const kRNCryptorOpenSSLSaltedString = @"Salted__";

static NSData *GetHashForHash(NSData *hash, NSData *passwordSalt) {
  unsigned char md[CC_MD5_DIGEST_LENGTH];

  NSMutableData *hashMaterial = [NSMutableData dataWithData:hash];
  [hashMaterial appendData:passwordSalt];
  CC_MD5([hashMaterial bytes], (CC_LONG)[hashMaterial length], md);

  return [NSData dataWithBytes:md length:sizeof(md)];
}


NSData *RNOpenSSLCryptorGetKey(NSString *password, NSData *salt, RNCryptorKeyDerivationSettings keySettings) {
  // FIXME: This is all very inefficient; we repeat ourselves in IVForKey:...

  NSMutableData *key;
  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [passwordSalt appendData:salt];

  if (keySettings.keySize != kCCKeySizeAES256) {
    // For aes-128:
    //
    // key = MD5(password + salt)
    // IV = MD5(Key + password + salt)
    unsigned char md[CC_MD5_DIGEST_LENGTH];
    CC_MD5([passwordSalt bytes], (CC_LONG)[passwordSalt length], md);
    key = [NSData dataWithBytes:md length:sizeof(md)];

  } else {
    // Hash0 = ''
    // Hash1 = MD5(Hash0 + Password + Salt)
    // Hash2 = MD5(Hash1 + Password + Salt)
    // Hash3 = MD5(Hash2 + Password + Salt)
    // Hash4 = MD5(Hash3 + Password + Salt)
    //
    // Key = Hash1 + Hash2
    // IV = Hash3 + Hash4

    NSData *hash1 = GetHashForHash(nil, passwordSalt);
    NSData *hash2 = GetHashForHash(hash1, passwordSalt);

    key = [hash1 mutableCopy];
    [key appendData:hash2];
  }
  return key;
}

NSData *RNOpenSSLCryptorGetIV(NSData *key, NSString *password, NSData *salt, RNCryptorKeyDerivationSettings keySettings) {

  NSMutableData *IV;
  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  [passwordSalt appendData:salt];

  if (keySettings.keySize != kCCKeySizeAES256) {
    // For aes-128:
    //
    // key = MD5(password + salt)
    // IV = MD5(Key + password + salt)
    IV = [GetHashForHash(key, passwordSalt) mutableCopy];

  } else {

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
    NSData *hash1 = GetHashForHash(nil, passwordSalt);
    NSData *hash2 = GetHashForHash(hash1, passwordSalt);
    NSData *hash3 = GetHashForHash(hash2, passwordSalt);
    NSData *hash4 = GetHashForHash(hash3, passwordSalt);

    IV = [hash3 mutableCopy];
    [IV appendData:hash4];
  }
  return IV;
}



//
//const NSUInteger kSaltSize = 8;
//NSString *const kSaltedString = @"Salted__";
//
//@interface NSInputStream (RNCryptor)
//- (BOOL)_RNGetData:(NSData **)data maxLength:(NSUInteger)maxLength error:(NSError **)error;
//@end
//
//@implementation NSInputStream (RNCryptor)
//- (BOOL)_RNGetData:(NSData **)data maxLength:(NSUInteger)maxLength error:(NSError **)error
//{
//  NSMutableData *buffer = [NSMutableData dataWithLength:maxLength];
//  if ([self read:buffer.mutableBytes maxLength:maxLength] < 0) {
//    if (error) {
//      *error = [self streamError];
//      return NO;
//    }
//  }
//
//  *data = buffer;
//  return YES;
//}
//@end
//
//@interface NSOutputStream (RNCryptor)
//- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error;
//@end
//
//@implementation NSOutputStream (RNCryptor)
//- (BOOL)_RNWriteData:(NSData *)data error:(NSError **)error
//{
//  // Writing 0 bytes will close the output stream.
//  // This is an undocumented side-effect. radar://9930518
//  if (data.length > 0) {
//    NSInteger bytesWritten = [self write:data.bytes
//                               maxLength:data.length];
//    if (bytesWritten != data.length) {
//      if (error) {
//        *error = [self streamError];
//      }
//      return NO;
//    }
//  }
//  return YES;
//}
//@end
//
//@interface RNOpenSSLCryptor ()
//@end
//
//@implementation RNOpenSSLCryptor
//+ (RNOpenSSLCryptor *)openSSLCryptor
//{
//  static dispatch_once_t once;
//  static id openSSLCryptor = nil;
//
//  dispatch_once(&once, ^{openSSLCryptor = [[self alloc] init];});
//  return openSSLCryptor;
//}
//
//- (NSData *)hashForHash:(NSData *)hash passwordSalt:(NSData *)passwordSalt
//{
//  unsigned char md[CC_MD5_DIGEST_LENGTH];
//
//  NSMutableData *hashMaterial = [NSMutableData dataWithData:hash];
//  [hashMaterial appendData:passwordSalt];
//  CC_MD5([hashMaterial bytes], [hashMaterial length], md);
//
//  return [NSData dataWithBytes:md length:sizeof(md)];
//}
//
//- (NSData *)keyForPassword:(NSString *)password salt:(NSData *)salt
//{
//  // FIXME: This is all very inefficient; we repeat ourselves in IVForKey:...
//
//  // Hash0 = ''
//  // Hash1 = MD5(Hash0 + Password + Salt)
//  // Hash2 = MD5(Hash1 + Password + Salt)
//  // Hash3 = MD5(Hash2 + Password + Salt)
//  // Hash4 = MD5(Hash3 + Password + Salt)
//  //
//  // Key = Hash1 + Hash2
//  // IV = Hash3 + Hash4
//
//  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
//  [passwordSalt appendData:salt];
//
//  NSData *hash1 = [self hashForHash:nil passwordSalt:passwordSalt];
//  NSData *hash2 = [self hashForHash:hash1 passwordSalt:passwordSalt];
//
//  NSMutableData *key = [hash1 mutableCopy];
//  [key appendData:hash2];
//
//  return key;
//
////  // key = MD5(password + salt)
////  unsigned char md[CC_MD5_DIGEST_LENGTH];
////  NSMutableData *keyMaterial = [NSMutableData dataWithData:[password dataUsingEncoding:NSUTF8StringEncoding]];
////  [keyMaterial appendData:salt];
////  CC_MD5([keyMaterial bytes], [keyMaterial length], md);
////  NSData *key = [NSData dataWithBytes:md length:sizeof(md)];
////  return key;
//}
//
//- (NSData *)IVForKey:(NSData *)key password:(NSString *)password salt:(NSData *)salt
//{
//  NSMutableData *passwordSalt = [[password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
//  [passwordSalt appendData:salt];
//
//  NSData *hash1 = [self hashForHash:nil passwordSalt:passwordSalt];
//  NSData *hash2 = [self hashForHash:hash1 passwordSalt:passwordSalt];
//  NSData *hash3 = [self hashForHash:hash2 passwordSalt:passwordSalt];
//  NSData *hash4 = [self hashForHash:hash3 passwordSalt:passwordSalt];
//
//  NSMutableData *IV = [hash3 mutableCopy];
//  [IV appendData:hash4];
//
//  return IV;
//
//
////  // IV = MD5(Key + password + salt)
////  unsigned char md[CC_MD5_DIGEST_LENGTH];
////  NSMutableData *IVMaterial = [NSMutableData dataWithData:key];
////  [IVMaterial appendData:[password dataUsingEncoding:NSUTF8StringEncoding]];
////  [IVMaterial appendData:salt];
////  CC_MD5([IVMaterial bytes], [IVMaterial length], md);
////  NSData *IV = [NSData dataWithBytes:md length:sizeof(md)];
////  return IV;
//}
//
//- (BOOL)decryptFromStream:(NSInputStream *)fromStream toStream:(NSOutputStream *)toStream password:(NSString *)password error:(NSError **)error
//{
//  NSData *salted;
//  NSData *encryptionKeySalt;
//
//  [fromStream open];
//
//  if (![fromStream _RNGetData:&salted maxLength:[kSaltedString length] error:error] ||
//      ![fromStream _RNGetData:&encryptionKeySalt maxLength:kSaltSize error:error]) {
//    return NO;
//  }
//
//  if (![[[NSString alloc] initWithData:salted encoding:NSUTF8StringEncoding] isEqualToString:kSaltedString]) {
//    if (error) {
//      *error = [NSError errorWithDomain:kRNCryptorErrorDomain code:kRNCryptorUnknownHeader
//                               userInfo:[NSDictionary dictionaryWithObject:NSLocalizedString(@"Could not find salt", @"Could not find salt") forKey:NSLocalizedDescriptionKey]];
//    }
//    return NO;
//  }
//
//  NSData *encryptionKey = [self keyForPassword:password salt:encryptionKeySalt];
//  NSData *IV = [self IVForKey:encryptionKey password:password salt:encryptionKeySalt];
//
//  RNCryptor *cryptor = [[RNCryptor alloc] initWithSettings:kRNCryptorOpenSSLSettings];
//
//  return [cryptor performOperation:kCCDecrypt fromStream:fromStream readCallback:nil toStream:toStream writeCallback:nil encryptionKey:encryptionKey IV:IV footerSize:0 footer:nil error:error];
//}
//
//
//- (BOOL)encryptFromStream:(NSInputStream *)fromStream toStream:(NSOutputStream *)toStream password:(NSString *)password error:(NSError **)error
//{
//  NSData *encryptionKeySalt = [RNCryptor randomDataOfLength:kSaltSize];
//  NSData *encryptionKey = [self keyForPassword:password salt:encryptionKeySalt];
//  NSData *IV = [self IVForKey:encryptionKey password:password salt:encryptionKeySalt];
//
//  [toStream open];
//  NSData *headerData = [kSaltedString dataUsingEncoding:NSUTF8StringEncoding];
//  if (![toStream _RNWriteData:headerData error:error] ||
//      ![toStream _RNWriteData:encryptionKeySalt error:error]
//      ) {
//    return NO;
//  }
//
//  RNCryptor *cryptor = [[RNCryptor alloc] initWithSettings:kRNCryptorOpenSSLSettings];
//  return [cryptor performOperation:kCCEncrypt fromStream:fromStream readCallback:nil toStream:toStream writeCallback:nil encryptionKey:encryptionKey IV:IV footerSize:0 footer:nil error:error];
//}
//@end
