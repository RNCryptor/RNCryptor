//
//  main.m
//  RNCryptorVectors
//
//  Test vectors to assist porting
//
//

#import <Foundation/Foundation.h>
#import "RNEncryptor.h"
#import "RNDecryptor.h"
#import "RNCryptorEngine.h"

void Encrypt(NSString *string, NSString *password, NSData *encryptionSalt, NSData *HMACSalt, NSData *IV)
{
  NSError *error = nil;
  NSData *plaintext = [string dataUsingEncoding:NSUTF8StringEncoding];
  NSData *encryptionKey = [RNCryptor keyForPassword:password
                                               salt:encryptionSalt
                                           settings:kRNCryptorAES256Settings.keySettings];
  
  NSData *HMACKey =[RNCryptor keyForPassword:password
                                        salt:HMACSalt
                                    settings:kRNCryptorAES256Settings.keySettings];
  
  
  RNCryptorEngine *engine = [[RNCryptorEngine alloc] initWithOperation:kCCEncrypt
                                                              settings:kRNCryptorAES256Settings
                                                                   key:encryptionKey
                                                                    IV:IV
                                                                 error:&error];
  
  NSCAssert(engine && ! error, @"Failed engine:%@", error);
  
  NSMutableData *ciphertext = [NSMutableData new];
  [ciphertext appendData:[engine addData:plaintext error:&error]];
  [ciphertext appendData:[engine finishWithError:&error]];
  
  NSCAssert(ciphertext && ! error, @"Failed encryption:%@", error);
  
  printf("string=%s\n", [string UTF8String]);
  printf("plaintext=%s\n", [[plaintext description] UTF8String]);
  printf("password=%s\n", [password UTF8String]);
  printf("passwordData=%s\n", [[[password dataUsingEncoding:NSUTF8StringEncoding] description] UTF8String]);
  printf("encryptionSalt=%s\n", [[encryptionSalt description] UTF8String]);
  printf("HMACSalt=%s\n", [[HMACSalt description] UTF8String]);
  printf("encryptionKey=%s\n", [[encryptionKey description] UTF8String]);
  printf("HMACKey=%s\n", [[HMACKey description] UTF8String]);
  printf("ciphertext=%s\n", [[ciphertext description] UTF8String]);
  printf("---\n");
}

int main(int argc, const char * argv[])
{
  @autoreleasepool {
    NSString *string = @"Short Vector";
    NSString *password = @"password";
    NSData *encryptionSalt = [@"12345678" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *HMACSalt = [@"87654321" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *IV = [@"0123456789abcdef" dataUsingEncoding:NSUTF8StringEncoding];
    
    Encrypt(string, password, encryptionSalt, HMACSalt, IV);
    
    string = @"This is a longer test vector intended to be longer than one block.";
    
    Encrypt(string, password, encryptionSalt, HMACSalt, IV);

    NSError *error;
    NSData *encryptedData = [RNEncryptor encryptData:[string dataUsingEncoding:NSUTF8StringEncoding]
                                        withSettings:kRNCryptorAES256Settings
                                       password:password
                                               error:&error];

    [encryptedData writeToFile:@"/tmp/RNCryptor.enc" atomically:NO];

    NSData *v1Data = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"RNCryptorV1.enc" ofType:nil]];

    NSData *decryptedData = [RNDecryptor decryptData:v1Data withPassword:password error:&error];
    NSLog(@"decryptedData:%@", [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding]);
    NSLog(@"error:%@", error);

  }
  return 0;
}

