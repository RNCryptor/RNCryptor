//
//  RNOpenSSLTests.m
//  RNCryptor
//
//  Created by Rob Napier on 12/12/13.
//  Copyright (c) 2013 Rob Napier. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "RNCryptor.h"
#import "RNOpenSSLCryptor.h"
#import "RNCryptorTestHelpers.h"

@interface RNOpenSSLTests : XCTestCase

@end

@implementation RNOpenSSLTests

- (void)setUp
{
    [super setUp];
    // Put setup code here; it will be run once, before the first test case.
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [super tearDown];
}

// echo Test data | openssl enc -aes-256-cbc -out test.enc -k Passw0rd

static NSString *const kOpenSSLString = @"Test data\n";
static NSString *const kOpenSSLPath = @"openssl.enc";
static NSString *const kOpenSSLPassword = @"Passw0rd";

- (void)testOpenSSLEncrypt
{
  NSError *error = nil;

  NSData *encryptedData = [RNOpenSSLEncryptor encryptData:[kOpenSSLString dataUsingEncoding:NSUTF8StringEncoding]
                                             withSettings:kRNCryptorAES256Settings
                                                 password:kOpenSSLPassword
                                                    error:&error];
  XCTAssertNotNil(encryptedData, @"Did not encrypt");
  XCTAssertNil(error, @"Error:%@", error);

  NSString *encryptedFile = CreateTemporaryFilePath();
  NSString *decryptedFile = CreateTemporaryFilePath();
  [encryptedData writeToFile:encryptedFile atomically:NO];

  NSString *cmd = [NSString stringWithFormat:@"/usr/bin/openssl enc -d -aes-256-cbc -k %@ -in %@ -out %@", kOpenSSLPassword, encryptedFile, decryptedFile];
  XCTAssertEqual(system([cmd UTF8String]), 0, @"System call failed");

  NSString *decryptedString = [NSString stringWithContentsOfFile:decryptedFile encoding:NSUTF8StringEncoding error:&error];
  XCTAssertEqualObjects(decryptedString, kOpenSSLString, @"Decryption doesn't match: %@", error);
}

- (void)testOpenSSLDecrypt
{
  NSData *encryptedData = [NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:kOpenSSLPath ofType:nil]];

  NSError *error = nil;
  NSData *decryptedData = [RNOpenSSLDecryptor decryptData:encryptedData
                                             withSettings:kRNCryptorAES256Settings
                                                 password:kOpenSSLPassword
                                                    error:&error];
  XCTAssertNotNil(decryptedData, @"Did not decrypt");
  XCTAssertNil(error, @"Error:%@", error);

  NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(decryptedString, kOpenSSLString, @"Decrypted data does not match");
}

- (void)testOpenSSLDecryptStream {
  NSString *filePath = [[NSBundle bundleForClass:[self class]] pathForResource:kOpenSSLPath ofType:nil];

  NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:filePath];
  [inputStream open];

  __block NSOutputStream *outputStream = [[NSOutputStream alloc] initToMemory];
  __block NSError *decryptionError = nil;
  [outputStream open];

  __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  size_t blockSize = 1024;

  __block RNDecryptor *decryptor;
  __block NSMutableData *buffer = [NSMutableData dataWithLength:blockSize];


  dispatch_block_t readStreamBlock = ^{
    [buffer setLength:blockSize];
    NSInteger bytesRead = [inputStream read:[buffer mutableBytes] maxLength:blockSize];
    if (bytesRead < 0) {
      XCTFail(@"Error reading block:%@", inputStream.streamError);
      [inputStream close];
      dispatch_semaphore_signal(sem);
    }
    else if (bytesRead == 0) {
      [inputStream close];
      [decryptor finish];
    }
    else {
      [buffer setLength:bytesRead];
      [decryptor addData:buffer];
      NSLog(@"Sent %ld bytes to decryptor", (unsigned long)bytesRead);
    }
  };

  decryptor = [[RNOpenSSLDecryptor alloc] initWithSettings:kRNCryptorAES256Settings
                                                  password:kOpenSSLPassword
                                                   handler:^(RNCryptor *cryptor, NSData *data) {
                                                     NSLog(@"Received %d bytes", data.length);
                                                     if (data.length > 0) {
                                                       [outputStream write:data.bytes maxLength:data.length];
                                                     }
                                                     if (cryptor.isFinished) {
                                                       [outputStream close];
                                                       dispatch_semaphore_signal(sem);
                                                     }
                                                     else {
                                                       readStreamBlock();
                                                     }
                                                   }];

  readStreamBlock();

  long timedout = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

  XCTAssertFalse(timedout, @"Test timed out.");
  XCTAssertNil(decryptionError, @"Decrypt error: %@", decryptionError);

  //Retrieve the decrypted data
  NSData *decryptedData = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  XCTAssertTrue([decryptedData length] > 0, @"Failed to decrypt.");

  NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
  XCTAssertEqualObjects(decryptedString, kOpenSSLString, @"Decrypted data does not match");
}

@end
