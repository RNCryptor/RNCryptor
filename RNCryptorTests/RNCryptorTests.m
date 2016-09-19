//
//  RNCryptTests.m
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

#import <XCTest/XCTest.h>

#import "RNEncryptor.h"
#import "RNDecryptor.h"

NSString *const kGoodPassword = @"Passw0rd!";
NSString *const kBadPassword = @"NotThePassword";

@interface RNCryptorTests : XCTestCase
@property (nonatomic, readwrite, assign) BOOL isTestRunning;
@property (nonatomic, readwrite, strong) RNEncryptor *encryptor;
@end

@interface NSData (RNCryptor_ConsistentCompare)
- (BOOL)rnc_isEqualInConsistentTime:(NSData *)otherData;
@end

@implementation RNCryptorTests

- (void)setUp
{
  [super setUp];

  // Set-up code here.
}

- (void)tearDown
{
  // Tear-down code here.

  [super tearDown];
}

- (void) testAsyncDecrypt {
  size_t dataLength = 29808;

  NSData * plaintext = [RNCryptor randomDataOfLength:dataLength];

  NSError *error = nil;
  NSData *encryptedData = [RNEncryptor encryptData:plaintext
                                      withSettings:kRNCryptorAES256Settings
                                          password:kGoodPassword
                                             error:&error];

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSInputStream *inputStream = [NSInputStream inputStreamWithData:encryptedData];
  [inputStream open];

  __block NSOutputStream *outputStream = [[NSOutputStream alloc] initToMemory];
  __block NSError *decryptionError = nil;
  [outputStream open];

  __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);

  int blockSize = 1024;

  __block RNDecryptor *decryptor;
  __block NSMutableData *buffer = [NSMutableData dataWithLength:blockSize];

  dispatch_block_t readStreamBlock = ^{
    @autoreleasepool {
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
      }
    }
  };

  decryptor = [[RNDecryptor alloc] initWithPassword:kGoodPassword handler:^(RNCryptor *cryptor, NSData *data) {
    [outputStream write:data.bytes maxLength:data.length];
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

  XCTAssertEqualObjects(decryptedData, plaintext, @"Incorrect decryption.");

}

- (void)testSimple
{
  NSData *data = [RNCryptor randomDataOfLength:1024];
  NSError *error = nil;

  NSData *encryptedData = [RNEncryptor encryptData:data
                                      withSettings:kRNCryptorAES256Settings
                                          password:kGoodPassword
                                             error:&error];

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:encryptedData withPassword:kGoodPassword error:&decryptionError];
  XCTAssertNil(decryptionError, @"Error decrypting:%@", decryptionError);
  XCTAssertEqualObjects(decryptedData, data, @"Incorrect decryption.");
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
  [self.encryptor addData:data];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
  self.isTestRunning = NO;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
  [self.encryptor finish];
}

- (void)testAsync
{
  NSURL *testURL = [NSURL URLWithString:@"http://robnapier.net/favicon.ico"];
  NSError *downloadError = nil;
  NSData *plaintext = [NSData dataWithContentsOfURL:testURL options:0 error:&downloadError];
  XCTAssertNotNil(plaintext, @"Couldn't download: %@", downloadError);

  NSURLRequest *request = [NSURLRequest requestWithURL:testURL];
  NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest:request delegate:self];
  [connection start];

  self.isTestRunning = YES;
  __block NSMutableData *encryptedData = [NSMutableData data];
  __block NSError *encryptionError = nil;
  self.encryptor = [[RNEncryptor alloc] initWithSettings:kRNCryptorAES256Settings
                                                password:kGoodPassword
                                                 handler:^(RNCryptor *cryptor, NSData *data) {
                                                   [encryptedData appendData:data];
                                                   if (cryptor.isFinished) {
                                                     encryptionError = cryptor.error;
                                                     self.isTestRunning = NO;
                                                   }
                                                 }];

  NSDate *timeout = [NSDate dateWithTimeIntervalSinceNow:10];
  do {
    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                             beforeDate:timeout];
  } while (self.isTestRunning);

  XCTAssertFalse(self.isTestRunning, @"Test timed out.");
  XCTAssertNil(encryptionError, @"Encrypt error: %@", encryptionError);
  XCTAssertTrue([encryptedData length] > 0, @"Failed to encrypt.");

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:encryptedData withPassword:kGoodPassword error:&decryptionError];
  XCTAssertNil(decryptionError, @"decryption error:%@", decryptionError);
  XCTAssertEqualObjects(plaintext, decryptedData, @"Bad decryption");
}

- (void)testSimpleFail
{
  NSData *data = [RNCryptor randomDataOfLength:1024];
  NSError *error = nil;

  NSData *encryptedData = [RNEncryptor encryptData:data
                                      withSettings:kRNCryptorAES256Settings
                                          password:kGoodPassword
                                             error:&error];

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:encryptedData withPassword:kBadPassword error:&decryptionError];
  XCTAssertNotNil(decryptionError, @"Should have received error decrypting:%@", decryptionError);
  XCTAssertNil(decryptedData, @"Decryption should be nil: %@", decryptedData);
}

- (void)testCorruption
{
  NSData *data = [RNCryptor randomDataOfLength:1024];
  NSError *error = nil;

  NSData *encryptedData = [RNEncryptor encryptData:data
                                      withSettings:kRNCryptorAES256Settings
                                          password:kGoodPassword
                                             error:&error];

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSMutableData *corruptData = [encryptedData mutableCopy];
  [corruptData replaceBytesInRange:NSMakeRange(100, 100) withBytes:[[RNCryptor randomDataOfLength:100] bytes]];

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:corruptData withPassword:kGoodPassword error:&decryptionError];
  XCTAssertNil(decryptedData, @"Decryption should be nil: %@", decryptedData);
  XCTAssertEqual([decryptionError code], (NSInteger)kRNCryptorHMACMismatch, @"Should have received kRNCryptorHMACMismatch");
}

- (void)testBadHeader
{
  NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *error = nil;
  NSMutableData *encrypted = [[RNEncryptor encryptData:data withSettings:kRNCryptorAES256Settings password:kGoodPassword error:&error] mutableCopy];

  uint8_t firstByte = 99;
  [encrypted replaceBytesInRange:NSMakeRange(0, 1) withBytes:&firstByte];

  NSData *decrypted = [RNDecryptor decryptData:encrypted withPassword:kGoodPassword error:&error];
  XCTAssertNil(decrypted, @"Decrypt should have failed");
  XCTAssertEqual([error code], (NSInteger)kRNCryptorUnknownHeader, @"Wrong error code:%ld", (long)[error code]);
}

- (void)testActuallyEncrypting
{
  NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *error = nil;
  NSData *encrypted = [RNEncryptor encryptData:data withSettings:kRNCryptorAES256Settings password:kGoodPassword error:&error];

  NSRange found = [encrypted rangeOfData:data options:0 range:NSMakeRange(0, encrypted.length)];
  XCTAssertEqual(found.location, (NSUInteger)NSNotFound, @"Data is not encrypted");
}

- (void)testBackground
{
  NSData *data = [RNCryptor randomDataOfLength:1024];

  __block NSError *error = nil;
  __block NSData *encryptedData = nil;

  dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
    encryptedData = [RNEncryptor encryptData:data
                                withSettings:kRNCryptorAES256Settings
                                    password:kGoodPassword
                                       error:&error];
  });

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:encryptedData withPassword:kGoodPassword error:&decryptionError];
  XCTAssertNil(decryptionError, @"Error decrypting:%@", decryptionError);
  XCTAssertEqualObjects(decryptedData, data, @"Incorrect decryption.");
}

- (void)testKey
{
  NSData *data = [RNCryptor randomDataOfLength:1024];
  NSData *encryptionKey = [RNCryptor randomDataOfLength:kRNCryptorAES256Settings.keySettings.keySize];
  NSData *HMACKey = [RNCryptor randomDataOfLength:kRNCryptorAES256Settings.HMACKeySettings.keySize];
  NSError *error = nil;

  NSData *encryptedData = [RNEncryptor encryptData:data
                                      withSettings:kRNCryptorAES256Settings
                                     encryptionKey:encryptionKey
                                           HMACKey:HMACKey
                                             error:&error];

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:encryptedData withEncryptionKey:encryptionKey HMACKey:HMACKey error:&decryptionError];
  XCTAssertNil(decryptionError, @"Error decrypting:%@", decryptionError);
  XCTAssertEqualObjects(decryptedData, data, @"Incorrect decryption.");
}

// Issue #77: KeyForPassword() broken for multi-byte passwords (UTF-8)
- (void)testMultibytePasswordTruncation {
  NSData *data = [RNCryptor randomDataOfLength:1024];
  NSString *password = @"中文密码"; // 4 characters, 8 bytes => uses first 2 characters
  NSString *truncatedPassword = @"中文xx";  // 4 characters, 6 bytes => uses first 2 characters

  NSError *error;
  NSData *encryptedData = [RNEncryptor encryptData:data withSettings:kRNCryptorAES256Settings password:password error:&error];

  XCTAssertNil(error, @"Encryption error:%@", error);
  XCTAssertNotNil(encryptedData, @"Data did not encrypt.");

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:encryptedData withPassword:truncatedPassword error:&decryptionError];
  XCTAssertNil(decryptedData, @"Decryption should be nil: %@", decryptedData);
  XCTAssertEqual([decryptionError code], (NSInteger)kRNCryptorHMACMismatch, @"Should have received kRNCryptorHMACMismatch");
}

// Issue #77: KeyForPassword() broken for multi-byte passwords (UTF-8)
- (void)testReadVersion2PasswordTruncation {
  NSString *plaintext = @"Attack at dawn";
  NSString *password = @"中文密码";
  NSData *v2EncryptionWithPasswordTrunction =
  [[NSData alloc] initWithBase64EncodedString:@"AgHOKe1rygDPDDk5DBInKERD85Ezo1EAU5uj+PyEz22o2dtFAjPyaJhY3jW0BXD4W9L4GnAhiscr8PKZ+zOzWDbTFB3/6alv2LWQ1TCG4cpT0g==" options:0];

  NSError *decryptionError = nil;
  NSData *decryptedData = [RNDecryptor decryptData:v2EncryptionWithPasswordTrunction withPassword:password error:&decryptionError];
  XCTAssertNil(decryptionError, @"Error decrypting:%@", decryptionError);
  XCTAssertEqualObjects(decryptedData, [plaintext dataUsingEncoding:NSUTF8StringEncoding], @"Incorrect decryption.");
}

// Issue #24: Crash on 0-length input
- (void)testZeroLengthInput {
  NSData *data = [NSData data];

  NSError *encryptionError;
  NSData *encryptedData = [RNEncryptor encryptData:data withSettings:kRNCryptorAES256Settings password:kGoodPassword error:&encryptionError];

  XCTAssertNil(encryptionError, @"Error while encrypting: %@", encryptionError);
  XCTAssertNotNil(encryptedData, @"Failed to encrypt: %@", encryptionError);

  NSError *decryptionError;
  NSData *decryptedData  = [RNDecryptor decryptData:encryptedData withPassword:kGoodPassword error:&decryptionError];

  XCTAssertNil(decryptionError, @"Error while decrypting: %@", decryptionError);
  XCTAssertEqualObjects(decryptedData, data, @"Failed to decrypt.");
}

- (void)testEqualInConsistentTime
{
    NSData *data = [RNCryptor randomDataOfLength:101];
    NSData *data2 = [RNCryptor randomDataOfLength:102];
    
    XCTAssertFalse([data rnc_isEqualInConsistentTime:nil]);
    XCTAssertFalse([data rnc_isEqualInConsistentTime:[NSData data]]);
    XCTAssertFalse([data rnc_isEqualInConsistentTime:data2]);
    XCTAssertTrue([data rnc_isEqualInConsistentTime:data]);
    
    /* There was a bug where two datas whose length differed by a multiple of 256 could return YES */
    NSData *data256 = [RNCryptor randomDataOfLength:256];
    NSMutableData *data512 = [data256 mutableCopy];
    [data512 appendData:data256];
    XCTAssertFalse([data256 rnc_isEqualInConsistentTime:data512]);
}

//
//- (void)_testDataOfLength:(NSUInteger)length encryptPassword:(NSString *)encryptPassword decryptPassword:(NSString *)decryptPassword
//{
//  RNCryptor *cryptor = [RNCryptor AES256Cryptor];
//
//  NSData *data = [[cryptor class] randomDataOfLength:length];
//
//  NSError *error;
//
//  NSData *encryptedData = [cryptor encryptData:data password:encryptPassword error:&error];
//  NSData *decryptedData = [cryptor decryptData:encryptedData password:decryptPassword error:&error];
//
//  if ([encryptPassword isEqualToString:decryptPassword]) {
//    STAssertTrue([data isEqualToData:decryptedData], @"Decrypted data does not match for length:%d", length); // Don't use STAssertEqualObjects(). Some data is quite large.
//  }
//  else {
//    STAssertFalse([data isEqualToData:decryptedData], @"Decrypt should have failed for length:%d", length); // Don't use STAssertEqualObjects(). Some data is quite large.
//  }
//}
//
//- (void)_testDataOfLength:(NSUInteger)length
//{
//  [self _testDataOfLength:length encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//}
//
//- (void)testData
//{
//  [self _testDataOfLength:1024];
//}

//

//
//- (void)_testURLWithLength:(NSUInteger)length encryptPassword:(NSString *)encryptPassword decryptPassword:(NSString *)decryptPassword
//{
//  RNCryptor *cryptor = [RNCryptor AES256Cryptor];
//
//  NSData *data = [[cryptor class] randomDataOfLength:length];
//  NSError *error;
//
//  NSURL *plaintextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
//  NSURL *ciphertextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
//  NSURL *decryptedURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
//
//  NSAssert([data writeToURL:plaintextURL options:0 error:&error], @"Couldn't write file:%@", error);
//
//  STAssertTrue([cryptor encryptFromURL:plaintextURL toURL:ciphertextURL append:NO password:encryptPassword error:&error], @"Failed to encrypt:%@", error);
//
//  BOOL result = [cryptor decryptFromURL:ciphertextURL toURL:decryptedURL append:NO password:decryptPassword error:&error];
//  if ([encryptPassword isEqualToString:decryptPassword]) {
//    STAssertTrue(result, @"Failed to decrypt:%@", error);
//    NSData *decryptedData = [NSData dataWithContentsOfURL:decryptedURL];
//    STAssertEqualObjects(data, decryptedData, @"Data doesn't match");
//
//  }
//  else {
//    STAssertFalse(result, @"Should have failed");
//  }
//
//  [[NSFileManager defaultManager] removeItemAtURL:plaintextURL error:&error];
//  [[NSFileManager defaultManager] removeItemAtURL:ciphertextURL error:&error];
//  [[NSFileManager defaultManager] removeItemAtURL:decryptedURL error:&error];
//}
//
//- (void)_testURLWithLength:(NSUInteger)length
//{
//  return [self _testURLWithLength:length encryptPassword:kGoodPassword decryptPassword:kGoodPassword];
//}
//
//
//- (void)testURL
//{
//  [self _testURLWithLength:1024];
//
//}
//
//- (void)testBigData
//{
//  [self _testDataOfLength:1024 * 1024];
//}
//
//- (void)testOddSizeData
//{
//  [self _testDataOfLength:1023];
//  [self _testDataOfLength:1025];
//}
//
//- (void)testActuallyEncrypting
//{
//  NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
//  NSError *error;
//  NSData *encrypted = [[RNCryptor AES256Cryptor] encryptData:data password:kGoodPassword error:&error];
//
//  NSRange found = [encrypted rangeOfData:data options:0 range:NSMakeRange(0, encrypted.length)];
//  STAssertEquals(found.location, (NSUInteger)NSNotFound, @"Data is not encrypted");
//}
//
//- (void)testSmall
//{
//  for (NSUInteger i = 1; i < 32; i++) {
//    [self _testDataOfLength:i];
//  }
//}
//
//- (void)testNearReadBlocksize
//{
//  for (NSUInteger i = 1024 - 10; i < 1024 + 10; i++) {
//    [self _testDataOfLength:i];
//  }
//}
//
//- (void)testNearDoubleReadBlocksize
//{
//  for (NSUInteger i = 2048 - 10; i < 2048 + 10; i++) {
//    [self _testDataOfLength:i];
//  }
//}
//
//- (void)testSmallBadPassword
//{
//  for (NSUInteger i = 1; i < 32; i++) {
//    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//  }
//}
//
//- (void)testNearReadBlocksizeBadPassword
//{
//  for (NSUInteger i = 1024 - 32; i < 1024 + 32; i++) {
//    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//  }
//}
//
//- (void)testNearDoubleReadBlocksizeBadPassword
//{
//  for (NSUInteger i = 2048 - 32; i < 2048 + 32; i++) {
//    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//  }
//}
//
//- (void)testNearTripleReadBlocksizeBadPassword
//{
//  for (NSUInteger i = 3072 - 32; i <= 3072 + 32; i++) {
//    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//  }
//}
//
//- (void)testURLBadPassword
//{
//  [self _testURLWithLength:1024 encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//}
//
//- (void)testURLSmallBadPassword
//{
//  for (NSUInteger i = 1; i < 32; i++) {
//    [self _testURLWithLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//  }
//}
//
//- (void)testURLNearReadBlocksize
//{
//  for (NSUInteger i = 1024 - 32; i < 1024 + 32; i++) {
//    [self _testURLWithLength:i];
//  }
//}
//
//- (void)testURLNearReadBlocksizeBadPassword
//{
//  for (NSUInteger i = 1024 - 32; i < 1024 + 32; i++) {
//    [self _testURLWithLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
//  }
//}
//
//

//
//- (void)testURLNegativeInput
//{
//  RNCryptor *cryptor = [RNCryptor AES256Cryptor];
//
//  NSError *error;
//
//  NSURL *plaintextURL = [NSURL fileURLWithPath:@"DoesNotExist"];
//  NSURL *ciphertextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
//  NSURL *decryptedURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
//
//  // Don't write the data
//
//  STAssertFalse([cryptor encryptFromURL:plaintextURL toURL:ciphertextURL append:NO password:kGoodPassword error:&error], @"Should have failed.");
//
//  [[NSFileManager defaultManager] removeItemAtURL:plaintextURL error:&error];
//  [[NSFileManager defaultManager] removeItemAtURL:ciphertextURL error:&error];
//  [[NSFileManager defaultManager] removeItemAtURL:decryptedURL error:&error];
//}

@end
