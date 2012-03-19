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

#import "RNCryptorTests.h"
#import "RNCryptor.h"
#import "RNEncryptor.h"
#import "RNCryptorSettings.h"
#import "RNDecryptor.h"

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

- (void)testStream
{
  RNCryptor *cryptor = [[RNCryptor alloc] initWithSettings:[RNCryptorSettings defaultSettings]];

  NSData *data = [cryptor randomDataOfLength:1024];
  NSData *key = [cryptor randomDataOfLength:kCCKeySizeAES128];
  NSData *IV = [cryptor randomDataOfLength:kCCBlockSizeAES128];

  NSError *error;
  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor performOperation:kCCEncrypt
                              fromStream:encryptInputStream
                            readCallback:nil
                                toStream:encryptOutputStream
                           writeCallback:nil
                           encryptionKey:key
                                      IV:IV
                              footerSize:0
                                  footer:nil
                                   error:&error],
  @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);


  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor performOperation:kCCDecrypt
                              fromStream:decryptInputStream
                            readCallback:nil
                                toStream:decryptOutputStream
                           writeCallback:nil
                           encryptionKey:key
                                      IV:IV
                              footerSize:0
                                  footer:nil
                                   error:&error],
  @"Decrypt failed:%@", error);


  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

- (void)testHMAC
{
  RNEncryptor *encryptor = [RNEncryptor defaultEncryptor];

  NSData *data = [encryptor randomDataOfLength:1024];
  NSData *key = [encryptor randomDataOfLength:kCCKeySizeAES128];
  NSData *HMACkey = [encryptor randomDataOfLength:kCCKeySizeAES128];
  NSData *IV = [encryptor randomDataOfLength:kCCBlockSizeAES128];

  NSError *error;
  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([encryptor encryptFromStream:encryptInputStream toStream:encryptOutputStream encryptionKey:key IV:IV HMACKey:HMACkey error:&error],
  @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);

  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  RNDecryptor *decryptor = [RNDecryptor defaultDecryptor];

  STAssertTrue([decryptor decryptFromStream:decryptInputStream toStream:decryptOutputStream encryptionKey:key IV:IV HMACKey:HMACkey error:&error],
  @"Decrypt failed:%@", error);

  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

- (void)testSimple
{
  RNEncryptor *encryptor = [RNEncryptor defaultEncryptor];

  NSData *data = [encryptor randomDataOfLength:1024];
  NSString *password = @"Passw0rd!";

  NSError *error;

  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([encryptor encryptFromStream:encryptInputStream toStream:encryptOutputStream password:password error:&error],
  @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);

  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([[RNDecryptor defaultDecryptor] decryptFromStream:decryptInputStream toStream:decryptOutputStream password:password error:&error],
  @"Decrypt failed:%@", error);

  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

- (void)testSimpleFail
{
  RNEncryptor *encryptor = [RNEncryptor defaultEncryptor];

  NSData *data = [encryptor randomDataOfLength:1024];
  NSString *password = @"Passw0rd!";
  NSString *badPassword = @"NotThePassword";

  NSError *error;

  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([encryptor encryptFromStream:encryptInputStream toStream:encryptOutputStream password:password error:&error],
    @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);

  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertFalse([[RNDecryptor defaultDecryptor] decryptFromStream:decryptInputStream toStream:decryptOutputStream password:badPassword error:&error],
    @"Decrypt failed:%@", error);

  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertFalse([data isEqualToData:[decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey]], @"Decryption doesn't match");
}


- (void)_testDataOfLength:(NSUInteger)length
{
  RNEncryptor *encryptor = [RNEncryptor defaultEncryptor];

  NSData *data = [encryptor randomDataOfLength:length];
  NSString *password = @"Passw0rd!";

  NSError *error;

  NSData *encryptedData = [encryptor encryptData:data password:password error:&error];
  NSData *decryptedData = [[RNDecryptor defaultDecryptor] decryptData:encryptedData password:password error:&error];

  STAssertEqualObjects(decryptedData, data, @"Decrypted data does not match");
}

- (void)testData
{
  [self _testDataOfLength:1024];
}

- (void)testCorruption
{
  RNEncryptor *encryptor = [RNEncryptor defaultEncryptor];

  NSData *data = [encryptor randomDataOfLength:1024];
  NSString *password = @"Passw0rd!";

  NSError *error;

  NSData *encryptedData = [encryptor encryptData:data password:password error:&error];

  NSMutableData *corruptData = [encryptedData mutableCopy];
  [corruptData replaceBytesInRange:NSMakeRange(100,100) withBytes:[[encryptor randomDataOfLength:100] bytes]];

  NSData *decryptedData = [[RNDecryptor defaultDecryptor] decryptData:corruptData password:password error:&error];

  STAssertNil(decryptedData, @"Data should not have decrypted");
  STAssertEquals([error code], 1, @"Should have received error 1");
}

- (NSString *)temporaryFilePath
{
  // Thanks to Matt Gallagher
  NSString *tempFileTemplate = [NSTemporaryDirectory() stringByAppendingPathComponent:@"RNCryptorTest.XXXXXX"];
  const char *tempFileTemplateCString = [tempFileTemplate fileSystemRepresentation];
  char *tempFileNameCString = (char *)malloc(strlen(tempFileTemplateCString) + 1);
  strcpy(tempFileNameCString, tempFileTemplateCString);
  int fileDescriptor = mkstemp(tempFileNameCString);

  NSAssert(fileDescriptor >= 0, @"Failed to create temporary file");

  NSString *tempFileName =
      [[NSFileManager defaultManager]
          stringWithFileSystemRepresentation:tempFileNameCString
          length:strlen(tempFileNameCString)];

  free(tempFileNameCString);
  return tempFileName;
}

- (void)testURL
{
  RNEncryptor *encryptor = [RNEncryptor defaultEncryptor];

  NSData *data = [encryptor randomDataOfLength:1024];
  NSString *password = @"Passw0rd!";
  NSError *error;

  NSURL *plaintextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
  NSURL *ciphertextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
  NSURL *decryptedURL = [NSURL fileURLWithPath:[self temporaryFilePath]];

  NSAssert([data writeToURL:plaintextURL options:0 error:&error], @"Couldn't write file:%@", error);

  STAssertTrue([[RNEncryptor defaultEncryptor] encryptFromURL:plaintextURL toURL:ciphertextURL append:NO password:password error:&error], @"Failed to encrypt:%@", error);

  STAssertTrue([[RNDecryptor defaultDecryptor] decryptFromURL:ciphertextURL toURL:decryptedURL append:NO password:password error:&error], @"Failed to decrypt:%@", error);

  NSData *decryptedData = [NSData dataWithContentsOfURL:decryptedURL];
  STAssertEqualObjects(data, decryptedData, @"Data doesn't match");

  [[NSFileManager defaultManager] removeItemAtURL:plaintextURL error:&error];
  [[NSFileManager defaultManager] removeItemAtURL:ciphertextURL error:&error];
  [[NSFileManager defaultManager] removeItemAtURL:decryptedURL error:&error];
}

- (void)testBigData
{
  [self _testDataOfLength:1024*1024];
}

- (void)testOddSizeData
{
  [self _testDataOfLength:1023];
  [self _testDataOfLength:1025];
}

@end
