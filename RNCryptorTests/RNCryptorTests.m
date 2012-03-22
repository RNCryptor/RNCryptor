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
#import "RNOpenSSLCryptor.h"

NSString * const kGoodPassword = @"Passw0rd!";
NSString * const kBadPassword = @"NotThePassword";

@interface RNCryptor (Private)
- (NSData *)randomDataOfLength:(size_t)length;
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

- (void)testStream
{
  RNCryptor *cryptor = [[RNCryptor alloc] initWithSettings:[RNCryptorSettings AES256Settings]];

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
  RNCryptor *cryptor = [RNCryptor AES256Cryptor];

  NSData *data = [cryptor randomDataOfLength:1024];
  NSData *key = [cryptor randomDataOfLength:kCCKeySizeAES128];
  NSData *HMACkey = [cryptor randomDataOfLength:kCCKeySizeAES128];
  NSData *IV = [cryptor randomDataOfLength:kCCBlockSizeAES128];

  NSError *error;
  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor encryptFromStream:encryptInputStream toStream:encryptOutputStream encryptionKey:key IV:IV HMACKey:HMACkey error:&error],
  @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);

  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor decryptFromStream:decryptInputStream toStream:decryptOutputStream encryptionKey:key IV:IV HMACKey:HMACkey error:&error],
  @"Decrypt failed:%@", error);

  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

- (void)testSimple
{
  RNCryptor *cryptor = [RNCryptor AES256Cryptor];

  NSData *data = [cryptor randomDataOfLength:1024];

  NSError *error;

  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor encryptFromStream:encryptInputStream toStream:encryptOutputStream password:kGoodPassword error:&error],
  @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);

  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor decryptFromStream:decryptInputStream toStream:decryptOutputStream password:kGoodPassword error:&error],
  @"Decrypt failed:%@", error);

  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

- (void)testSimpleFail
{
  RNCryptor *cryptor = [RNCryptor AES256Cryptor];

  NSData *data = [cryptor randomDataOfLength:1024];

  NSError *error;

  NSInputStream *encryptInputStream = [NSInputStream inputStreamWithData:data];
  NSOutputStream *encryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertTrue([cryptor encryptFromStream:encryptInputStream toStream:encryptOutputStream password:kGoodPassword error:&error],
    @"Encrypt failed:%@", error);

  [encryptOutputStream close];
  [encryptInputStream close];

  NSData *encryptedData = [encryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  STAssertTrue([encryptedData length] >= [data length], @"Encrypted data too short: %d/%d", [encryptedData length], [data length]);

  NSInputStream *decryptInputStream = [NSInputStream inputStreamWithData:encryptedData];
  NSOutputStream *decryptOutputStream = [NSOutputStream outputStreamToMemory];

  STAssertFalse([cryptor decryptFromStream:decryptInputStream toStream:decryptOutputStream password:kBadPassword error:&error],
    @"Decrypt failed:%@", error);

  [decryptOutputStream close];
  [decryptInputStream close];

  STAssertFalse([data isEqualToData:[decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey]], @"Decryption doesn't match");
}

- (void)_testDataOfLength:(NSUInteger)length encryptPassword:(NSString *)encryptPassword decryptPassword:(NSString *)decryptPassword
{
  RNCryptor *cryptor = [RNCryptor AES256Cryptor];

  NSData *data = [cryptor randomDataOfLength:length];

  NSError *error;

  NSData *encryptedData = [cryptor encryptData:data password:encryptPassword error:&error];
  NSData *decryptedData = [cryptor decryptData:encryptedData password:decryptPassword error:&error];

  if ([encryptPassword isEqualToString:decryptPassword])
  {
    STAssertTrue([data isEqualToData:decryptedData], @"Decrypted data does not match for length:%d", length); // Don't use STAssertEqualObjects(). Some data is quite large.
  }
  else
  {
    STAssertFalse([data isEqualToData:decryptedData], @"Decrypt should have failed for length:%d", length); // Don't use STAssertEqualObjects(). Some data is quite large.
  }
}

- (void)_testDataOfLength:(NSUInteger)length
{
 [self _testDataOfLength:length encryptPassword:kGoodPassword decryptPassword:kBadPassword];
}

- (void)testData
{
  [self _testDataOfLength:1024];
}

- (void)testCorruption
{
  RNCryptor *cryptor = [RNCryptor AES256Cryptor];

  NSData *data = [cryptor randomDataOfLength:1024];

  NSError *error;

  NSData *encryptedData = [cryptor encryptData:data password:kGoodPassword error:&error];

  NSMutableData *corruptData = [encryptedData mutableCopy];
  [corruptData replaceBytesInRange:NSMakeRange(100,100) withBytes:[[cryptor randomDataOfLength:100] bytes]];

  NSData *decryptedData = [cryptor decryptData:corruptData password:kGoodPassword error:&error];

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

- (void)_testURLWithLength:(NSUInteger)length encryptPassword:(NSString *)encryptPassword decryptPassword:(NSString *)decryptPassword
{
  RNCryptor *cryptor = [RNCryptor AES256Cryptor];

  NSData *data = [cryptor randomDataOfLength:length];
  NSError *error;

  NSURL *plaintextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
  NSURL *ciphertextURL = [NSURL fileURLWithPath:[self temporaryFilePath]];
  NSURL *decryptedURL = [NSURL fileURLWithPath:[self temporaryFilePath]];

  NSAssert([data writeToURL:plaintextURL options:0 error:&error], @"Couldn't write file:%@", error);

  STAssertTrue([cryptor encryptFromURL:plaintextURL toURL:ciphertextURL append:NO password:encryptPassword error:&error], @"Failed to encrypt:%@", error);

  BOOL result = [cryptor decryptFromURL:ciphertextURL toURL:decryptedURL append:NO password:decryptPassword error:&error];
  if ([encryptPassword isEqualToString:decryptPassword])
  {
    STAssertTrue(result, @"Failed to decrypt:%@", error);
    NSData *decryptedData = [NSData dataWithContentsOfURL:decryptedURL];
    STAssertEqualObjects(data, decryptedData, @"Data doesn't match");

  }
  else
  {
    STAssertFalse(result, @"Should have failed");
  }

  [[NSFileManager defaultManager] removeItemAtURL:plaintextURL error:&error];
  [[NSFileManager defaultManager] removeItemAtURL:ciphertextURL error:&error];
  [[NSFileManager defaultManager] removeItemAtURL:decryptedURL error:&error];
}

- (void)_testURLWithLength:(NSUInteger)length
{
  return [self _testURLWithLength:length encryptPassword:kGoodPassword decryptPassword:kGoodPassword];
}


- (void)testURL
{
  [self _testURLWithLength:1024];

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

- (void)testActuallyEncrypting
{
  NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *error;
  NSData *encrypted = [[RNCryptor AES256Cryptor] encryptData:data password:kGoodPassword error:&error];

  NSRange found = [encrypted rangeOfData:data options:0 range:NSMakeRange(0, encrypted.length)];
  STAssertEquals(found.location, (NSUInteger)NSNotFound, @"Data is not encrypted");
}

- (void)testBadHeader
{
  NSData *data = [@"Data" dataUsingEncoding:NSUTF8StringEncoding];
  NSError *error;
  NSMutableData *encrypted = [[[RNCryptor AES256Cryptor] encryptData:data password:kGoodPassword error:&error] mutableCopy];

  uint8_t firstByte = 1;
  [encrypted replaceBytesInRange:NSMakeRange(0, 1) withBytes:&firstByte];

  NSData *decrypted = [[RNCryptor AES256Cryptor] decryptData:encrypted password:kGoodPassword error:&error];
  STAssertNil(decrypted, @"Decrypt should have failed");
  STAssertEquals([error code], kRNCyrptorUnknownHeader, @"Wrong error code:%d", [error code]);
}

- (void)testSmall
{
  for (NSUInteger i = 1; i < 32; i++)
  {
    [self _testDataOfLength:i];
  }
}

- (void)testNearReadBlocksize
{
  for (NSUInteger i = 1024 - 10; i < 1024 + 10; i++)
  {
    [self _testDataOfLength:i];
  }
}

- (void)testNearDoubleReadBlocksize
{
  for (NSUInteger i = 2048 - 10; i < 2048 + 10; i++)
  {
    [self _testDataOfLength:i];
  }
}

- (void)testSmallBadPassword
{
  for (NSUInteger i = 1; i < 32; i++)
  {
    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
  }
}

- (void)testNearReadBlocksizeBadPassword
{
  for (NSUInteger i = 1024 - 32; i < 1024 + 32; i++)
  {
    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
  }
}

- (void)testNearDoubleReadBlocksizeBadPassword
{
  for (NSUInteger i = 2048 - 32; i < 2048 + 32; i++)
  {
    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
  }
}

- (void)testNearTripleReadBlocksizeBadPassword
{
  for (NSUInteger i = 3072 - 32; i <= 3072 + 32; i++)
  {
    [self _testDataOfLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
  }
}

- (void)testURLBadPassword
{
  [self _testURLWithLength:1024 encryptPassword:kGoodPassword decryptPassword:kBadPassword];
}

- (void)testURLSmallBadPassword
{
  for (NSUInteger i = 1; i < 32; i++)
  {
    [self _testURLWithLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
  }
}

- (void)testURLNearReadBlocksize
{
  for (NSUInteger i = 1024 - 32; i < 1024 + 32; i++)
  {
    [self _testURLWithLength:i];
  }
}

- (void)testURLNearReadBlocksizeBadPassword
{
  for (NSUInteger i = 1024 - 32; i < 1024 + 32; i++)
  {
    [self _testURLWithLength:i encryptPassword:kGoodPassword decryptPassword:kBadPassword];
  }
}

- (void)testOpenSSL
{
  NSInputStream *input = [NSInputStream inputStreamWithFileAtPath:@"test.enc"];
  NSOutputStream *output = [NSOutputStream outputStreamToMemory];
  NSError *error;
  STAssertTrue([[[RNOpenSSLCryptor alloc] init] decryptFromStream:input toStream:output password:@"Passw0rd" error:&error], @"Could not decrypt:%@", error);

  NSData *decryptedData = [output propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
  NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
  NSString *testString = @"Test data\n";
  STAssertEqualObjects(decryptedString, testString, @"Decrypted data does not match");
}

@end
