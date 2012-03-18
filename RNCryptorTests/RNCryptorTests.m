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

//- (void)testData
//{
//  RNCryptor *cryptor = [RNCryptor AES128Cryptor];
//
//  NSData *data = [cryptor randomDataOfLength:1024];
//  NSData *key = [cryptor randomDataOfLength:kCCKeySizeAES128];
//  NSData *HMACkey = [cryptor randomDataOfLength:kCCKeySizeAES128];
//  NSData *IV = [cryptor randomDataOfLength:kCCBlockSizeAES128];
//
//  NSError *error;
//  RNCryptorDataOutput *encryptedStream = [[RNCryptorDataOutput alloc] initWithHMACKey:HMACkey];
//  STAssertTrue([cryptor encryptWithInput:[[RNCryptorDataInput alloc] initWithData:data HMACKey:nil]
//                                  output:encryptedStream
//                           encryptionKey:key
//                                      IV:IV
//                                   error:&error], @"Failed to encrypt:%@", error);
//
//  STAssertTrue([[encryptedStream data] length] > 0, @"No encrypted data");
//  STAssertEquals([[encryptedStream computedHMAC] length], (NSUInteger)CC_SHA1_DIGEST_LENGTH, @"HMAC incorrect length:%d", [[encryptedStream computedHMAC] length]);
//
//  RNCryptorDataInput *decryptStream = [[RNCryptorDataInput alloc] initWithData:[encryptedStream data] HMACKey:HMACkey];
//  RNCryptorDataOutput *decryptedStream = [[RNCryptorDataOutput alloc] initWithHMACKey:nil];
//  STAssertTrue([cryptor decryptWithInput:decryptStream
//                                  output:decryptedStream
//                           encryptionKey:key
//                                      IV:IV
//                                   error:&error], @"Failed to decrypt:%@", error);
//
//  STAssertEqualObjects([decryptedStream data], data, @"Data does not match.");
//  STAssertEqualObjects([encryptedStream computedHMAC], [decryptStream computedHMAC], @"HMAC does not match.");
//}

- (void)testStream
{
  RNCryptor *cryptor = [RNCryptor AES128Cryptor];

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


  [encryptOutputStream close];
  [encryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

- (void)testHMAC
{
  RNCryptor *cryptor = [RNCryptor AES128Cryptor];

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

  [encryptOutputStream close];
  [encryptInputStream close];

  STAssertEqualObjects(data, [decryptOutputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey], @"Decryption doesn't match");
}

@end
