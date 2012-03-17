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

- (void)testLowLevel
{
  RNCryptor *cryptor = [RNCryptor AES128Cryptor];

  NSData *data = [cryptor randomDataOfLength:1024];
  NSData *key = [cryptor randomDataOfLength:kCCKeySizeAES128];
  NSData *iv = [cryptor randomDataOfLength:kCCBlockSizeAES128];

  NSInputStream *encryptStream = [NSInputStream inputStreamWithData:data];
  [encryptStream open];
  NSOutputStream *encryptedStream = [NSOutputStream outputStreamToMemory];
  [encryptedStream open];
  NSError *error;

  STAssertTrue([cryptor encryptFromStream:encryptStream toStream:encryptedStream encryptionKey:key IV:iv HMACKey:nil error:&error], @"Failed encryption:%@", error);

  [encryptStream close];
  [encryptedStream close];

  NSData *encrypted = [encryptedStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

  NSInputStream *decryptStream = [NSInputStream inputStreamWithData:encrypted];
  [decryptStream open];
  NSOutputStream *decryptedStream = [NSOutputStream outputStreamToMemory];
  [decryptedStream open];

  STAssertTrue([cryptor decryptFromStream:decryptStream toStream:decryptedStream encryptionKey:key IV:iv HMACKey:nil error:&error], @"Failed decryption:%@", error);

  [decryptStream close];
  [decryptedStream close];

  NSData *decrypted = [decryptedStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

  STAssertEqualObjects(data, decrypted, @"Encrypted and decrypted data do not match:%@:%@", data, decrypted);
}

- (void)testSimple
{
  NSData *data = [@"Test" dataUsingEncoding:NSUTF8StringEncoding];
  NSString *password = @"Password";

  RNCryptor *cryptor = [RNCryptor AES128Cryptor];
  NSInputStream *encryptStream = [NSInputStream inputStreamWithData:data];
  [encryptStream open];
  NSOutputStream *encryptedStream = [NSOutputStream outputStreamToMemory];
  [encryptedStream open];
  NSError *error;
  STAssertTrue([cryptor encryptFromStream:encryptStream toStream:encryptedStream password:password error:&error], @"Failed encryption:%@", error);
  [encryptStream close];
  [encryptedStream close];

  NSData *encrypted = [encryptedStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

  NSInputStream *decryptStream = [NSInputStream inputStreamWithData:encrypted];
  [decryptStream open];
  NSOutputStream *decryptedStream = [NSOutputStream outputStreamToMemory];
  [decryptedStream open];
  STAssertTrue([cryptor decryptFromStream:decryptStream toStream:decryptedStream password:password error:&error], @"Failed decryption:%@", error);
  [decryptStream close];
  [decryptedStream close];

  NSData *decrypted = [decryptedStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

  STAssertEqualObjects(data, decrypted, @"Encrypted and decrypted data do not match");
}

@end
