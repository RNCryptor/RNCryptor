//
//  ObjC.m
//  RNCryptor
//
//  Created by Rob Napier on 9/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

#import <XCTest/XCTest.h>
@import RNCryptor;
#import <CommonCrypto/CommonCryptor.h>

@interface ObjC : XCTestCase

@end

@implementation ObjC

NSData *randomDataOfLength(NSInteger length) {
    NSMutableData *data = [[NSMutableData alloc] initWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    NSCAssert(result == errSecSuccess, @"SecRandomCopyBytes must succeed");
    return data;
}

- (void)testOneShotKey {
    NSData *encryptionKey = randomDataOfLength(kCCKeySizeAES256);
    NSData *hmacKey = randomDataOfLength(kCCKeySizeAES256);
    NSData *data = randomDataOfLength(1024);

    NSData *ciphertext = [[[RNEncryptorV3 alloc] initWithEncryptionKey:encryptionKey hmacKey:hmacKey] encrypt:data];
    XCTAssertNotNil(ciphertext);

    NSError *error = nil;
    NSData *plaintext = [[[RNDecryptorV3 alloc] initWithEncryptionKey:encryptionKey hmacKey:hmacKey] decrypt:ciphertext error:&error];
    XCTAssertNil(error);
    XCTAssertEqualObjects(plaintext, data);
}

- (void)testOneShotPassword {
    NSString *password = @"PASSWORD";
    NSData *data = randomDataOfLength(1024);

    NSData *ciphertext = [[[RNEncryptor alloc] initWithPassword:password] encrypt:data];
    XCTAssertNotNil(ciphertext);

    NSError *error = nil;
    NSData *plaintext = [[[RNDecryptor alloc] initWithPassword:password] decrypt:ciphertext error:&error];
    XCTAssertNil(error);
    XCTAssertEqualObjects(plaintext, data);
}

- (void)testOneShotPasswordV3 {
    NSString *password = @"PASSWORD";
    NSData *data = randomDataOfLength(1024);

    NSData *ciphertext = [[[RNEncryptorV3 alloc] initWithPassword:password] encrypt:data];
    XCTAssertNotNil(ciphertext);

    NSError *error = nil;
    NSData *plaintext = [[[RNDecryptorV3 alloc] initWithPassword:password] decrypt:ciphertext error:&error];
    XCTAssertNil(error);
    XCTAssertEqualObjects(plaintext, data);
}


- (void)testUpdatesPassword {
    NSString *password = @"PASSWORD";
    NSData *data = randomDataOfLength(1024);

    RNEncryptor *cryptor = [[RNEncryptor alloc] initWithPassword:password];
    XCTAssertNotNil(cryptor);

    NSMutableData *ciphertext = [NSMutableData new];
    [ciphertext appendData:[cryptor update:data]];
    [ciphertext appendData:[cryptor final]];
    XCTAssertGreaterThan(ciphertext.length, data.length);


    NSError *error = nil;
    RNDecryptor *decryptor = [[RNDecryptor alloc] initWithPassword:password];
    XCTAssertNotNil(decryptor);

    NSMutableData *plaintext = [NSMutableData new];
    [plaintext appendData:[decryptor update:ciphertext error:&error]];
    XCTAssertNil(error);
    [plaintext appendData:[decryptor finalAndReturnError:&error]];
    XCTAssertNil(error);

    XCTAssertEqualObjects(plaintext, data);
}

@end
