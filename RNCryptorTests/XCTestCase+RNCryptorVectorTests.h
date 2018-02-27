//
//  RNCryptorVectorTests.h
//  RNCryptor
//
//  Created by Rob Napier on 1/9/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "RNEncryptor.h"
#import "RNDecryptor.h"

// Entry points for auto-generated test cases from GenVectorTests
// Are in the form verify_{filename}

@interface XCTestCase (RNCryptorVectorTests)
- (void)verify_v3_kdf:(NSDictionary *)vector;
- (void)verify_v3_password:(NSDictionary *)vector;
- (void)verify_v3_key:(NSDictionary *)vector;

- (void)verify_v2_kdf:(NSDictionary *)vector;
- (void)verify_v2_password:(NSDictionary *)vector;

- (void)verify_v1_kdf:(NSDictionary *)vector;
- (void)verify_v1_password:(NSDictionary *)vector;

@end
