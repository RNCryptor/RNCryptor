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
- (void)verify_kdf:(NSDictionary *)vector;
- (void)verify_kdf_short:(NSDictionary *)vector;
- (void)verify_password:(NSDictionary *)vector;
- (void)verify_password_short:(NSDictionary *)vector;
- (void)verify_key:(NSDictionary *)vector;
@end
