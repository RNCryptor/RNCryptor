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

@interface XCTestCase (RNCryptorVectorTests)
- (void)verify_kdf:(NSDictionary *)vector;
- (void)verify_kdf_short:(NSDictionary *)vector;
@end
