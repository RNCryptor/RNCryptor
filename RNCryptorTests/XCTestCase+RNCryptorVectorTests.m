//
//  RNCryptorVectorTests.m
//  RNCryptor
//
//  Created by Rob Napier on 1/9/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

#import "XCTestCase+RNCryptorVectorTests.h"

NSData *GetDataForHex(NSString *hex) {
  NSString *hexNoSpaces = [[[hex stringByReplacingOccurrencesOfString:@" " withString:@""]
                            stringByReplacingOccurrencesOfString:@"<" withString:@""]
                           stringByReplacingOccurrencesOfString:@">" withString:@""];

  NSMutableData *data = [[NSMutableData alloc] init];
  unsigned char whole_byte = 0;
  char byte_chars[3] = {'\0','\0','\0'};
  int i;
  for (i=0; i < [hexNoSpaces length] / 2; i++) {
    byte_chars[0] = [hexNoSpaces characterAtIndex:i*2];
    byte_chars[1] = [hexNoSpaces characterAtIndex:i*2+1];
    whole_byte = strtol(byte_chars, NULL, 16);
    [data appendBytes:&whole_byte length:1];
  }
  return data;
}

@implementation XCTestCase (RNCryptorVectorTests)

- (void)verifyVector:(NSDictionary *)vector key:(NSString *)key equals:(NSData *)actual title:(NSString*)title {
  XCTAssertEqualObjects(actual, GetDataForHex(vector[key]), @"Failed %@ test (v%d): %s\n", title, [vector[@"version"] intValue], [vector[@"title"] UTF8String]);
}

- (void)verify_kdf:(NSDictionary *)vector {
  NSCParameterAssert(vector[@"title"]);
  NSCParameterAssert(vector[@"version"]);
  NSCParameterAssert(vector[@"password"]);
  NSCParameterAssert(vector[@"salt_hex"]);
  NSCParameterAssert(vector[@"key_hex"]);

  NSData *key = [RNCryptor keyForPassword:vector[@"password"]
                                     salt:GetDataForHex(vector[@"salt_hex"])
                                 settings:kRNCryptorAES256Settings.keySettings];
  [self verifyVector:vector key:@"key_hex" equals:key title:@"kdf"];
}

- (void)verify_kdf_short:(NSDictionary *)vector {
  NSCParameterAssert(vector[@"title"]);
  NSCParameterAssert(vector[@"version"]);
  NSCParameterAssert(vector[@"password"]);
  NSCParameterAssert(vector[@"iterations"]);
  NSCParameterAssert(vector[@"salt_hex"]);
  NSCParameterAssert(vector[@"key_hex"]);

  RNCryptorKeyDerivationSettings settings = kRNCryptorAES256Settings.keySettings;
  settings.rounds = 1000;

  NSData *key = [RNCryptor keyForPassword:vector[@"password"]
                                     salt:GetDataForHex(vector[@"salt_hex"])
                                 settings:settings];
  [self verifyVector:vector key:@"key_hex" equals:key title:@"short kdf"];
}

@end


