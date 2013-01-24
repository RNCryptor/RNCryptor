//
//  main.m
//  testphp
//
//  Created by Rob Napier on 1/24/13.
//  Copyright (c) 2013 Rob Napier. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RNDecryptor.h"
#import "Base64.h"

int main(int argc, const char * argv[])
{

  @autoreleasepool {
    NSError *decryptionError = nil;
    // Output of encrypt.php
    NSData *fromPHPData = [@"AgENx4deAFlngMaLY8aNzvhr5AlIjLdttyWnqszfohkpz/Q13gXsEUYmjNMXaBhg3AQnrKXuEnZbhL9Rtcb0ja/YUV21OKsCC3eb70CCeBvEjsCB/nPKCHJBp5tVmoyR8i/SI1FYrCLJmVqGAxJQbsa7X4YzC1Dan3+tG/mQ5VQE7LAgrwlVQNvNYL22DRocECU9XGdo9SSS8L6hYtVmACbe" base64DecodedData];

    NSData *fromPHPDecryptedData = [RNDecryptor decryptData:fromPHPData withPassword:@"myPassword" error:&decryptionError];

    NSLog(@"decryptionError %@", decryptionError);
    NSLog(@"Result = %@", fromPHPDecryptedData);
    NSLog(@"Result = %@", [[NSString alloc] initWithData:fromPHPDecryptedData encoding:NSUTF8StringEncoding]);

  }
    return 0;
}

