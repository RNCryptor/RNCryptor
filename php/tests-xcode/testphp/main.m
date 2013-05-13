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
    NSData *fromPHPData = [@"AgF12bfxXb0lpR5tJAWTNb9jRUyyhTS5A8GBu5M1qhwA7CV0NMqHYTsyEsDjSccQiohU+FV9wk+VzGDrRmEpoK6PnVKTmsmJpnlqftxOv9BXlkmHIiEBCXzTprhzv4lWQ2MiEKkx+zda9B4WEoBuMTPxdLwnAxek9baTgv9mDH64oPmhZZWtlG3s9gSEaA1Cu2uYScDOin3+T1sEOdVAbnJG" base64DecodedData];

    NSData *fromPHPDecryptedData = [RNDecryptor decryptData:fromPHPData withPassword:@"myPassword" error:&decryptionError];

    NSLog(@"decryptionError %@", decryptionError);
    NSLog(@"Result = %@", fromPHPDecryptedData);
    NSLog(@"Result = %@", [[NSString alloc] initWithData:fromPHPDecryptedData encoding:NSUTF8StringEncoding]);

  }
    return 0;
}

