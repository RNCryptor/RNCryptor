//
//  main.m
//  rncrypt
//
//  Created by Rob Napier on 1/29/13.
//  Copyright (c) 2013 Rob Napier. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RNDecryptor.h"

NSData *GetDataForHex(NSString *hex) {
  NSMutableData *data = [NSMutableData new];
  unsigned char whole_byte;
  char byte_chars[3] = {'\0','\0','\0'};
  int i;
  for (i=0; i < [hex length]/2; i++) {
    byte_chars[0] = [hex characterAtIndex:i*2];
    byte_chars[1] = [hex characterAtIndex:i*2+1];
    whole_byte = strtol(byte_chars, NULL, 16);
    [data appendBytes:&whole_byte length:1];
  }
  return data;
}

int main(int argc, const char * argv[])
{
  @autoreleasepool {

    NSString *password = @"P@ssw0rd!";
    NSString *messageString = @"02013F194AA9969CF70C8ACB76824DE4CB6CDCF78B7449A87C679FB8EDB6A0109C513481DE877F3A855A184C4947F2B3E8FEF7E916E4739F9F889A717FCAF277402866341008A09FD3EBAC7FA26C969DD7EE72CFB695547C971A75D8BF1CC5980E0C727BD9F97F6B7489F687813BEB94DEB61031260C246B9B0A78C2A52017AA8C92";

    NSData *message = GetDataForHex(messageString);

    NSError *error;
    NSData *decrypted = [RNDecryptor decryptData:message withPassword:password error:&error];

    NSLog(@"Result=%@", [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding]);

  }
    return 0;
}

