//
//  main.m
//  rncrypt
//
//  Created by Rob Napier on 3/17/13.
//  Copyright (c) 2013 Rob Napier. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RNEncryptor.h"
#import "RNDecryptor.h"
#import <getopt.h>

NSData *GetDataForHex(NSString *hex)
{
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

void usage() {
  printf("Not like that\n");
  exit(2);
}

void OutputData(NSData *data)
{
  NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (string) {
    printf("%s\n", [string UTF8String]);
  }
  else {
    printf("%s\n", [[data base64EncodedStringWithOptions:0] UTF8String]);
  }
}

int main(int argc, char * const argv[])
{
  @autoreleasepool {

    int decrypt_flag;
    NSString *password = nil;
    NSString *message = nil;

    char ch;

    /* options descriptor */
    struct option longopts[] = {
      { "decrypt",    no_argument,            &decrypt_flag,    1 },
      { "password",   required_argument,      NULL,           'p' },
      { NULL,         0,                      NULL,           0 }
    };

    while ((ch = getopt_long(argc, argv, "dp:P", longopts, NULL)) != -1)
      switch (ch) {
        case 'd':
          decrypt_flag = 1;
          break;
        case 'p':
          password = [NSString stringWithUTF8String:optarg];
          break;
        default:
          usage();
      }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
      usage();
    }

    message = [NSString stringWithUTF8String:argv[0]];

    NSError *error;
    NSData *data;
    if (decrypt_flag) {
      data = [RNDecryptor decryptData:[[NSData alloc] initWithBase64EncodedString:message
                                                                          options:NSDataBase64DecodingIgnoreUnknownCharacters]
                         withPassword:password
                                error:&error];
    }
    else {
      data = [RNEncryptor encryptData:[message dataUsingEncoding:NSUTF8StringEncoding]
                         withSettings:kRNCryptorAES256Settings
                             password:password
                                error:&error];
    }
    if (error) {
      NSLog(@"Failed: %@", error);
      exit(1);
    }
    else {
      OutputData(data);
    }
  }
  return 0;
}