//
//  main.m
//  RNCryptorVectors
//
//  Test vector verifier
//  vectors/
//    key       key-based test vectors
//    password  password-based test vectors
//
//

#import <Foundation/Foundation.h>
#import "RNEncryptor.h"
#import "RNDecryptor.h"
#import "RNCryptorEngine.h"

@interface MockEncryptor : RNEncryptor

@end

NSString *Trim(NSString *string) {
  return [string stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

NSString *GetStringFromPath(NSString *path) {
  NSError *error;
  NSString *string = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];
  NSCAssert(string, @"Could not read vector file %@: %@", path, error);

  return string;
}

NSString *GetUncommentedLineForLine(NSString *line) {
  return Trim([line componentsSeparatedByString:@"#"][0]);
}

NSArray *GetUncommentedLinesFromString(NSString *string) {
  NSMutableArray *lines = [NSMutableArray new];
  for (NSString *line in [string componentsSeparatedByString:@"\n"]) {
    [lines addObject:GetUncommentedLineForLine(line)];
  }
  return lines;
}

NSArray *GetBlocksFromLines(NSArray *lines) {
  NSMutableArray *blocks = [NSMutableArray new];

  NSMutableArray *block = [NSMutableArray new];
  for (NSString *line in lines) {
    if ([line length] == 0) {
      if ([block count] > 0) {
        [blocks addObject:block];
        block = [NSMutableArray new];
      }
      continue;
    }

    [block addObject:line];
  }

  if ([block count] > 0) {
    [blocks addObject:block];
  }

  return blocks;
}

NSDictionary *VectorForBlock(NSArray *vectorBlock) {
  NSMutableDictionary *vector = [NSMutableDictionary new];
  for (NSString *line in vectorBlock) {
    NSRange colonRange = [line rangeOfString:@":"];
    NSCAssert(colonRange.location != NSNotFound, @"Unexpected line: %@", line);
    NSString *key = Trim([line substringToIndex:colonRange.location]);
    NSString *value = Trim([line substringFromIndex:NSMaxRange(colonRange)]);
    NSCAssert([vector objectForKey:key] == nil, @"Duplicate key (%@) in block: %@", key, vectorBlock);
    vector[key] = value;
  }

  return vector;
}

NSArray *MapBlocksToVectors(NSArray *blocks) {
  NSMutableArray *vectors = [NSMutableArray new];
  for (NSArray *block in blocks) {
    [vectors addObject:VectorForBlock(block)];
  }

  return vectors;
}

NSArray *GetVectorsFromPath(NSString *path) {

  return MapBlocksToVectors(
                            GetBlocksFromLines(
                                               GetUncommentedLinesFromString(
                                                                             GetStringFromPath(path)
                                                                             )
                                               )
                            );
}

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

void Verify(NSString *type, NSDictionary *vector, NSString *key, NSData *actual) {
  if (! actual || ! [actual isEqual:GetDataForHex(vector[key])]) {
    printf("Failed %s test (v%d): %s\n", [type UTF8String], [vector[@"version"] intValue], [vector[@"title"] UTF8String]);
    printf("Expected: %s\n", [vector[key] UTF8String]);
    printf("Found: %s\n", [[actual description] UTF8String]);
    abort();
  }
}

void VerifyKeyVector(NSDictionary *vector) {
  NSCParameterAssert(vector[@"title"]);
  NSCParameterAssert(vector[@"version"]);
  NSCParameterAssert(vector[@"enc_key"]);
  NSCParameterAssert(vector[@"hmac_key"]);
  NSCParameterAssert(vector[@"iv"]);
  NSCParameterAssert(vector[@"plaintext"]);
  NSCParameterAssert(vector[@"ciphertext"]);

  NSError *error;

  if ([vector[@"version"] intValue] == kRNCryptorFileVersion) {
    NSData *cipherText = [RNEncryptor encryptData:GetDataForHex(vector[@"plaintext"])
                                     withSettings:kRNCryptorAES256Settings
                                    encryptionKey:GetDataForHex(vector[@"enc_key"])
                                          HMACKey:GetDataForHex(vector[@"hmac_key"])
                                               IV:GetDataForHex(vector[@"iv"])
                                            error:&error];
    if (! cipherText || ! [cipherText isEqual:GetDataForHex(vector[@"ciphertext"])]) {
      printf("Failed encrypting test (v%d): %s\n", [vector[@"version"] intValue], [vector[@"title"] UTF8String]);
      printf("Error: %s\n", [[error description] UTF8String]);
      printf("Expected: %s\n", [vector[@"ciphertext"] UTF8String]);
      printf("Found: %s\n", [[cipherText description] UTF8String]);
      abort();
    }
  }

  NSData *plaintext = [RNDecryptor decryptData:GetDataForHex(vector[@"ciphertext"])
                             withEncryptionKey:GetDataForHex(vector[@"enc_key"])
                                       HMACKey:GetDataForHex(vector[@"hmac_key"])
                                         error:&error];

  if (! plaintext || ! [plaintext isEqual:GetDataForHex(vector[@"plaintext"])]) {
    printf("Failed decrypting test: (v%d) %s \n", [vector[@"version"] intValue], [vector[@"title"] UTF8String]);
    printf("Error: %s\n", [[error description] UTF8String]);
    printf("Expected: %s\n", [vector[@"plaintext"] UTF8String]);
    printf("Found: %s\n", [[plaintext description] UTF8String]);
    abort();
  }
}

void VerifyPasswordVector(NSDictionary *vector) {
  NSCParameterAssert(vector[@"title"]);
  NSCParameterAssert(vector[@"version"]);
  NSCParameterAssert(vector[@"password"]);
  NSCParameterAssert(vector[@"iv"]);
  NSCParameterAssert(vector[@"enc_salt"]);
  NSCParameterAssert(vector[@"hmac_salt"]);
  NSCParameterAssert(vector[@"plaintext"]);
  NSCParameterAssert(vector[@"ciphertext"]);

  NSError *error;

  if ([vector[@"version"] intValue] == kRNCryptorFileVersion) {
    NSData *cipherText = [RNEncryptor encryptData:GetDataForHex(vector[@"plaintext"])
                                     withSettings:kRNCryptorAES256Settings
                                         password:vector[@"password"]
                                               IV:GetDataForHex(vector[@"iv"])
                                   encryptionSalt:GetDataForHex(vector[@"enc_salt"])
                                         HMACSalt:GetDataForHex(vector[@"hmac_salt"])
                                            error:&error];
    if (! cipherText || ! [cipherText isEqual:GetDataForHex(vector[@"ciphertext"])]) {
      printf("Failed encrypting test (v%d): %s\n", [vector[@"version"] intValue], [vector[@"title"] UTF8String]);
      printf("Error: %s\n", [[error description] UTF8String]);
      printf("Expected: %s\n", [vector[@"ciphertext"] UTF8String]);
      printf("Found: %s\n", [[cipherText description] UTF8String]);
      abort();
    }
  }

  NSData *plaintext = [RNDecryptor decryptData:GetDataForHex(vector[@"ciphertext"])
                                  withPassword:vector[@"password"]
                                         error:&error];
  Verify(@"decrypt", vector, @"plaintext", plaintext);
}

void VerifyKDFVector(NSDictionary *vector) {
  NSCParameterAssert(vector[@"title"]);
  NSCParameterAssert(vector[@"version"]);
  NSCParameterAssert(vector[@"password"]);
  NSCParameterAssert(vector[@"salt"]);
  NSCParameterAssert(vector[@"key"]);

  NSData *key = [RNCryptor keyForPassword:vector[@"password"]
                                     salt:GetDataForHex(vector[@"salt"])
                                 settings:kRNCryptorAES256Settings.keySettings];
  Verify(@"kdf", vector, @"key", key);
}

typedef void(*TestFunction)(NSDictionary *);

void ApplyTestToFile(TestFunction f, NSString *directory, NSString *filename) {
  NSArray *vectors = GetVectorsFromPath([directory stringByAppendingPathComponent:filename]);
  for (NSDictionary *vector in vectors) {
    f(vector);
  }
}

int main(int argc, const char * argv[]) {
  @autoreleasepool {
    if (argc != 2) {
      printf("RNCryptorVectors: Verify test vectors for RNCryptor.\n");
      printf("Usage: rncryptorvectors <path_to_vectors_dir>\n");
      printf("\n");
      exit(1);
    }

    NSString *vectorPath = @(argv[1]);
    ApplyTestToFile(&VerifyKeyVector, vectorPath, @"key");
    ApplyTestToFile(&VerifyPasswordVector, vectorPath, @"password");
    ApplyTestToFile(&VerifyKDFVector, vectorPath, @"kdf");
  }
  return 0;
}

