//
//  RNCryptorTestHelpers.m
//  RNCryptor
//
//  Created by Rob Napier on 12/12/13.
//  Copyright (c) 2013 Rob Napier. All rights reserved.
//

#import "RNCryptorTestHelpers.h"

NSString * CreateTemporaryFilePath()
{
  // Thanks to Matt Gallagher
  NSString *tempFileTemplate = [NSTemporaryDirectory() stringByAppendingPathComponent:@"RNCryptorTest.XXXXXX"];
  const char *tempFileTemplateCString = [tempFileTemplate fileSystemRepresentation];
  char *tempFileNameCString = (char *)malloc(strlen(tempFileTemplateCString) + 1);
  strcpy(tempFileNameCString, tempFileTemplateCString);
  int fileDescriptor = mkstemp(tempFileNameCString);

  NSCAssert(fileDescriptor >= 0, @"Failed to create temporary file");

  NSString *tempFileName =
  [[NSFileManager defaultManager]
   stringWithFileSystemRepresentation:tempFileNameCString
   length:strlen(tempFileNameCString)];

  free(tempFileNameCString);
  return tempFileName;
}