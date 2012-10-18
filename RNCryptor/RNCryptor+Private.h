//
//  RNCryptor(Private)
//
//  Copyright (c) 2012 Rob Napier
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a 
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//  
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

#import <Foundation/Foundation.h>
#import "RNCryptor.h"

@class RNCryptorEngine;

@interface RNCryptor ()
@property (nonatomic, readwrite, strong) RNCryptorEngine *engine;
#if OS_OBJECT_USE_OBJC
@property (nonatomic, readwrite, strong) dispatch_queue_t queue;
#else
@property (nonatomic, readwrite, assign) dispatch_queue_t queue;
#endif
@property (nonatomic, readonly) NSMutableData *outData;
@property (nonatomic, readwrite, copy) RNCryptorHandler handler;
@property (nonatomic, readwrite, assign) NSUInteger HMACLength;
@property (nonatomic, readwrite, strong) NSError *error;
@property (nonatomic, readwrite, assign, getter=isFinished) BOOL finished;
@property (nonatomic, readwrite, assign) RNCryptorOptions options;

- (id)initWithHandler:(RNCryptorHandler)handler;
+ (NSData *)synchronousResultForCryptor:(RNCryptor *)cryptor data:(NSData *)inData error:(NSError **)anError;
- (void)cleanupAndNotifyWithError:(NSError *)error;
- (BOOL)hasHMAC;
@end

@interface NSMutableData (RNCryptor)
- (NSData *)_RNConsumeToIndex:(NSUInteger)index;
@end
