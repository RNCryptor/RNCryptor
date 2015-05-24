//
//  RNCryptor+Swift.h
//  RNCryptor
//
//  Created by Rob Napier on 5/24/15.
//  Copyright (c) 2015 Rob Napier. All rights reserved.
//

#ifndef RNCryptor_RNCryptor_Swift_h
#define RNCryptor_RNCryptor_Swift_h

// These define what we can't import into a Swift framework.
// See https://github.com/RNCryptor/RNCryptor/issues/147

//
// CommonCryptor.h
//
#ifndef _CC_COMMON_CRYPTOR_
enum {
    kCCAlgorithmAES128 = 0,
    kCCAlgorithmDES,
    kCCAlgorithm3DES,
    kCCAlgorithmCAST,
    kCCAlgorithmRC4,
    kCCAlgorithmRC2
};
typedef uint32_t CCAlgorithm;

enum {
    /* options for block ciphers */
    kCCOptionPKCS7Padding	= 0x0001,
    kCCOptionECBMode		= 0x0002
    /* stream ciphers currently have no options */
};
typedef uint32_t CCOptions;

enum {
    /* AES */
    kCCBlockSizeAES128	= 16,
    /* DES */
    kCCBlockSizeDES		= 8,
    /* 3DES */
    kCCBlockSize3DES	= 8,
    /* CAST */
    kCCBlockSizeCAST	= 8,
    kCCBlockSizeRC2		= 8,
};

enum {
    kCCKeySizeAES128	= 16,
    kCCKeySizeAES192	= 24,
    kCCKeySizeAES256	= 32,
    kCCKeySizeDES		= 8,
    kCCKeySize3DES		= 24,
    kCCKeySizeMinCAST	= 5,
    kCCKeySizeMaxCAST	= 16,
    kCCKeySizeMinRC4	= 1,
    kCCKeySizeMaxRC4	= 512,
    kCCKeySizeMinRC2	= 1,
    kCCKeySizeMaxRC2	= 128
};

enum {
    kCCEncrypt = 0,
    kCCDecrypt,
};
typedef uint32_t CCOperation;

enum {
    kCCSuccess			= 0,
    kCCParamError		= -4300,
    kCCBufferTooSmall	= -4301,
    kCCMemoryFailure	= -4302,
    kCCAlignmentError	= -4303,
    kCCDecodeError		= -4304,
    kCCUnimplemented	= -4305
};
typedef int32_t CCCryptorStatus;
typedef struct _CCCryptor *CCCryptorRef;
CCCryptorStatus CCCryptorCreate(
                                CCOperation op,             /* kCCEncrypt, etc. */
                                CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
                                CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
                                const void *key,            /* raw key material */
                                size_t keyLength,
                                const void *iv,             /* optional initialization vector */
                                CCCryptorRef *cryptorRef);  /* RETURNED */
CCCryptorStatus CCCryptorRelease(
                                 CCCryptorRef cryptorRef);
size_t CCCryptorGetOutputLength(
                                CCCryptorRef cryptorRef,
                                size_t inputLength,
                                bool final);
CCCryptorStatus CCCryptorUpdate(
                                CCCryptorRef cryptorRef,
                                const void *dataIn,
                                size_t dataInLength,
                                void *dataOut,				/* data RETURNED here */
                                size_t dataOutAvailable,
                                size_t *dataOutMoved);		/* number of bytes written */
CCCryptorStatus CCCryptorFinal(
                               CCCryptorRef cryptorRef,
                               void *dataOut,
                               size_t dataOutAvailable,
                               size_t *dataOutMoved);		/* number of bytes written */
#endif // _CC_COMMON_CRYPTOR_

//
// CommonKeyDerivation.h
//
#ifndef _CC_PBKDF_H_
enum {
    kCCPBKDF2 = 2,
};
typedef uint32_t CCPBKDFAlgorithm;

enum {
    kCCPRFHmacAlgSHA1 = 1,
    kCCPRFHmacAlgSHA224 = 2,
    kCCPRFHmacAlgSHA256 = 3,
    kCCPRFHmacAlgSHA384 = 4,
    kCCPRFHmacAlgSHA512 = 5,
};
typedef uint32_t CCPseudoRandomAlgorithm;
#endif // _CC_PBKDF_H_

//
// CommonHMAC.h
//
#ifndef _CC_COMMON_HMAC_H_
enum {
    kCCHmacAlgSHA1,
    kCCHmacAlgMD5,
    kCCHmacAlgSHA256,
    kCCHmacAlgSHA384,
    kCCHmacAlgSHA512,
    kCCHmacAlgSHA224
};
typedef uint32_t CCHmacAlgorithm;

#define CC_HMAC_CONTEXT_SIZE    96
typedef struct {
    uint32_t            ctx[CC_HMAC_CONTEXT_SIZE];
} CCHmacContext;
void
CCHmacInit(CCHmacContext *ctx, CCHmacAlgorithm algorithm, const void *key, size_t keyLength);
void
CCHmacUpdate(CCHmacContext *ctx, const void *data, size_t dataLength);
void
CCHmacFinal(CCHmacContext *ctx, void *macOut);
void
CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength, const void *data,
       size_t dataLength, void *macOut);
#endif // _CC_COMMON_HMAC_H_

//
// CommonDigest.h
//
#ifndef _CC_COMMON_DIGEST_H_
#define CC_SHA1_DIGEST_LENGTH	20			/* digest length in bytes */
#define CC_SHA224_DIGEST_LENGTH		28			/* digest length in bytes */
#define CC_SHA256_DIGEST_LENGTH		32			/* digest length in bytes */
#define CC_SHA384_DIGEST_LENGTH		48			/* digest length in bytes */
#define CC_SHA512_DIGEST_LENGTH		64			/* digest length in bytes */
#endif // _CC_COMMON_DIGEST_H_

#endif // RNCryptor_RNCryptor_Swift_h
