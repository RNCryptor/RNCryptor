//
//  RNCryptor.h
//
//  Copyright © 2015 Rob Napier. All rights reserved.
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

@import Foundation;

//! Project version number for RNCryptor.
FOUNDATION_EXPORT double RNCryptorVersionNumber;

//! Project version string for RNCryptor.
FOUNDATION_EXPORT const unsigned char RNCryptorVersionString[];

//
//  CommonCryptoError.h
//  CommonCrypto
//
//  Created by Richard Murphy on 4/15/14.
//  Copyright (c) 2014 Platform Security. All rights reserved.
//

#ifndef CommonCrypto_CommonCryptoError_h
#define CommonCrypto_CommonCryptoError_h

/*
 * Copyright (c) 2014 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

    /*!
     @enum       CCCryptorStatus
     @abstract   Return values from CommonCryptor operations.

     @constant   kCCSuccess          Operation completed normally.
     @constant   kCCParamError       Illegal parameter value.
     @constant   kCCBufferTooSmall   Insufficent buffer provided for specified
     operation.
     @constant   kCCMemoryFailure    Memory allocation failure.
     @constant   kCCAlignmentError   Input size was not aligned properly.
     @constant   kCCDecodeError      Input data did not decode or decrypt
     properly.
     @constant   kCCUnimplemented    Function not implemented for the current
     algorithm.
     */
    enum {
        kCCSuccess          = 0,
        kCCParamError       = -4300,
        kCCBufferTooSmall   = -4301,
        kCCMemoryFailure    = -4302,
        kCCAlignmentError   = -4303,
        kCCDecodeError      = -4304,
        kCCUnimplemented    = -4305,
        kCCOverflow         = -4306,
        kCCRNGFailure       = -4307,
    };
    typedef int32_t CCStatus;
    typedef int32_t CCCryptorStatus;

#if defined(__cplusplus)
}
#endif

#endif


/*
 * Copyright (c) 2006-2010 Apple, Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*!
 @header     CommonCryptor.h
 @abstract   Generic interface for symmetric encryption.

 @discussion This interface provides access to a number of symmetric
 encryption algorithms. Symmetric encryption algorithms come
 in two "flavors" -  block ciphers, and stream ciphers. Block
 ciphers process data (while both encrypting and decrypting)
 in discrete chunks of  data called blocks; stream ciphers
 operate on arbitrary sized data.

 The object declared in this interface, CCCryptor, provides
 access to both block ciphers and stream ciphers with the same
 API; however some options are available for block ciphers that
 do not apply to stream ciphers.

 The general operation of a CCCryptor is: initialize it
 with raw key data and other optional fields with
 CCCryptorCreate(); process input data via one or more calls to
 CCCryptorUpdate(), each of which may result in output data
 being written to caller-supplied memory; and obtain possible
 remaining output data with CCCryptorFinal(). The CCCryptor is
 disposed of via CCCryptorRelease(), or it can be reused (with
 the same key data as provided to CCCryptorCreate()) by calling
 CCCryptorReset().

 CCCryptors can be dynamically allocated by this module, or
 their memory can be allocated by the caller. See discussion for
 CCCryptorCreate() and CCCryptorCreateFromData() for information
 on CCCryptor allocation.

 One option for block ciphers is padding, as defined in PKCS7;
 when padding is enabled, the total amount of data encrypted
 does not have to be an even multiple of the block size, and
 the actual length of plaintext is calculated during decryption.

 Another option for block ciphers is Cipher Block Chaining, known
 as CBC mode. When using CBC mode, an Initialization Vector (IV)
 is provided along with the key when starting an encrypt
 or decrypt operation. If CBC mode is selected and no IV is
 provided, an IV of all zeroes will be used.

 CCCryptor also implements block bufferring, so that individual
 calls to CCCryptorUpdate() do not have to provide data whose
 length is aligned to the block size. (If padding is disabled,
 encrypting with block ciphers does require that the *total*
 length of data input to CCCryptorUpdate() call(s) be aligned
 to the block size.)

 A given CCCryptor can only be used by one thread at a time;
 multiple threads can use safely different CCCryptors at the
 same time.
 */

#ifndef _CC_COMMON_CRYPTOR_
#define _CC_COMMON_CRYPTOR_

#include <stdbool.h>
#include <stdint.h>
#ifndef KERNEL
#include <stddef.h>
#endif /* KERNEL */
#include <Availability.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*!
     @typedef    CCCryptorRef
     @abstract   Opaque reference to a CCCryptor object.
     */
    typedef struct _CCCryptor *CCCryptorRef;


    /*!
     @enum       CCOperation
     @abstract   Operations that an CCCryptor can perform.

     @constant   kCCEncrypt  Symmetric encryption.
     @constant   kCCDecrypt  Symmetric decryption.
     */
    enum {
        kCCEncrypt = 0,
        kCCDecrypt,
    };
    typedef uint32_t CCOperation;

    /*!
     @enum       CCAlgorithm
     @abstract   Encryption algorithms implemented by this module.

     @constant   kCCAlgorithmAES128  Advanced Encryption Standard, 128-bit block
     This is kept for historical reasons.  It's
     preferred now to use kCCAlgorithmAES since
     128-bit blocks are part of the standard.
     @constant   kCCAlgorithmAES     Advanced Encryption Standard, 128-bit block
     @constant   kCCAlgorithmDES     Data Encryption Standard
     @constant   kCCAlgorithm3DES    Triple-DES, three key, EDE configuration
     @constant   kCCAlgorithmCAST    CAST
     @constant   kCCAlgorithmRC4     RC4 stream cipher
     @constant   kCCAlgorithmBlowfish    Blowfish block cipher
     */
    enum {
        kCCAlgorithmAES128 = 0,
        kCCAlgorithmAES = 0,
        kCCAlgorithmDES,
        kCCAlgorithm3DES,
        kCCAlgorithmCAST,
        kCCAlgorithmRC4,
        kCCAlgorithmRC2,
        kCCAlgorithmBlowfish
    };
    typedef uint32_t CCAlgorithm;

    /*!
     @enum       CCOptions
     @abstract   Options flags, passed to CCCryptorCreate().

     @constant   kCCOptionPKCS7Padding   Perform PKCS7 padding.
     @constant   kCCOptionECBMode        Electronic Code Book Mode.
     Default is CBC.
     */
    enum {
        /* options for block ciphers */
        kCCOptionPKCS7Padding   = 0x0001,
        kCCOptionECBMode        = 0x0002
        /* stream ciphers currently have no options */
    };
    typedef uint32_t CCOptions;

    /*!
     @enum           Key sizes

     @discussion     Key sizes, in bytes, for supported algorithms.  Use these
     constants to select any keysize variants you wish to use
     for algorithms that support them (ie AES-128, AES-192, AES-256)

     @constant kCCKeySizeAES128      128 bit AES key size.
     @constant kCCKeySizeAES192      192 bit AES key size.
     @constant kCCKeySizeAES256      256 bit AES key size.
     @constant kCCKeySizeDES         DES key size.
     @constant kCCKeySize3DES        Triple DES key size.
     @constant kCCKeySizeMinCAST     CAST minimum key size.
     @constant kCCKeySizeMaxCAST     CAST maximum key size.
     @constant kCCKeySizeMinRC4      RC4 minimum key size.
     @constant kCCKeySizeMaxRC4      RC4 maximum key size.

     @discussion     DES and TripleDES have fixed key sizes.
     AES has three discrete key sizes.
     CAST and RC4 have variable key sizes.
     */
    enum {
        kCCKeySizeAES128          = 16,
        kCCKeySizeAES192          = 24,
        kCCKeySizeAES256          = 32,
        kCCKeySizeDES             = 8,
        kCCKeySize3DES            = 24,
        kCCKeySizeMinCAST         = 5,
        kCCKeySizeMaxCAST         = 16,
        kCCKeySizeMinRC4          = 1,
        kCCKeySizeMaxRC4          = 512,
        kCCKeySizeMinRC2          = 1,
        kCCKeySizeMaxRC2          = 128,
        kCCKeySizeMinBlowfish     = 8,
        kCCKeySizeMaxBlowfish     = 56,
    };

    /*!
     @enum           Block sizes

     @discussion     Block sizes, in bytes, for supported algorithms.

     @constant kCCBlockSizeAES128    AES block size (currently, only 128-bit
     blocks are supported).
     @constant kCCBlockSizeDES       DES block size.
     @constant kCCBlockSize3DES      Triple DES block size.
     @constant kCCBlockSizeCAST      CAST block size.
     */
    enum {
        /* AES */
        kCCBlockSizeAES128        = 16,
        /* DES */
        kCCBlockSizeDES           = 8,
        /* 3DES */
        kCCBlockSize3DES          = 8,
        /* CAST */
        kCCBlockSizeCAST          = 8,
        kCCBlockSizeRC2           = 8,
        kCCBlockSizeBlowfish      = 8,
    };

    /*!
     @enum       Minimum context sizes
     @discussion Minimum context sizes, for caller-allocated CCCryptorRefs.
     To minimize dynamic allocation memory, a caller can create
     a CCCryptorRef by passing caller-supplied memory to the
     CCCryptorCreateFromData() function.

     These constants define the minimum amount of memory, in
     bytes, needed for CCCryptorRefs for each supported algorithm.

     Note: these constants are valid for the current version of
     this library; they may change in subsequent releases, so
     applications wishing to allocate their own memory for use
     in creating CCCryptorRefs must be prepared to deal with
     a kCCBufferTooSmall return from CCCryptorCreateFromData().
     See discussion for the CCCryptorCreateFromData() function.

     @constant kCCContextSizeAES128 - Minimum context size for kCCAlgorithmAES128.
     @constant kCCContextSizeDES    - Minimum context size for kCCAlgorithmDES.
     @constant kCCContextSize3DES   - Minimum context size for kCCAlgorithm3DES.
     @constant kCCContextSizeCAST   - Minimum context size for kCCAlgorithmCAST.
     @constant kCCContextSizeRC4    - Minimum context size for kCCAlgorithmRC4.
     */

    enum {
        kCCContextSizeAES128	= 404,
        kCCContextSizeDES		= 240,
        kCCContextSize3DES		= 496,
        kCCContextSizeCAST		= 240,
        kCCContextSizeRC4		= 1072
    };



    /*!
     @function   CCCryptorCreate
     @abstract   Create a cryptographic context.

     @param      op          Defines the basic operation: kCCEncrypt or
     kCCDecrypt.

     @param      alg         Defines the algorithm.

     @param      options     A word of flags defining options. See discussion
     for the CCOptions type.

     @param      key         Raw key material, length keyLength bytes.

     @param      keyLength   Length of key material. Must be appropriate
     for the selected operation and algorithm. Some
     algorithms  provide for varying key lengths.

     @param      iv          Initialization vector, optional. Used by
     block ciphers when Cipher Block Chaining (CBC)
     mode is enabled. If present, must be the same
     length as the selected algorithm's block size.
     If CBC mode is selected (by the absence of the
     kCCOptionECBMode bit in the options flags) and no
     IV is present, a NULL (all zeroes) IV will be used.
     This parameter is ignored if ECB mode is used or
     if a stream cipher algorithm is selected.

     @param      cryptorRef  A (required) pointer to the returned CCCryptorRef.

     @result     Possible error returns are kCCParamError and kCCMemoryFailure.
     */
    CCCryptorStatus CCCryptorCreate(
                                    CCOperation op,             /* kCCEncrypt, etc. */
                                    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
                                    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
                                    const void *key,            /* raw key material */
                                    size_t keyLength,
                                    const void *iv,             /* optional initialization vector */
                                    CCCryptorRef *cryptorRef)  /* RETURNED */
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*!
     @function   CCCryptorCreateFromData
     @abstract   Create a cryptographic context using caller-supplied memory.

     @param      op          Defines the basic operation: kCCEncrypt or
     kCCDecrypt.

     @param      alg         Defines the algorithm.

     @param      options     A word of flags defining options. See discussion
     for the CCOptions type.

     @param      key         Raw key material, length keyLength bytes.

     @param      keyLength   Length of key material. Must be appropriate
     for the selected operation and algorithm. Some
     algorithms  provide for varying key lengths.

     @param      iv          Initialization vector, optional. Used by
     block ciphers when Cipher Block Chaining (CBC)
     mode is enabled. If present, must be the same
     length as the selected algorithm's block size.
     If CBC mode is selected (by the absence of the
     kCCOptionECBMode bit in the options flags) and no
     IV is present, a NULL (all zeroes) IV will be used.
     This parameter is ignored if ECB mode is used or
     if a stream cipher algorithm is selected.

     @param      data        A pointer to caller-supplied memory from which the
     CCCryptorRef will be created.

     @param      dataLength  The size of the caller-supplied memory in bytes.

     @param      cryptorRef  A (required) pointer to the returned CCCryptorRef.

     @param      dataUsed    Optional. If present, the actual number of bytes of
     the caller-supplied memory which was consumed by
     creation of the CCCryptorRef is returned here. Also,
     if the supplied memory is of insufficent size to create
     a CCCryptorRef, kCCBufferTooSmall is returned, and
     the minimum required buffer size is returned via this
     parameter if present.

     @result     Possible error returns are kCCParamError and kCCBufferTooSmall.

     @discussion The CCCryptorRef created by this function *may* be disposed of
     via CCCRyptorRelease; that call is not strictly necessary, but
     if it's not performed, good security practice dictates that the
     caller should zero the memory provided to create the CCCryptorRef
     when the caller is finished using the CCCryptorRef.
     */
    CCCryptorStatus CCCryptorCreateFromData(
                                            CCOperation op,             /* kCCEncrypt, etc. */
                                            CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
                                            CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
                                            const void *key,            /* raw key material */
                                            size_t keyLength,
                                            const void *iv,             /* optional initialization vector */
                                            const void *data,           /* caller-supplied memory */
                                            size_t dataLength,          /* length of data in bytes */
                                            CCCryptorRef *cryptorRef,   /* RETURNED */
                                            size_t *dataUsed)           /* optional, RETURNED */
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*!
     @function   CCCryptorRelease
     @abstract   Free a context created by CCCryptorCreate or
     CCCryptorCreateFromData().

     @param      cryptorRef  The CCCryptorRef to release.

     @result     The only possible error return is kCCParamError resulting
     from passing in a null CCCryptorRef.
     */
    CCCryptorStatus CCCryptorRelease(
                                     CCCryptorRef cryptorRef)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*!
     @function   CCCryptorUpdate
     @abstract   Process (encrypt, decrypt) some data. The result, if any,
     is written to a caller-provided buffer.

     @param      cryptorRef      A CCCryptorRef created via CCCryptorCreate() or
     CCCryptorCreateFromData().
     @param      dataIn          Data to process, length dataInLength bytes.
     @param      dataInLength    Length of data to process.
     @param      dataOut         Result is written here. Allocated by caller.
     Encryption and decryption can be performed
     "in-place", with the same buffer used for
     input and output.
     @param      dataOutAvailable The size of the dataOut buffer in bytes.
     @param      dataOutMoved    On successful return, the number of bytes
     written to dataOut.

     @result     kCCBufferTooSmall indicates insufficent space in the dataOut
     buffer. The caller can use
     CCCryptorGetOutputLength() to determine the
     required output buffer size in this case. The
     operation can be retried; no state is lost
     when this is returned.

     @discussion This routine can be called multiple times. The caller does
     not need to align input data lengths to block sizes; input is
     bufferred as necessary for block ciphers.

     When performing symmetric encryption with block ciphers,
     and padding is enabled via kCCOptionPKCS7Padding, the total
     number of bytes provided by all the calls to this function
     when encrypting can be arbitrary (i.e., the total number
     of bytes does not have to be block aligned). However if
     padding is disabled, or when decrypting, the total number
     of bytes does have to be aligned to the block size; otherwise
     CCCryptFinal() will return kCCAlignmentError.

     A general rule for the size of the output buffer which must be
     provided by the caller is that for block ciphers, the output
     length is never larger than the input length plus the block size.
     For stream ciphers, the output length is always exactly the same
     as the input length. See the discussion for
     CCCryptorGetOutputLength() for more information on this topic.

     Generally, when all data has been processed, call
     CCCryptorFinal().

     In the following cases, the CCCryptorFinal() is superfluous as
     it will not yield any data nor return an error:
     1. Encrypting or decrypting with a block cipher with padding
     disabled, when the total amount of data provided to
     CCCryptorUpdate() is an integral multiple of the block size.
     2. Encrypting or decrypting with a stream cipher.
     */
    CCCryptorStatus CCCryptorUpdate(
                                    CCCryptorRef cryptorRef,
                                    const void *dataIn,
                                    size_t dataInLength,
                                    void *dataOut,              /* data RETURNED here */
                                    size_t dataOutAvailable,
                                    size_t *dataOutMoved)       /* number of bytes written */
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*!
     @function   CCCryptorFinal
     @abstract   Finish an encrypt or decrypt operation, and obtain the (possible)
     final data output.

     @param      cryptorRef      A CCCryptorRef created via CCCryptorCreate() or
     CCCryptorCreateFromData().
     @param      dataOut         Result is written here. Allocated by caller.
     @param      dataOutAvailable The size of the dataOut buffer in bytes.
     @param      dataOutMoved    On successful return, the number of bytes
     written to dataOut.

     @result     kCCBufferTooSmall indicates insufficent space in the dataOut
     buffer. The caller can use
     CCCryptorGetOutputLength() to determine the
     required output buffer size in this case. The
     operation can be retried; no state is lost
     when this is returned.
     kCCAlignmentError When decrypting, or when encrypting with a
     block cipher with padding disabled,
     kCCAlignmentError will be returned if the total
     number of bytes provided to CCCryptUpdate() is
     not an integral multiple of the current
     algorithm's block size.
     kCCDecodeError  Indicates garbled ciphertext or the
     wrong key during decryption. This can only
     be returned while decrypting with padding
     enabled.

     @discussion Except when kCCBufferTooSmall is returned, the CCCryptorRef
     can no longer be used for subsequent operations unless
     CCCryptorReset() is called on it.

     It is not necessary to call CCCryptorFinal() when performing
     symmetric encryption or decryption if padding is disabled, or
     when using a stream cipher.

     It is not necessary to call CCCryptorFinal() prior to
     CCCryptorRelease() when aborting an operation.
     */
    CCCryptorStatus CCCryptorFinal(
                                   CCCryptorRef cryptorRef,
                                   void *dataOut,
                                   size_t dataOutAvailable,
                                   size_t *dataOutMoved)       /* number of bytes written */
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*!
     @function   CCCryptorGetOutputLength
     @abstract   Determine output buffer size required to process a given input
     size.

     @param      cryptorRef  A CCCryptorRef created via CCCryptorCreate() or
     CCCryptorCreateFromData().
     @param      inputLength The length of data which will be provided to
     CCCryptorUpdate().
     @param      final       If false, the returned value will indicate the
     output buffer space needed when 'inputLength'
     bytes are provided to CCCryptorUpdate(). When
     'final' is true, the returned value will indicate
     the total combined buffer space needed when
     'inputLength' bytes are provided to
     CCCryptorUpdate() and then CCCryptorFinal() is
     called.

     @result The maximum buffer space need to perform CCCryptorUpdate() and
     optionally CCCryptorFinal().

     @discussion Some general rules apply that allow clients of this module to
     know a priori how much output buffer space will be required
     in a given situation. For stream ciphers, the output size is
     always equal to the input size, and CCCryptorFinal() never
     produces any data. For block ciphers, the output size will
     always be less than or equal to the input size plus the size
     of one block. For block ciphers, if the input size provided
     to each call to CCCryptorUpdate() is is an integral multiple
     of the block size, then the output size for each call to
     CCCryptorUpdate() is less than or equal to the input size
     for that call to CCCryptorUpdate(). CCCryptorFinal() only
     produces output when using a block cipher with padding enabled.
     */
    size_t CCCryptorGetOutputLength(
                                    CCCryptorRef cryptorRef,
                                    size_t inputLength,
                                    bool final)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*!
     @function   CCCryptorReset
     @abstract   Reinitializes an existing CCCryptorRef with a (possibly)
     new initialization vector. The CCCryptorRef's key is
     unchanged. Not implemented for stream ciphers.

     @param      cryptorRef  A CCCryptorRef created via CCCryptorCreate() or
     CCCryptorCreateFromData().
     @param      iv          Optional initialization vector; if present, must
     be the same size as the current algorithm's block
     size.

     @result     The the only possible errors are kCCParamError and
     kCCUnimplemented.

     @discussion This can be called on a CCCryptorRef with data pending (i.e.
     in a padded mode operation before CCCryptFinal is called);
     however any pending data will be lost in that case.
     */
    CCCryptorStatus CCCryptorReset(
                                   CCCryptorRef cryptorRef,
                                   const void *iv)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*!
     @function   CCCrypt
     @abstract   Stateless, one-shot encrypt or decrypt operation.
     This basically performs a sequence of CCCrytorCreate(),
     CCCryptorUpdate(), CCCryptorFinal(), and CCCryptorRelease().

     @param      alg             Defines the encryption algorithm.


     @param      op              Defines the basic operation: kCCEncrypt or
     kCCDecrypt.

     @param      options         A word of flags defining options. See discussion
     for the CCOptions type.

     @param      key             Raw key material, length keyLength bytes.

     @param      keyLength       Length of key material. Must be appropriate
     for the select algorithm. Some algorithms may
     provide for varying key lengths.

     @param      iv              Initialization vector, optional. Used for
     Cipher Block Chaining (CBC) mode. If present,
     must be the same length as the selected
     algorithm's block size. If CBC mode is
     selected (by the absence of any mode bits in
     the options flags) and no IV is present, a
     NULL (all zeroes) IV will be used. This is
     ignored if ECB mode is used or if a stream
     cipher algorithm is selected.

     @param      dataIn          Data to encrypt or decrypt, length dataInLength
     bytes.

     @param      dataInLength    Length of data to encrypt or decrypt.

     @param      dataOut         Result is written here. Allocated by caller.
     Encryption and decryption can be performed
     "in-place", with the same buffer used for
     input and output.

     @param      dataOutAvailable The size of the dataOut buffer in bytes.

     @param      dataOutMoved    On successful return, the number of bytes
     written to dataOut. If kCCBufferTooSmall is
     returned as a result of insufficient buffer
     space being provided, the required buffer space
     is returned here.

     @result     kCCBufferTooSmall indicates insufficent space in the dataOut
     buffer. In this case, the *dataOutMoved
     parameter will indicate the size of the buffer
     needed to complete the operation. The
     operation can be retried with minimal runtime
     penalty.
     kCCAlignmentError indicates that dataInLength was not properly
     aligned. This can only be returned for block
     ciphers, and then only when decrypting or when
     encrypting with block with padding disabled.
     kCCDecodeError  Indicates improperly formatted ciphertext or
     a "wrong key" error; occurs only during decrypt
     operations.
     */

    CCCryptorStatus CCCrypt(
                            CCOperation op,         /* kCCEncrypt, etc. */
                            CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
                            CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
                            const void *key,
                            size_t keyLength,
                            const void *iv,         /* optional initialization vector */
                            const void *dataIn,     /* optional per op and alg */
                            size_t dataInLength,
                            void *dataOut,          /* data RETURNED here */
                            size_t dataOutAvailable,
                            size_t *dataOutMoved)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*!
     @enum       Cipher Modes
     @discussion These are the selections available for modes of operation for
     use with block ciphers.  If RC4 is selected as the cipher (a stream
     cipher) the only correct mode is kCCModeRC4.

     @constant kCCModeECB - Electronic Code Book Mode.
     @constant kCCModeCBC - Cipher Block Chaining Mode.
     @constant kCCModeCFB - Cipher Feedback Mode.
     @constant kCCModeOFB - Output Feedback Mode.
     @constant kCCModeXTS - XEX-based Tweaked CodeBook Mode.
     @constant kCCModeRC4 - RC4 as a streaming cipher is handled internally as a mode.
     @constant kCCModeCFB8 - Cipher Feedback Mode producing 8 bits per round.
     */


    enum {
        kCCModeECB		= 1,
        kCCModeCBC		= 2,
        kCCModeCFB		= 3,
        kCCModeCTR		= 4,
        kCCModeF8		= 5, // Unimplemented for now (not included)
        kCCModeLRW		= 6, // Unimplemented for now (not included)
        kCCModeOFB		= 7,
        kCCModeXTS		= 8,
        kCCModeRC4		= 9,
        kCCModeCFB8		= 10,
    };
    typedef uint32_t CCMode;

    /*!
     @enum       Padding for Block Ciphers
     @discussion These are the padding options available for block modes.

     @constant ccNoPadding -  No padding.
     @constant ccPKCS7Padding - PKCS7 Padding.
     */

    enum {
        ccNoPadding			= 0,
        ccPKCS7Padding		= 1,
    };
    typedef uint32_t CCPadding;

    /*!
     @enum       Mode options - Not currently in use.

     @discussion Values used to specify options for modes. This was used for counter
     mode operations in 10.8, now only Big Endian mode is supported.

     @constant kCCModeOptionCTR_LE - CTR Mode Little Endian.
     @constant kCCModeOptionCTR_BE - CTR Mode Big Endian.
     */

    enum {
        kCCModeOptionCTR_LE	= 0x0001, // Deprecated in iPhoneOS 6.0 and MacOSX10.9
        kCCModeOptionCTR_BE = 0x0002  // Deprecated in iPhoneOS 6.0 and MacOSX10.9
    };

    typedef uint32_t CCModeOptions;

    /*!
     @function   CCCryptorCreateWithMode
     @abstract   Create a cryptographic context.

     @param      op         Defines the basic operation: kCCEncrypt or
     kCCDecrypt.

     @param     mode		Specifies the cipher mode to use for operations.

     @param      alg        Defines the algorithm.

     @param		padding		Specifies the padding to use.

     @param      iv         Initialization vector, optional. Used by
     block ciphers with the following modes:

     Cipher Block Chaining (CBC)
     Cipher Feedback (CFB and CFB8)
     Output Feedback (OFB)
     Counter (CTR)

     If present, must be the same length as the selected
     algorithm's block size.  If no IV is present, a NULL
     (all zeroes) IV will be used.

     This parameter is ignored if ECB mode is used or
     if a stream cipher algorithm is selected.

     @param      key         Raw key material, length keyLength bytes.

     @param      keyLength   Length of key material. Must be appropriate
     for the selected operation and algorithm. Some
     algorithms  provide for varying key lengths.

     @param      tweak      Raw key material, length keyLength bytes. Used for the
     tweak key in XEX-based Tweaked CodeBook (XTS) mode.

     @param      tweakLength   Length of tweak key material. Must be appropriate
     for the selected operation and algorithm. Some
     algorithms  provide for varying key lengths.  For XTS
     this is the same length as the encryption key.

     @param		numRounds	The number of rounds of the cipher to use.  0 uses the default.

     @param      options    A word of flags defining options. See discussion
     for the CCModeOptions type.

     @param      cryptorRef  A (required) pointer to the returned CCCryptorRef.

     @result     Possible error returns are kCCParamError and kCCMemoryFailure.
     */


    CCCryptorStatus CCCryptorCreateWithMode(
                                            CCOperation 	op,				/* kCCEncrypt, kCCEncrypt */
                                            CCMode			mode,
                                            CCAlgorithm		alg,
                                            CCPadding		padding,
                                            const void 		*iv,			/* optional initialization vector */
                                            const void 		*key,			/* raw key material */
                                            size_t 			keyLength,
                                            const void 		*tweak,			/* raw tweak material */
                                            size_t 			tweakLength,
                                            int				numRounds,		/* 0 == default */
                                            CCModeOptions 	options,
                                            CCCryptorRef	*cryptorRef)	/* RETURNED */
    __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0);

#ifdef __cplusplus
}
#endif

#endif  /* _CC_COMMON_CRYPTOR_ */


/*
 * Copyright (c) 2004 Apple Computer, Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * CommonDigest.h - common digest routines: MD2, MD4, MD5, SHA1.
 */

#ifndef _CC_COMMON_DIGEST_H_
#define _CC_COMMON_DIGEST_H_

#include <stdint.h>
#include <Availability.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * For compatibility with legacy implementations, the *Init(), *Update(),
     * and *Final() functions declared here *always* return a value of 1 (one).
     * This corresponds to "success" in the similar openssl implementations.
     * There are no errors of any kind which can be, or are, reported here,
     * so you can safely ignore the return values of all of these functions
     * if you are implementing new code.
     *
     * The one-shot functions (CC_MD2(), CC_SHA1(), etc.) perform digest
     * calculation and place the result in the caller-supplied buffer
     * indicated by the md parameter. They return the md parameter.
     * Unlike the opensssl counterparts, these one-shot functions require
     * a non-NULL md pointer. Passing in NULL for the md parameter
     * results in a NULL return and no digest calculation.
     */

    typedef uint32_t CC_LONG;       /* 32 bit unsigned integer */
    typedef uint64_t CC_LONG64;     /* 64 bit unsigned integer */

    /*** MD2 ***/

#define CC_MD2_DIGEST_LENGTH    16          /* digest length in bytes */
#define CC_MD2_BLOCK_BYTES      64          /* block size in bytes */
#define CC_MD2_BLOCK_LONG       (CC_MD2_BLOCK_BYTES / sizeof(CC_LONG))

    typedef struct CC_MD2state_st
    {
        int num;
        unsigned char data[CC_MD2_DIGEST_LENGTH];
        CC_LONG cksm[CC_MD2_BLOCK_LONG];
        CC_LONG state[CC_MD2_BLOCK_LONG];
    } CC_MD2_CTX;

    extern int CC_MD2_Init(CC_MD2_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_MD2_Update(CC_MD2_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_MD2_Final(unsigned char *md, CC_MD2_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_MD2(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*** MD4 ***/

#define CC_MD4_DIGEST_LENGTH    16          /* digest length in bytes */
#define CC_MD4_BLOCK_BYTES      64          /* block size in bytes */
#define CC_MD4_BLOCK_LONG       (CC_MD4_BLOCK_BYTES / sizeof(CC_LONG))

    typedef struct CC_MD4state_st
    {
        CC_LONG A,B,C,D;
        CC_LONG Nl,Nh;
        CC_LONG data[CC_MD4_BLOCK_LONG];
        uint32_t num;
    } CC_MD4_CTX;

    extern int CC_MD4_Init(CC_MD4_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_MD4_Update(CC_MD4_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_MD4_Final(unsigned char *md, CC_MD4_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_MD4(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*** MD5 ***/

#define CC_MD5_DIGEST_LENGTH    16          /* digest length in bytes */
#define CC_MD5_BLOCK_BYTES      64          /* block size in bytes */
#define CC_MD5_BLOCK_LONG       (CC_MD5_BLOCK_BYTES / sizeof(CC_LONG))

    typedef struct CC_MD5state_st
    {
        CC_LONG A,B,C,D;
        CC_LONG Nl,Nh;
        CC_LONG data[CC_MD5_BLOCK_LONG];
        int num;
    } CC_MD5_CTX;

    extern int CC_MD5_Init(CC_MD5_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_MD5_Update(CC_MD5_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_MD5_Final(unsigned char *md, CC_MD5_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_MD5(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*** SHA1 ***/

#define CC_SHA1_DIGEST_LENGTH   20          /* digest length in bytes */
#define CC_SHA1_BLOCK_BYTES     64          /* block size in bytes */
#define CC_SHA1_BLOCK_LONG      (CC_SHA1_BLOCK_BYTES / sizeof(CC_LONG))

    typedef struct CC_SHA1state_st
    {
        CC_LONG h0,h1,h2,h3,h4;
        CC_LONG Nl,Nh;
        CC_LONG data[CC_SHA1_BLOCK_LONG];
        int num;
    } CC_SHA1_CTX;

    extern int CC_SHA1_Init(CC_SHA1_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA1_Final(unsigned char *md, CC_SHA1_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_SHA1(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*** SHA224 ***/
#define CC_SHA224_DIGEST_LENGTH     28          /* digest length in bytes */
#define CC_SHA224_BLOCK_BYTES       64          /* block size in bytes */

    /* same context struct is used for SHA224 and SHA256 */
    typedef struct CC_SHA256state_st
    {   CC_LONG count[2];
        CC_LONG hash[8];
        CC_LONG wbuf[16];
    } CC_SHA256_CTX;

    extern int CC_SHA224_Init(CC_SHA256_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA224_Update(CC_SHA256_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA224_Final(unsigned char *md, CC_SHA256_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_SHA224(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*** SHA256 ***/

#define CC_SHA256_DIGEST_LENGTH     32          /* digest length in bytes */
#define CC_SHA256_BLOCK_BYTES       64          /* block size in bytes */

    extern int CC_SHA256_Init(CC_SHA256_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA256_Update(CC_SHA256_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA256_Final(unsigned char *md, CC_SHA256_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*** SHA384 ***/

#define CC_SHA384_DIGEST_LENGTH     48          /* digest length in bytes */
#define CC_SHA384_BLOCK_BYTES      128          /* block size in bytes */

    /* same context struct is used for SHA384 and SHA512 */
    typedef struct CC_SHA512state_st
    {   CC_LONG64 count[2];
        CC_LONG64 hash[8];
        CC_LONG64 wbuf[16];
    } CC_SHA512_CTX;

    extern int CC_SHA384_Init(CC_SHA512_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA384_Update(CC_SHA512_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA384_Final(unsigned char *md, CC_SHA512_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_SHA384(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*** SHA512 ***/

#define CC_SHA512_DIGEST_LENGTH     64          /* digest length in bytes */
#define CC_SHA512_BLOCK_BYTES      128          /* block size in bytes */

    extern int CC_SHA512_Init(CC_SHA512_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA512_Update(CC_SHA512_CTX *c, const void *data, CC_LONG len)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern int CC_SHA512_Final(unsigned char *md, CC_SHA512_CTX *c)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    extern unsigned char *CC_SHA512(const void *data, CC_LONG len, unsigned char *md)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

    /*
     * To use the above digest functions with existing code which uses
     * the corresponding openssl functions, #define the symbol
     * COMMON_DIGEST_FOR_OPENSSL in your client code (BEFORE including
     * this file), and simply link against libSystem (or System.framework)
     * instead of libcrypto.
     *
     * You can *NOT* mix and match functions operating on a given data
     * type from the two implementations; i.e., if you do a CC_MD5_Init()
     * on a CC_MD5_CTX object, do not assume that you can do an openssl-style
     * MD5_Update() on that same context.
     */

#ifdef  COMMON_DIGEST_FOR_OPENSSL

#define MD2_DIGEST_LENGTH           CC_MD2_DIGEST_LENGTH
#define MD2_CTX                     CC_MD2_CTX
#define MD2_Init                    CC_MD2_Init
#define MD2_Update                  CC_MD2_Update
#define MD2_Final                   CC_MD2_Final

#define MD4_DIGEST_LENGTH           CC_MD4_DIGEST_LENGTH
#define MD4_CTX                     CC_MD4_CTX
#define MD4_Init                    CC_MD4_Init
#define MD4_Update                  CC_MD4_Update
#define MD4_Final                   CC_MD4_Final

#define MD5_DIGEST_LENGTH           CC_MD5_DIGEST_LENGTH
#define MD5_CTX                     CC_MD5_CTX
#define MD5_Init                    CC_MD5_Init
#define MD5_Update                  CC_MD5_Update
#define MD5_Final                   CC_MD5_Final

#define SHA_DIGEST_LENGTH           CC_SHA1_DIGEST_LENGTH
#define SHA_CTX                     CC_SHA1_CTX
#define SHA1_Init                   CC_SHA1_Init
#define SHA1_Update                 CC_SHA1_Update
#define SHA1_Final                  CC_SHA1_Final

#define SHA224_DIGEST_LENGTH        CC_SHA224_DIGEST_LENGTH
#define SHA256_CTX                  CC_SHA256_CTX
#define SHA224_Init                 CC_SHA224_Init
#define SHA224_Update               CC_SHA224_Update
#define SHA224_Final                CC_SHA224_Final

#define SHA256_DIGEST_LENGTH        CC_SHA256_DIGEST_LENGTH
#define SHA256_Init                 CC_SHA256_Init
#define SHA256_Update               CC_SHA256_Update
#define SHA256_Final                CC_SHA256_Final

#define SHA384_DIGEST_LENGTH        CC_SHA384_DIGEST_LENGTH
#define SHA512_CTX                  CC_SHA512_CTX
#define SHA384_Init                 CC_SHA384_Init
#define SHA384_Update               CC_SHA384_Update
#define SHA384_Final                CC_SHA384_Final

#define SHA512_DIGEST_LENGTH        CC_SHA512_DIGEST_LENGTH
#define SHA512_Init                 CC_SHA512_Init
#define SHA512_Update               CC_SHA512_Update
#define SHA512_Final                CC_SHA512_Final
    
    
#endif  /* COMMON_DIGEST_FOR_OPENSSL */
    
    /*
     * In a manner similar to that described above for openssl 
     * compatibility, these macros can be used to provide compatiblity 
     * with legacy implementations of MD5 using the interface defined 
     * in RFC 1321.
     */
    
#ifdef  COMMON_DIGEST_FOR_RFC_1321
    
#define MD5_CTX                     CC_MD5_CTX
#define MD5Init                     CC_MD5_Init
#define MD5Update                   CC_MD5_Update
    void MD5Final (unsigned char [16], MD5_CTX *)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);
    
#endif  /* COMMON_DIGEST_FOR_RFC_1321 */
    
#ifdef __cplusplus
}
#endif

#endif  /* _CC_COMMON_DIGEST_H_ */


/*
 * Copyright (c) 2004 Apple Computer, Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*!
 @header     CommonHMAC.h
 @abstract   Keyed Message Authentication Code (HMAC) functions.
 */

#ifndef _CC_COMMON_HMAC_H_
#define _CC_COMMON_HMAC_H_

#include <sys/types.h>
#include <Availability.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*!
     @enum       CCHmacAlgorithm
     @abstract   Algorithms implemented in this module.

     @constant   kCCHmacAlgSHA1      HMAC with SHA1 digest
     @constant   kCCHmacAlgMD5       HMAC with MD5 digest
     @constant   kCCHmacAlgSHA256    HMAC with SHA256 digest
     @constant   kCCHmacAlgSHA384    HMAC with SHA384 digest
     @constant   kCCHmacAlgSHA512    HMAC with SHA512 digest
     @constant   kCCHmacAlgSHA224    HMAC with SHA224 digest
     */
    enum {
        kCCHmacAlgSHA1,
        kCCHmacAlgMD5,
        kCCHmacAlgSHA256,
        kCCHmacAlgSHA384,
        kCCHmacAlgSHA512,
        kCCHmacAlgSHA224
    };
    typedef uint32_t CCHmacAlgorithm;

    /*!
     @typedef    CCHmacContext
     @abstract   HMAC context.
     */
#define CC_HMAC_CONTEXT_SIZE    96
    typedef struct {
        uint32_t            ctx[CC_HMAC_CONTEXT_SIZE];
    } CCHmacContext;

    /*!
     @function   CCHmacInit
     @abstract   Initialize an CCHmacContext with provided raw key bytes.

     @param      ctx         An HMAC context.
     @param      algorithm   HMAC algorithm to perform.
     @param      key         Raw key bytes.
     @param      keyLength   Length of raw key bytes; can be any
     length including zero.
     */
    void CCHmacInit(
                    CCHmacContext *ctx,
                    CCHmacAlgorithm algorithm,
                    const void *key,
                    size_t keyLength)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*!
     @function   CCHmacUpdate
     @abstract   Process some data.

     @param      ctx         An HMAC context.
     @param      data        Data to process.
     @param      dataLength  Length of data to process, in bytes.

     @discussion This can be called multiple times.
     */
    void CCHmacUpdate(
                      CCHmacContext *ctx,
                      const void *data,
                      size_t dataLength)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*!
     @function   CCHmacFinal
     @abstract   Obtain the final Message Authentication Code.

     @param      ctx         An HMAC context.
     @param      macOut      Destination of MAC; allocated by caller.

     @discussion The length of the MAC written to *macOut is the same as
     the digest length associated with the HMAC algorithm:

     kCCHmacSHA1 : CC_SHA1_DIGEST_LENGTH

     kCCHmacMD5  : CC_MD5_DIGEST_LENGTH
     */
    void CCHmacFinal(
                     CCHmacContext *ctx,
                     void *macOut)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);


    /*
     * Stateless, one-shot HMAC function.
     * Output is written to caller-supplied buffer, as in CCHmacFinal().
     */
    void CCHmac(
                CCHmacAlgorithm algorithm,  /* kCCHmacSHA1, kCCHmacMD5 */
                const void *key,
                size_t keyLength,           /* length of key in bytes */
                const void *data,
                size_t dataLength,          /* length of data in bytes */
                void *macOut)               /* MAC written here */
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);
    
#ifdef __cplusplus
}
#endif

#endif  /* _CC_COMMON_HMAC_H_ */


/*
 * Copyright (c) 2010 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _CC_PBKDF_H_
#define _CC_PBKDF_H_

#include <sys/param.h>
#include <string.h>
#include <Availability.h>
#ifdef KERNEL
#include <machine/limits.h>
#else
#include <limits.h>
#include <stdlib.h>
#endif /* KERNEL */


#ifdef __cplusplus
extern "C" {
#endif

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

    /*

     @function  CCKeyDerivationPBKDF
     @abstract  Derive a key from a text password/passphrase

     @param algorithm       Currently only PBKDF2 is available via kCCPBKDF2
     @param password        The text password used as input to the derivation
     function.  The actual octets present in this string
     will be used with no additional processing.  It's
     extremely important that the same encoding and
     normalization be used each time this routine is
     called if the same key is  expected to be derived.
     @param passwordLen     The length of the text password in bytes.
     @param salt            The salt byte values used as input to the derivation
     function.
     @param saltLen         The length of the salt in bytes.
     @param prf             The Pseudo Random Algorithm to use for the derivation
     iterations.
     @param rounds          The number of rounds of the Pseudo Random Algorithm
     to use.
     @param derivedKey      The resulting derived key produced by the function.
     The space for this must be provided by the caller.
     @param derivedKeyLen   The expected length of the derived key in bytes.

     @discussion The following values are used to designate the PRF:

     * kCCPRFHmacAlgSHA1
     * kCCPRFHmacAlgSHA224
     * kCCPRFHmacAlgSHA256
     * kCCPRFHmacAlgSHA384
     * kCCPRFHmacAlgSHA512

     @result     kCCParamError can result from bad values for the password, salt,
     and unwrapped key pointers as well as a bad value for the prf
     function.

     */

    int
    CCKeyDerivationPBKDF( CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen,
                         const uint8_t *salt, size_t saltLen,
                         CCPseudoRandomAlgorithm prf, uint rounds,
                         uint8_t *derivedKey, size_t derivedKeyLen)
    __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0);

    /*
     * All lengths are in bytes - not bits.
     */

    /*

     @function  CCCalibratePBKDF
     @abstract  Determine the number of PRF rounds to use for a specific delay on
     the current platform.
     @param algorithm       Currently only PBKDF2 is available via kCCPBKDF2
     @param passwordLen     The length of the text password in bytes.
     @param saltLen         The length of the salt in bytes.
     @param prf             The Pseudo Random Algorithm to use for the derivation
     iterations.
     @param derivedKeyLen   The expected length of the derived key in bytes.
     @param msec            The targetted duration we want to achieve for a key
     derivation with these parameters.

     @result the number of iterations to use for the desired processing time.

     */

    uint
    CCCalibratePBKDF(CCPBKDFAlgorithm algorithm, size_t passwordLen, size_t saltLen,
                     CCPseudoRandomAlgorithm prf, size_t derivedKeyLen, uint32_t msec)
    __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0);

#ifdef __cplusplus
}
#endif

#endif  /* _CC_PBKDF_H_ */


/*
 * Copyright (c) 2014 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

//
//  CommonRandom.h
//  CommonCrypto

#ifndef CommonCrypto_CommonRandom_h
#define CommonCrypto_CommonRandom_h

#if defined(__cplusplus)
extern "C" {
#endif

    typedef CCCryptorStatus CCRNGStatus;

    /*!
     @function      CCRandomGenerateBytes

     @abstract      Return random bytes in a buffer allocated by the caller.

     @discussion    The PRNG returns cryptographically strong random
     bits suitable for use as cryptographic keys, IVs, nonces etc.

     @param         bytes   Pointer to the return buffer.
     @param         count   Number of random bytes to return.

     @result        Return kCCSuccess on success.
     */

    CCRNGStatus CCRandomGenerateBytes(void *bytes, size_t count)
    __OSX_AVAILABLE_STARTING(__MAC_10_10, __IPHONE_8_0);
    
#if defined(__cplusplus)
}
#endif

#endif
