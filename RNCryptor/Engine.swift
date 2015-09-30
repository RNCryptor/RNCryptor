//
//  Cryptor.swift
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

import Foundation
import CommonCrypto

private let CCErrorDomain = "com.apple.CommonCrypto"

internal enum CryptorOperation: CCOperation {
    case Encrypt = 0 // CCOperation(kCCEncrypt)
    case Decrypt = 1 // CCOperation(kCCDecrypt)
}

internal final class Engine {
    private let cryptor: CCCryptorRef
    private var buffer = NSMutableData()

    init(operation: CryptorOperation, key: NSData, iv: NSData) {
        var cryptorOut = CCCryptorRef()
        let result = CCCryptorCreate(
            operation.rawValue,
            CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
            key.bytes, key.length,
            iv.bytes,
            &cryptorOut
        )
        self.cryptor = cryptorOut

        // It is a programming error to create us with illegal values
        // This is an internal class, so we can constrain what is sent to us.
        // If this is ever made public, it should throw instead of asserting.
        assert(result == CCCryptorStatus(kCCSuccess))
    }

    deinit {
        if self.cryptor != CCCryptorRef() {
            CCCryptorRelease(self.cryptor)
        }
    }

    func sizeBufferForDataOfLength(length: Int) -> Int {
        let size = CCCryptorGetOutputLength(cryptor, length, true)
        buffer.length = size
        return size
    }

    func updateWithData(data: NSData) throws -> NSData {
        let outputLength = sizeBufferForDataOfLength(data.length)
        var dataOutMoved: Int = 0

        var result: CCCryptorStatus = CCCryptorStatus(kCCUnimplemented)

        result = CCCryptorUpdate(
            self.cryptor,
            data.bytes, data.length,
            buffer.mutableBytes, outputLength,
            &dataOutMoved)

        // The only error returned by CCCryptorUpdate is kCCBufferTooSmall, which would be a programming error
        assert(result == CCCryptorStatus(kCCSuccess))

        buffer.length = dataOutMoved
        return buffer
    }

    func finalData() throws -> NSData {
        let outputLength = sizeBufferForDataOfLength(0)
        var dataOutMoved: Int = 0

        let result = CCCryptorFinal(
            self.cryptor,
            buffer.mutableBytes, outputLength,
            &dataOutMoved
        )
        
        guard result == CCCryptorStatus(kCCSuccess) else {
            throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
        }

        buffer.length = dataOutMoved
        return buffer
    }
}