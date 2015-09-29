//
//  Cryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation
import CommonCrypto

private let CCErrorDomain = "com.apple.CommonCrypto"

internal enum CryptorOperation: CCOperation {
    case Encrypt = 0 // CCOperation(kCCEncrypt)
    case Decrypt = 1 // CCOperation(kCCDecrypt)
}

internal final class Engine: CryptorType {
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