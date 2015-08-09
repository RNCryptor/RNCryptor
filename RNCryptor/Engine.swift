//
//  Cryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation
import CommonCrypto

public enum CryptorOperation: CCOperation {
    case Encrypt = 0 // CCOperation(kCCEncrypt)
    case Decrypt = 1 // CCOperation(kCCDecrypt)
}

internal final class Engine {
    private let cryptor: CCCryptorRef

    init(operation: CryptorOperation, key: [UInt8], iv: [UInt8]) {
        var cryptorOut = CCCryptorRef()
        let result = CCCryptorCreate(
            operation.rawValue,
            CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
            key, key.count,
            iv,
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

    // FIXME: Convert to "withUnsafeBufferPointer" style. Take a closure that handles the result.
    //        That way we can keep using the same buffer, and don't have to return anything.
    @warn_unused_result
    func update(data: [UInt8]) -> [UInt8] {
        let outputLength = CCCryptorGetOutputLength(self.cryptor, data.count, false)
        var output = Array<UInt8>(count: outputLength, repeatedValue: 0)
        var dataOutMoved: Int = 0

        var result: CCCryptorStatus = CCCryptorStatus(kCCUnimplemented)

        data.withUnsafeBufferPointer { buf in
         result = CCCryptorUpdate(
            self.cryptor,
            buf.baseAddress, buf.count,
            &output, outputLength,
            &dataOutMoved)
        }

        // The only error returned by CCCryptorUpdate is kCCBufferTooSmall, which would be a programming error
        assert(result == CCCryptorStatus(kCCSuccess))

        output.replaceRange(dataOutMoved..<output.endIndex, with:[])
        return output
    }

    @warn_unused_result
    func final() throws -> [UInt8] {
        let outputLength = CCCryptorGetOutputLength(self.cryptor, 0, true)
        var output = Array<UInt8>(count: outputLength, repeatedValue: 0)
        var dataOutMoved: Int = 0
        try checkResult(
            CCCryptorFinal(
                self.cryptor,
                &output, outputLength,
                &dataOutMoved
            )
        )

        output.replaceRange(dataOutMoved..<output.endIndex, with:[])
        return output
    }
}