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

internal class Engine {
    private let cryptor: CCCryptorRef
    var error: NSError?

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
        if result != CCCryptorStatus(kCCSuccess) {
            assertionFailure("Failed to create CCCryptor")
            self.error = NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
        }
    }

    @warn_unused_result
    func update(data: [UInt8]) throws -> [UInt8] {
        if let err = self.error {
            throw err
        }

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
        try checkResult(result)
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