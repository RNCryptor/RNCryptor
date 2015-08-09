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
    private var buffer = [UInt8]()

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

    func sizeBufferForDataOfLength(length: Int) -> Int {
        let size = CCCryptorGetOutputLength(cryptor, length, true)
        let delta = size - buffer.count
        if delta > 0 {
            buffer += [UInt8](count: delta, repeatedValue:0)
        }
        return size
    }

    // FIXME: Convert to "withUnsafeBufferPointer" style. Take a closure that handles the result.
    //        That way we can keep using the same buffer, and don't have to return anything.
    func update(data: [UInt8], body: (UnsafeBufferPointer<UInt8>) throws -> Void) rethrows {
        let outputLength = sizeBufferForDataOfLength(data.count)
        var dataOutMoved: Int = 0

        var result: CCCryptorStatus = CCCryptorStatus(kCCUnimplemented)

        data.withUnsafeBufferPointer { buf in
            result = CCCryptorUpdate(
                self.cryptor,
                buf.baseAddress, buf.count,
                &buffer, outputLength,
                &dataOutMoved)
        }

        // The only error returned by CCCryptorUpdate is kCCBufferTooSmall, which would be a programming error
        assert(result == CCCryptorStatus(kCCSuccess))

        try body(UnsafeBufferPointer(start: buffer, count: dataOutMoved))
    }

    func final(body: (UnsafeBufferPointer<UInt8>) throws -> Void) throws {
        let outputLength = sizeBufferForDataOfLength(0)
        var dataOutMoved: Int = 0

        let result = CCCryptorFinal(
            self.cryptor,
            &buffer, outputLength,
            &dataOutMoved
        )
        
        guard result == CCCryptorStatus(kCCSuccess) else {
            throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
        }

        try body(UnsafeBufferPointer(start: buffer, count: dataOutMoved))
    }
}