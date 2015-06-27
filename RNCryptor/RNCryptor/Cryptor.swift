//
//  Cryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

public class Cryptor: DataSinkType {
    public var sink: DataSinkType

    private let cryptor: CCCryptorRef

    public init(operation: CCOperation, key: [UInt8], IV: [UInt8], sink: DataSinkType) throws {
        self.sink = sink

        do {
            var cryptorOut = CCCryptorRef()
            try checkResult(
                CCCryptorCreate(
                    operation,
                    CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
                    key, key.count,
                    IV,
                    &cryptorOut
                )
            )
            self.cryptor = cryptorOut
        } catch {
            self.cryptor = CCCryptorRef()
        }
    }

    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        let outputLength = CCCryptorGetOutputLength(self.cryptor, data.count, false)
        var output = Array<UInt8>(count: outputLength, repeatedValue: 0)  // FIXME: Reuse buffer
        var dataOutMoved: Int = 0
        try checkResult(CCCryptorUpdate(
            self.cryptor,
            data.baseAddress, data.count,
            &output, outputLength,
            &dataOutMoved))

        try output.withUnsafeBufferPointer {
            try self.sink.put(UnsafeBufferPointer(start: $0.baseAddress, count: dataOutMoved))
        }
    }

    public func finish() throws {
        let outputLength = CCCryptorGetOutputLength(self.cryptor, 0, true)
        var output = Array<UInt8>(count: outputLength, repeatedValue: 0) // FIXME: Reuse buffer
        var dataOutMoved: Int = 0
        try checkResult(
            CCCryptorFinal(
                self.cryptor,
                &output, outputLength,
                &dataOutMoved
            )
        )

        try output.withUnsafeBufferPointer {
            try self.sink.put(UnsafeBufferPointer(start: $0.baseAddress, count: dataOutMoved))
        }
    }
}