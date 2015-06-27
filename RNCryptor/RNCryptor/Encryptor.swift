//
//  Encryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

public final class Encryptor: DataSinkType {
    private let sink: DataSinkType

    // There is no default value for these, they have to be var! in order to throw in init()
    private var cryptor: Cryptor!
    private var hmacSink: HMACSink!

    // Expose IV internally for testing
    internal init(encryptionKey: [UInt8], HMACKey: [UInt8], IV: [UInt8], sink: DataSinkType) throws {
        self.sink = sink

        self.hmacSink = try HMACSink(key: HMACKey, sink: sink)
        self.cryptor = try Cryptor(operation: CCOperation(kCCEncrypt), key: encryptionKey, IV: IV, sink: self.hmacSink)

        var header = [UInt8]()
        header.extend([Version, UInt8(0)])  // FIXME: Refactor to support password option
        header.extend(IV)

        try header.withUnsafeBufferPointer {
            try self.hmacSink.put($0)
        }
    }

    public convenience init(encryptionKey: [UInt8], HMACKey: [UInt8], sink: DataSinkType) throws {
        try self.init(encryptionKey: encryptionKey, HMACKey: HMACKey, IV: try randomDataOfLength(IVSize), sink: sink)
    }

    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        try self.cryptor.put(data)
    }

    public func finish() throws {
        try self.cryptor.finish()
        try self.sink.put(self.hmacSink.final())
    }
}
