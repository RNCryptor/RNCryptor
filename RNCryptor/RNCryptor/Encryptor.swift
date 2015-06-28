//
//  Encryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

public final class Encryptor: DataSinkType {
    // Sink chain is Cryptor -> Tee -> HMAC
    //                              -> Sink

    private let sink: DataSinkType

    // There is no default value for these, they have to be var! in order to throw in init()
    private var cryptor: Cryptor
    private var hmacSink: HMACSink

    private var header: [UInt8]?

    // Expose IV internally for testing
    internal init(encryptionKey: [UInt8], HMACKey: [UInt8], IV: [UInt8], sink: DataSinkType) {
        self.sink = sink

        self.hmacSink = HMACSink(key: HMACKey)
        let tee = TeeSink(self.hmacSink, sink)

        self.cryptor = Cryptor(operation: CCOperation(kCCEncrypt), key: encryptionKey, IV: IV, sink: tee)

        self.header = [UInt8]()
        self.header?.extend([Version, UInt8(0)])  // FIXME: Refactor to support password option
        self.header?.extend(IV)
    }

    public convenience init(encryptionKey: [UInt8], HMACKey: [UInt8], sink: DataSinkType) {
        self.init(encryptionKey: encryptionKey, HMACKey: HMACKey, IV: randomDataOfLength(IVSize), sink: sink)
    }

    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        if let header = self.header {
            try header.withUnsafeBufferPointer { buf -> Void in
                try self.sink.put(buf)
                try self.hmacSink.put(buf)
            }
            self.header = nil
        }

        try self.cryptor.put(data) // Cryptor -> HMAC -> sink
    }

    public func finish() throws {
        try self.cryptor.finish()
        try self.sink.put(self.hmacSink.final())
    }
}
