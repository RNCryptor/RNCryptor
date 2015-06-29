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

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: [UInt8], HMACKey: [UInt8], IV: [UInt8], header: [UInt8], sink: DataSinkType) {
        self.sink = sink
        self.hmacSink = HMACSink(key: HMACKey)
        let tee = TeeSink(self.hmacSink, sink)
        self.cryptor = Cryptor(operation: .Encrypt, key: encryptionKey, IV: IV, sink: tee)
        self.pendingHeader = header
    }

    // Expose random numbers for testing
    internal convenience init(encryptionKey: [UInt8], HMACKey: [UInt8], IV: [UInt8], sink: DataSinkType) {
        var header = [UInt8]()
        header.extend([V3.version, UInt8(0)])
        header.extend(IV)
        self.init(encryptionKey: encryptionKey, HMACKey: HMACKey, IV: IV, header: header, sink: sink)
    }

    public convenience init(encryptionKey: [UInt8], HMACKey: [UInt8], sink: DataSinkType) {
        self.init(encryptionKey: encryptionKey, HMACKey: HMACKey, IV: randomDataOfLength(V3.ivSize), sink: sink)
    }

    // Expose random numbers for testing
    internal convenience init(password: String, encryptionSalt: [UInt8], hmacSalt: [UInt8], iv: [UInt8], sink: DataSinkType) {
        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)
        var header = [UInt8]()
        header.extend([V3.version, UInt8(1)])
        header.extend(encryptionSalt)
        header.extend(hmacSalt)
        header.extend(iv)
        self.init(encryptionKey: encryptionKey, HMACKey: hmacKey, IV: iv, header: header, sink: sink)
    }

    public convenience init(password: String, sink: DataSinkType) {
        self.init(
            password: password,
            encryptionSalt: randomDataOfLength(V3.saltSize),
            hmacSalt:randomDataOfLength(V3.saltSize),
            iv: randomDataOfLength(V3.ivSize),
            sink: sink)
    }

    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        if let header = self.pendingHeader {
            try header.withUnsafeBufferPointer { buf -> Void in
                try self.sink.put(buf)
                try self.hmacSink.put(buf)
            }
            self.pendingHeader = nil
        }

        try self.cryptor.put(data) // Cryptor -> HMAC -> sink
    }

    public func finish() throws {
        try self.cryptor.finish()
        try self.sink.put(self.hmacSink.final())
    }
}
