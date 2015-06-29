//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

private protocol KeyDecryptorType: DataSinkType {
    init?(encryptionKey: [UInt8], hmacKey: [UInt8], header: [UInt8], sink: DataSinkType)
    func finish() throws
}

public final class KeyDecryptor: DataSinkType {
    private static let decryptors = [KeyDecryptorV3.self]
    static let maxHeaderLength: Int = { decryptors.reduce(0) { max($0, $1.headerLength) } }()

    private let encryptionKey: [UInt8]
    private let hmacKey: [UInt8]
    private let sink: DataSinkType

    private var buffer: [UInt8] = []

    private var decryptor: KeyDecryptorType?

    init(encryptionKey: [UInt8], hmacKey: [UInt8], sink: DataSinkType) {
        assert(encryptionKey.count == KeySize)
        assert(hmacKey.count == KeySize)

        self.encryptionKey = encryptionKey
        self.hmacKey = hmacKey
        self.sink = sink
    }

    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        if let decryptor = self.decryptor {
            try decryptor.put(data)
        } else {
            let maxHeaderLength = self.dynamicType.maxHeaderLength
            guard self.buffer.count + data.count >= maxHeaderLength else {
                self.buffer.extend(data)
                return
            }

            for decryptorType in self.dynamicType.decryptors {
                let (dataHeader, content) = data.splitAt(decryptorType.headerLength - self.buffer.count)
                let header = self.buffer + dataHeader
                if let decryptor = decryptorType.init(encryptionKey: self.encryptionKey, hmacKey: self.hmacKey, header: header, sink: self.sink) {
                    self.decryptor = decryptor
                    self.buffer.removeAll()
                    try self.decryptor?.put(content)
                    return
                }
            }
            throw Error.UnknownHeader
        }
    }
    func finish() throws {
        try self.decryptor?.finish()
    }
}

private final class KeyDecryptorV3: DataSinkType, KeyDecryptorType {
    // Buffer -> Tee -> HMAC
    //               -> Cryptor -> Sink

    static let version = UInt8(3)
    static let options = UInt8(0)
    static let headerLength: Int = sizeofValue(version) + sizeofValue(options) + IVSize

    private var bufferSink: BufferSink
    private var hmacSink: HMACSink
    private var cryptor: Cryptor
    private var pendingHeader: [UInt8]?

    init?(encryptionKey: [UInt8], hmacKey: [UInt8], header: [UInt8], sink: DataSinkType) {
        guard encryptionKey.count == KeySize &&
            hmacKey.count == KeySize &&
            header.count == KeyDecryptorV3.headerLength &&
            header[0] == KeyDecryptorV3.version &&
            header[1] == KeyDecryptorV3.options
            else {
                // Shouldn't have to set these, but Swift 2 requires it
                self.bufferSink = BufferSink(capacity: 0, sink: NullSink())
                self.hmacSink = HMACSink(key: [])
                self.cryptor = Cryptor(operation: CCOperation(kCCDecrypt), key: [], IV: [], sink: NullSink())
                return nil
        }

        self.pendingHeader = header

        let iv = Array(header[2..<18])
        self.cryptor = Cryptor(operation: CCOperation(kCCDecrypt), key: encryptionKey, IV: iv, sink: sink)
        self.hmacSink = HMACSink(key: hmacKey)
        let teeSink = TeeSink(self.cryptor, self.hmacSink)
        self.bufferSink = BufferSink(capacity: HMACSize, sink: teeSink)
    }

    func put(data: UnsafeBufferPointer<UInt8>) throws {
        if let pendingHeader = self.pendingHeader {
            try self.hmacSink.put(pendingHeader)
            self.pendingHeader = nil
        }
        try bufferSink.put(data) // Cryptor -> HMAC -> sink
    }

    func finish() throws {
        try self.cryptor.finish()
        let hash = self.hmacSink.final()
        if hash != self.bufferSink.array {
            throw Error.HMACMismatch
        }
    }
}