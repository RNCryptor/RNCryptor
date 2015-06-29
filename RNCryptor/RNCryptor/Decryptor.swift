//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

public final class KeyDecryptorV3: DataSinkType {
    // Buffer -> Tee -> HMAC
    //               -> Cryptor -> Sink

    static let version = UInt8(3)
    static let optionsSize = 1

    static var headerLength: Int { return sizeofValue(version) + optionsSize + IVSize }

    private let encryptionKey: [UInt8]
    private let hmacKey: [UInt8]

    private let sink: DataSinkType
    private var bufferSink: BufferSink?
    private var hmacSink: HMACSink?
    private var cryptor: Cryptor?
    private var expectedHMAC: [UInt8]?

    private var header: [UInt8] = []

    init(encryptionKey: [UInt8], hmacKey: [UInt8], sink: DataSinkType) {
        assert(encryptionKey.count == KeySize)
        assert(hmacKey.count == KeySize)
        
        self.encryptionKey = encryptionKey
        self.hmacKey = hmacKey
        self.sink = sink
    }

    public func put(var data: UnsafeBufferPointer<UInt8>) throws {
        if let bufferSink = self.bufferSink {
            try bufferSink.put(data) // Cryptor -> HMAC -> sink
        } else {
            let headerLength = self.dynamicType.headerLength
            if self.header.count + data.count >= headerLength {
                if headerLength > header.count {
                    let (h, d) = data.splitAt(headerLength-self.header.count)
                    self.header.extend(h)
                    data = d
                }
                assert(self.header.count == self.dynamicType.headerLength)
                guard header[0] == 3 else { throw Error.UnknownHeader }
                guard header[1] == 0 else { throw Error.ParameterError }
                let iv = Array(header[2..<18])

                self.cryptor = Cryptor(operation: CCOperation(kCCDecrypt), key: self.encryptionKey, IV: iv, sink: self.sink)
                self.hmacSink = HMACSink(key: self.hmacKey)

                let teeSink = TeeSink(self.cryptor!, self.hmacSink!)

                self.bufferSink = BufferSink(capacity: HMACSize, sink: teeSink)

                try self.hmacSink?.put(header)
                try self.bufferSink?.put(data)
            } else {
                self.header.extend(data)
            }
        }
    }

    func finish() throws {
        try self.cryptor?.finish()
        guard let hsink = self.hmacSink, bsink = self.bufferSink else { return }
        let hash = hsink.final()
        if hash != bsink.array {
//            throw Error.HMACMismatch
        }
    }
}