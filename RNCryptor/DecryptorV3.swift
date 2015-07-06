//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

final class DecryptorV3: Writable, DecryptorType {
    // Buffer -> Tee -> HMAC
    //               -> Cryptor -> Sink

    private let bufferSink: BufferWriter
    private let hmacSink: HMACWriter
    private let engine: Engine

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: [UInt8], hmacKey: [UInt8], iv: [UInt8], header: [UInt8], sink: Writable) {
        self.pendingHeader = header

        self.engine = Engine(operation: .Decrypt, key: encryptionKey, iv: iv, sink: sink)
        self.hmacSink = HMACWriter(key: hmacKey)
        let teeSink = TeeWriter(self.engine, self.hmacSink)
        self.bufferSink = BufferWriter(capacity: RNCryptorV3.hmacSize, sink: teeSink)
    }

    convenience init?(password: String, header: [UInt8], sink: Writable) {
        guard password != "" &&
            header.count == RNCryptorV3.passwordHeaderSize &&
            header[0] == RNCryptorV3.version &&
            header[1] == 1
            else {
                // Shouldn't have to set these, but Swift 2 requires it
                self.init(encryptionKey: [], hmacKey: [], iv: [], header: [], sink: sink)
                return nil
        }

        let encryptionSalt = Array(header[2...9])
        let hmacSalt = Array(header[10...17])
        let iv = Array(header[18...33])

        let encryptionKey = RNCryptorV3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = RNCryptorV3.keyForPassword(password, salt: hmacSalt)

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header, sink: sink)
    }

    convenience init?(encryptionKey: [UInt8], hmacKey: [UInt8], header: [UInt8], sink: Writable) {
        guard encryptionKey.count == RNCryptorV3.keySize &&
            hmacKey.count == RNCryptorV3.keySize &&
            header.count == RNCryptorV3.keyHeaderSize &&
            header[0] == RNCryptorV3.version &&
            header[1] == 0
            else {
                // Shouldn't have to set these, but Swift 2 requires it
                self.init(encryptionKey: [], hmacKey: [], iv: [], header: [], sink: sink)
                return nil
        }

        let iv = Array(header[2..<18])
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header, sink: sink)
    }

    func write(data: UnsafeBufferPointer<UInt8>) throws {
        if let pendingHeader = self.pendingHeader {
            try self.hmacSink.write(pendingHeader)
            self.pendingHeader = nil
        }
        try bufferSink.write(data) // Cryptor -> HMAC -> sink
    }

    func finish() throws {
        try self.engine.finish()
        let hash = self.hmacSink.final()
        if hash != self.bufferSink.array {
            throw Error.HMACMismatch
        }
    }
}