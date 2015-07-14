//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

final class DecryptorV3: DecryptorType {
    // Buffer -> Tee -> HMAC
    //               -> Cryptor -> Sink

    private let bufferSink: BufferWriter
    private let hmacSink: HMACWriter
    private let engine: Engine

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: [UInt8], hmacKey: [UInt8], iv: [UInt8], header: [UInt8]) {
        self.pendingHeader = header

        self.engine = Engine(operation: .Decrypt, key: encryptionKey, iv: iv)
        self.hmacSink = HMACWriter(key: hmacKey)
        self.bufferSink = BufferWriter(capacity: RNCryptorV3.hmacSize)
    }

    convenience init?(password: String, header: [UInt8]) {
        guard password != "" &&
            header.count == RNCryptorV3.passwordHeaderSize &&
            header[0] == RNCryptorV3.version &&
            header[1] == 1
            else {
                // Shouldn't have to set these, but Swift 2 requires it
                self.init(encryptionKey: [], hmacKey: [], iv: [], header: [])
                return nil
        }

        let encryptionSalt = Array(header[2...9])
        let hmacSalt = Array(header[10...17])
        let iv = Array(header[18...33])

        let encryptionKey = RNCryptorV3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = RNCryptorV3.keyForPassword(password, salt: hmacSalt)

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    convenience init?(encryptionKey: [UInt8], hmacKey: [UInt8], header: [UInt8]) {
        guard encryptionKey.count == RNCryptorV3.keySize &&
            hmacKey.count == RNCryptorV3.keySize &&
            header.count == RNCryptorV3.keyHeaderSize &&
            header[0] == RNCryptorV3.version &&
            header[1] == 0
            else {
                // Shouldn't have to set these, but Swift 2 requires it
                self.init(encryptionKey: [], hmacKey: [], iv: [], header: [])
                return nil
        }

        let iv = Array(header[2..<18])
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    func update(data: [UInt8]) throws -> [UInt8] {
        if let pendingHeader = self.pendingHeader {
            self.hmacSink.update(pendingHeader)
            self.pendingHeader = nil
        }
        let overflow = bufferSink.update(data)
        self.hmacSink.update(overflow)
        let decrypted = try self.engine.update(overflow)

        return decrypted
    }

    func final() throws -> [UInt8] {
        let data = try self.engine.final()
        let hash = self.hmacSink.final()
        if hash != self.bufferSink.array {
            throw Error.HMACMismatch
        }
        return data
    }
}