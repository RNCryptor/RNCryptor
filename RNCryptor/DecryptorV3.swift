//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

final class DecryptorV3: DecryptorType {
    private let bufferSink: TruncatingBuffer
    private let hmacSink: HMACWriter
    private let engine: Engine

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, iv: RNCryptorV3IV, header: [UInt8]) {
        self.pendingHeader = header

        self.engine = try! Engine(operation: .Decrypt, key: encryptionKey.bytes, iv: iv.bytes) // It is a programming error for this to fail
        self.hmacSink = HMACWriter(key: hmacKey.bytes)
        self.bufferSink = TruncatingBuffer(capacity: RNCryptorV3.hmacSize)
    }

    convenience init?(password: String, header: [UInt8]) {
        guard password != "" &&
            header.count == RNCryptorV3.passwordHeaderSize &&
            header[0] == RNCryptorV3.version &&
            header[1] == 1
            else {
                return nil
        }

        let encryptionSalt = RNCryptorV3Salt(Array(header[2...9]))!
        let hmacSalt = RNCryptorV3Salt(Array(header[10...17]))!
        let iv = RNCryptorV3IV(Array(header[18...33]))!

        let encryptionKey = RNCryptorV3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = RNCryptorV3.keyForPassword(password, salt: hmacSalt)

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    convenience init?(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, header: [UInt8]) {
        guard 
            header.count == RNCryptorV3.keyHeaderSize &&
            header[0] == RNCryptorV3.version &&
            header[1] == 0
            else {
                return nil
        }

        let iv = RNCryptorV3IV(Array(header[2..<18]))!
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
        if hash != self.bufferSink.final() {
            throw Error.HMACMismatch
        }
        return data
    }
}