//
//  Encryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto


public final class EncryptorV3 {
    // There is no default value for these, they have to be var! in order to throw in init()
    private var engine: Engine
    private var hmacSink: HMACWriter

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, iv: RNCryptorV3IV, header: [UInt8]) {
        self.hmacSink = HMACWriter(key: hmacKey.bytes)
        self.engine = try! Engine(operation: .Encrypt, key: encryptionKey.bytes, iv: iv.bytes) // It is an internal error for this to fail
        self.pendingHeader = header
    }

    // Expose random numbers for testing
    internal convenience init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, iv: RNCryptorV3IV) {
        let header = [UInt8]([RNCryptorV3.version, UInt8(0)]) + iv.bytes
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key) {
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: RNCryptorV3IV(randomDataOfLength(RNCryptorV3.ivSize))!)
    }

    // Expose random numbers for testing
    internal convenience init(password: String, encryptionSalt: RNCryptorV3Salt, hmacSalt: RNCryptorV3Salt, iv: RNCryptorV3IV) {
        let encryptionKey = RNCryptorV3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = RNCryptorV3.keyForPassword(password, salt: hmacSalt)
        let header = [UInt8]([RNCryptorV3.version, UInt8(1)]) + encryptionSalt.bytes + hmacSalt.bytes + iv.bytes
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(password: String) {
        self.init(
            password: password,
            encryptionSalt: RNCryptorV3Salt(randomDataOfLength(RNCryptorV3.saltSize))!,
            hmacSalt:RNCryptorV3Salt(randomDataOfLength(RNCryptorV3.saltSize))!,
            iv: RNCryptorV3IV(randomDataOfLength(RNCryptorV3.ivSize))!)
    }

    @warn_unused_result
    public func update(data: [UInt8]) throws -> [UInt8] {
        var result = [UInt8]()
        if let header = self.pendingHeader {
            result = header
            self.pendingHeader = nil
        }

        result += try self.engine.update(data)
        self.hmacSink.update(result)
        return result
    }

    @warn_unused_result
    public func final() throws -> [UInt8] {
        var result = try self.engine.final()
        self.hmacSink.update(result)
        result += self.hmacSink.final()
        return result
    }
}
