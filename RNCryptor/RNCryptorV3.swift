//
//  V3.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

public struct _RNCryptorV3: Equatable {
    public let version = UInt8(3)

    public let keySize = kCCKeySizeAES256
    let ivSize   = kCCBlockSizeAES128
    let hmacSize = Int(CC_SHA256_DIGEST_LENGTH)
    let saltSize = 8

    let keyHeaderSize = 1 + 1 + kCCBlockSizeAES128
    let passwordHeaderSize = 1 + 1 + 8 + 8 + kCCBlockSizeAES128

    public func keyForPassword(password: String, salt: [UInt8]) -> [UInt8] {
        var derivedKey = [UInt8](count: self.keySize, repeatedValue: 0)

        // utf8 returns [UInt8], but CCKeyDerivationPBKDF takes [Int8]
        let passwordData = [UInt8](password.utf8)
        let passwordPtr  = UnsafePointer<Int8>(passwordData)

        // All the crazy casting because CommonCryptor hates Swift
        let algorithm     = CCPBKDFAlgorithm(kCCPBKDF2)
        let prf           = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        let pbkdf2Rounds  = UInt32(10000)

        let result = CCKeyDerivationPBKDF(
            algorithm,
            passwordPtr, passwordData.count,
            salt,        salt.count,
            prf,         pbkdf2Rounds,
            &derivedKey, derivedKey.count)

        guard result == CCCryptorStatus(kCCSuccess) else {
            fatalError("SECURITY FAILURE: Could not derive secure password (\(result)): \(derivedKey).")
        }
        return derivedKey
    }
    private init() {} // no one else may create one
}

public let RNCryptorV3 = _RNCryptorV3()
internal let V3 = RNCryptorV3

public func ==(lhs: _RNCryptorV3, rhs: _RNCryptorV3) -> Bool {
    return true // It's constant
}

public final class EncryptorV3 {
    private var engine: Engine
    private var hmac: HMACV3

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: [UInt8], hmacKey: [UInt8], iv: [UInt8], header: [UInt8]) {
        precondition(encryptionKey.count == V3.keySize)
        precondition(hmacKey.count == V3.keySize)
        precondition(iv.count == V3.ivSize)
        self.hmac = HMACV3(key: hmacKey)
        self.engine = Engine(operation: .Encrypt, key: encryptionKey, iv: iv)
        self.pendingHeader = header
    }

    // Expose random numbers for testing
    internal convenience init(encryptionKey: [UInt8], hmacKey: [UInt8], iv: [UInt8]) {
        let header = [V3.version, UInt8(0)] + iv
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(encryptionKey: [UInt8], hmacKey: [UInt8]) {
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: randomDataOfLength(V3.ivSize))
    }

    // Expose random numbers for testing
    internal convenience init(password: String, encryptionSalt: [UInt8], hmacSalt: [UInt8], iv: [UInt8]) {
        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

        // TODO: This chained-+ is very slow to compile in Swift 2b5 (http://www.openradar.me/21842206)
        // let header = [V3.version, UInt8(1)] + encryptionSalt + hmacSalt + iv
        var header = [V3.version, UInt8(1)]
        header += encryptionSalt
        header += hmacSalt
        header += iv

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(password: String) {
        self.init(
            password: password,
            encryptionSalt: randomDataOfLength(V3.saltSize),
            hmacSalt: randomDataOfLength(V3.saltSize),
            iv: randomDataOfLength(V3.ivSize))
    }

    @warn_unused_result
    public func update(data: [UInt8]) -> [UInt8] {
        var result = [UInt8]()
        if let header = self.pendingHeader {
            result = header
            self.pendingHeader = nil
        }

        result += self.engine.update(data)
        self.hmac.update(result)
        return result
    }

    @warn_unused_result
    public func final() throws -> [UInt8] {
        var result = try self.engine.final()
        self.hmac.update(result)
        result += self.hmac.final()
        return result
    }
}

final class DecryptorV3: DecryptorType {
    private let buffer: TruncatingBuffer
    private let hmac: HMACV3
    private let engine: Engine

    private init(encryptionKey: [UInt8], hmacKey: [UInt8], iv: [UInt8], header: [UInt8]) {
        precondition(encryptionKey.count == V3.keySize)
        precondition(hmacKey.count == V3.hmacSize)
        precondition(iv.count == V3.ivSize)

        self.hmac = HMACV3(key: hmacKey)
        self.hmac.update(header)
        self.buffer = TruncatingBuffer(capacity: V3.hmacSize)
        self.engine = Engine(operation: .Decrypt, key: encryptionKey, iv: iv)
    }

    convenience internal init?(password: String, header: [UInt8]) {
        guard
            password != "" &&
                header.count == V3.passwordHeaderSize &&
                header[0] == V3.version &&
                header[1] == 1
            else {
                return nil
        }

        let encryptionSalt = Array(header[2...9])
        let hmacSalt = Array(header[10...17])
        let iv = Array(header[18...33])

        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    convenience internal init?(encryptionKey: [UInt8], hmacKey: [UInt8], header: [UInt8]) {
        guard
            header.count == V3.keyHeaderSize &&
                header[0] == V3.version &&
                header[1] == 0 &&
                encryptionKey.count == V3.keySize &&
                hmacKey.count == V3.keySize
            else {
                return nil
        }

        let iv = Array(header[2..<18])
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    func update(data: [UInt8]) throws -> [UInt8] {
        let overflow = buffer.update(data)
        self.hmac.update(overflow)
        return self.engine.update(overflow)
    }

    func final() throws -> [UInt8] {
        let data = try self.engine.final()
        let hash = self.hmac.final()
        if !isEqualInConsistentTime(trusted: hash, untrusted: self.buffer.final()) {
            throw Error.HMACMismatch
        }
        return data
    }
}

private final class HMACV3 {
    var context: CCHmacContext = CCHmacContext()

    init(key: [UInt8]) {
        CCHmacInit(
            &self.context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key,
            key.count
        )
    }

    func update(data: [UInt8]) {
        data.withUnsafeBufferPointer { buf in
            CCHmacUpdate(&self.context, buf.baseAddress, buf.count)
        }
    }
    
    func final() -> [UInt8] {
        var hmac = [UInt8](count: V3.hmacSize, repeatedValue: 0)
        CCHmacFinal(&self.context, &hmac)
        return hmac
    }
}
