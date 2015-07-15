//
//  V3.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

private typealias Key = RNCryptorV3Key
private typealias IV = RNCryptorV3IV
private typealias Salt = RNCryptorV3Salt

public struct _RNCryptorV3: Equatable {
    public let version = UInt8(3)

    public let keySize  = kCCKeySizeAES256
    let ivSize   = kCCBlockSizeAES128
    let hmacSize = Int(CC_SHA256_DIGEST_LENGTH)
    let saltSize = 8

    let keyHeaderSize = 1 + 1 + kCCBlockSizeAES128
    let passwordHeaderSize = 1 + 1 + 8 + 8 + kCCBlockSizeAES128

    public func keyForPassword(password: String, salt: RNCryptorV3Salt) -> RNCryptorV3Key {
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
            salt.bytes,  salt.bytes.count,
            prf,         pbkdf2Rounds,
            &derivedKey, derivedKey.count)

        guard
            result == CCCryptorStatus(kCCSuccess),
            let key = Key(derivedKey) else {
                fatalError("SECURITY FAILURE: Could not derive secure password (\(result)): \(derivedKey).")
        }
        return key
    }
    private init() {} // no one else may create one
}

public let RNCryptorV3 = _RNCryptorV3()
internal let V3 = RNCryptorV3

public func ==(lhs: _RNCryptorV3, rhs: _RNCryptorV3) -> Bool {
    return true // It's constant
}

public protocol FixedSizeByteArray: Equatable, CustomStringConvertible {
    var bytes: [UInt8] { get }
    static var count: Int { get }
    init()
    init?(_ bytes: [UInt8])
}

extension FixedSizeByteArray {
    static func random() -> Self {
        return self.init()
    }
}

extension FixedSizeByteArray {
    public var description: String { return self.bytes.description }
    init?<Seq: SequenceType where Seq.Generator.Element == UInt8>(_ bytes: Seq) {
        self.init(Array(bytes))
    }
}

public func ==<T: FixedSizeByteArray>(lhs: T, rhs: T) -> Bool {
    return lhs.bytes == rhs.bytes
}

public struct RNCryptorV3Key: FixedSizeByteArray {
    public static let count = RNCryptorV3.keySize
    public let bytes: [UInt8]
    public init() { bytes = randomDataOfLength(self.dynamicType.count) }
    public init?(_ bytes: [UInt8]) {
        guard bytes.count == self.dynamicType.count else { return nil }
        self.bytes = bytes
    }
}

internal struct RNCryptorV3IV: FixedSizeByteArray {
    static let count = RNCryptorV3.ivSize
    let bytes: [UInt8]
    init() { bytes = randomDataOfLength(self.dynamicType.count) }
    init?(_ bytes: [UInt8]) {
        guard bytes.count == self.dynamicType.count else { return nil }
        self.bytes = bytes
    }
}

public struct RNCryptorV3Salt: FixedSizeByteArray {
    public static let count = RNCryptorV3.saltSize
    public let bytes: [UInt8]
    public init() { bytes = randomDataOfLength(self.dynamicType.count) }
    public init?(_ bytes: [UInt8]) {
        guard bytes.count == self.dynamicType.count else { return nil }
        self.bytes = bytes
    }
}

public final class EncryptorV3 {
    private var engine: Engine
    private var hmac: HMACV3

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, iv: RNCryptorV3IV, header: [UInt8]) {
        self.hmac = HMACV3(key: hmacKey.bytes)
        self.engine = try! Engine(operation: .Encrypt, key: encryptionKey.bytes, iv: iv.bytes) // It is an internal error for this to fail
        self.pendingHeader = header
    }

    // Expose random numbers for testing
    internal convenience init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, iv: RNCryptorV3IV) {
        let header = [UInt8]([V3.version, UInt8(0)]) + iv.bytes
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key) {
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: IV.random())
    }

    // Expose random numbers for testing
    internal convenience init(password: String, encryptionSalt: RNCryptorV3Salt, hmacSalt: RNCryptorV3Salt, iv: RNCryptorV3IV) {
        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)
        let header = [V3.version, UInt8(1)] + encryptionSalt.bytes + hmacSalt.bytes + iv.bytes
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(password: String) {
        self.init(
            password: password,
            encryptionSalt: Salt.random(),
            hmacSalt: Salt.random(),
            iv: IV.random())
    }

    @warn_unused_result
    public func update(data: [UInt8]) throws -> [UInt8] {
        var result = [UInt8]()
        if let header = self.pendingHeader {
            result = header
            self.pendingHeader = nil
        }

        result += try self.engine.update(data)
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

    private var pendingHeader: [UInt8]?

    private init(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, iv: RNCryptorV3IV, header: [UInt8]) {
        self.pendingHeader = header

        self.engine = try! Engine(operation: .Decrypt, key: encryptionKey.bytes, iv: iv.bytes) // It is a programming error for this to fail
        self.hmac = HMACV3(key: hmacKey.bytes)
        self.buffer = TruncatingBuffer(capacity: V3.hmacSize)
    }

    convenience init?(password: String, header: [UInt8]) {
        guard password != "" &&
            header.count == V3.passwordHeaderSize &&
            header[0] == V3.version &&
            header[1] == 1
            else {
                return nil
        }

        let encryptionSalt = Salt(header[2...9])!
        let hmacSalt = Salt(header[10...17])!
        let iv = IV(header[18...33])!

        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    convenience init?(encryptionKey: RNCryptorV3Key, hmacKey: RNCryptorV3Key, header: [UInt8]) {
        guard
            header.count == V3.keyHeaderSize &&
                header[0] == V3.version &&
                header[1] == 0
            else {
                return nil
        }

        let iv = IV(header[2..<18])!
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    func update(data: [UInt8]) throws -> [UInt8] {
        if let pendingHeader = self.pendingHeader {
            self.hmac.update(pendingHeader)
            self.pendingHeader = nil
        }
        let overflow = buffer.update(data)
        self.hmac.update(overflow)
        let decrypted = try self.engine.update(overflow)

        return decrypted
    }

    func final() throws -> [UInt8] {
        let data = try self.engine.final()
        let hash = self.hmac.final()
        if hash != self.buffer.final() {
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
