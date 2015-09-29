//
//  V3.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation
import CommonCrypto

private enum Credential {
    case Password(String)
    case Keys(encryptionKey: NSData, hmacKey: NSData)
}

public struct RNCryptorV3 {
    static public let version = UInt8(3)
    static public let keySize = kCCKeySizeAES256

    static let ivSize   = kCCBlockSizeAES128
    static let hmacSize = Int(CC_SHA256_DIGEST_LENGTH)
    static let saltSize = 8

    static let keyHeaderSize = 1 + 1 + kCCBlockSizeAES128
    static let passwordHeaderSize = 1 + 1 + 8 + 8 + kCCBlockSizeAES128

    static public func keyForPassword(password: String, salt: NSData) -> NSData {
        let derivedKey = NSMutableData(length: self.keySize)!
        let derivedKeyPtr = UnsafeMutablePointer<UInt8>(derivedKey.mutableBytes)

        let passwordData = password.dataUsingEncoding(NSUTF8StringEncoding)!
        let passwordPtr = UnsafePointer<Int8>(passwordData.bytes)

        let saltPtr = UnsafePointer<UInt8>(salt.bytes)

        // All the crazy casting because CommonCryptor hates Swift
        let algorithm     = CCPBKDFAlgorithm(kCCPBKDF2)
        let prf           = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        let pbkdf2Rounds  = UInt32(10000)

        let result = CCKeyDerivationPBKDF(
            algorithm,
            passwordPtr,   passwordData.length,
            saltPtr,       salt.length,
            prf,           pbkdf2Rounds,
            derivedKeyPtr, derivedKey.length)

        guard result == CCCryptorStatus(kCCSuccess) else {
            fatalError("SECURITY FAILURE: Could not derive secure password (\(result)): \(derivedKey).")
        }
        return derivedKey
    }
}

internal typealias V3 = RNCryptorV3

@objc(RNEncryptor)
public final class EncryptorV3 : NSObject, CryptorType {
    private var engine: Engine
    private var hmac: HMACV3

    private var pendingHeader: NSData?

    private init(encryptionKey: NSData, hmacKey: NSData, iv: NSData, header: NSData) {
        precondition(encryptionKey.length == V3.keySize)
        precondition(hmacKey.length == V3.keySize)
        precondition(iv.length == V3.ivSize)
        self.hmac = HMACV3(key: hmacKey)
        self.engine = Engine(operation: .Encrypt, key: encryptionKey, iv: iv)
        self.pendingHeader = header
    }

    // Expose random numbers for testing
    internal convenience init(encryptionKey: NSData, hmacKey: NSData, iv: NSData) {
        let preamble = [V3.version, UInt8(0)]
        let header = NSMutableData(bytes: preamble, length: preamble.count)
        header.appendData(iv)
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(encryptionKey: NSData, hmacKey: NSData) {
        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: randomDataOfLength(V3.ivSize))
    }

    // Expose random numbers for testing
    internal convenience init(password: String, encryptionSalt: NSData, hmacSalt: NSData, iv: NSData) {
        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

        // TODO: This chained-+ is very slow to compile in Swift 2b5 (http://www.openradar.me/21842206)
        // let header = [V3.version, UInt8(1)] + encryptionSalt + hmacSalt + iv
        let preamble = [V3.version, UInt8(1)]
        let header = NSMutableData(bytes: preamble, length: preamble.count)
        header.appendData(encryptionSalt)
        header.appendData(hmacSalt)
        header.appendData(iv)

        self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public convenience init(password: String) {
        self.init(
            password: password,
            encryptionSalt: randomDataOfLength(V3.saltSize),
            hmacSalt: randomDataOfLength(V3.saltSize),
            iv: randomDataOfLength(V3.ivSize))
    }

    public func encrypt(data: NSData) -> NSData {
        return try! oneshot(data)
    }

    private func handle(data: NSData) -> NSData {
        var result: NSData
        if let ph = pendingHeader {
            let accum = NSMutableData(data: ph)
            pendingHeader = nil
            accum.appendData(data)
            result = accum
        } else {
            result = data
        }
        hmac.update(result)
        return result
    }

    public func update(data: NSData) -> NSData {
        // It should not be possible for this to fail during encryption
        return try! handle(engine.update(data))
    }

    public func final() -> NSData {
        let result = NSMutableData(data: try! handle(engine.final()))
        result.appendData(self.hmac.final())
        return result
    }
}

public final class DecryptorV3: PasswordDecryptorType {
    static let preambleSize = 1
    static func canDecrypt(preamble: NSData) -> Bool {
        assert(preamble.length == 1)
        return preamble.bytesView[0] == 3
    }

    var requiredHeaderSize: Int {
        switch credential {
        case .Password(_): return V3.passwordHeaderSize
        case .Keys(_, _): return V3.keyHeaderSize
        }
    }

    private var buffer = NSMutableData()
    private var decryptorEngine: DecryptorEngineV3?
    private let credential: Credential

    public init(password: String) {
        credential = .Password(password)
    }

    public init(encryptionKey: NSData, hmacKey: NSData) {
        precondition(encryptionKey.length == V3.keySize)
        precondition(hmacKey.length == V3.hmacSize)
        credential = .Keys(encryptionKey: encryptionKey, hmacKey: hmacKey)
    }

    public func decrypt(data: NSData) throws -> NSData {
        return try oneshot(data)
    }

    public func update(data: NSData) throws -> NSData {
        if let e = decryptorEngine {
            return try e.update(data)
        }

        buffer.appendData(data)
        guard buffer.length >= requiredHeaderSize else {
            return NSData()
        }

        let e = try createEngineWithCredential(credential, header: buffer.bytesView[0..<requiredHeaderSize])
        decryptorEngine = e
        let body = buffer.bytesView[requiredHeaderSize..<buffer.length]
        buffer.length = 0
        return try e.update(body)
    }

    private func createEngineWithCredential(credential: Credential, header: NSData) throws -> DecryptorEngineV3 {
        switch credential {
        case let .Password(password):
            return try createEngineWithPassword(password, header: header)
        case let .Keys(encryptionKey, hmacKey):
            return try createEngineWithKeys(encryptionKey: encryptionKey, hmacKey: hmacKey, header: header)
        }
    }

    private func createEngineWithPassword(password: String, header: NSData) throws -> DecryptorEngineV3 {
        assert(password != "")
        precondition(header.length == V3.passwordHeaderSize)
        precondition(header.bytesView[0] == V3.version)

        guard header.bytesView[1] == 1 else {
            throw Error.InvalidCredentialType
        }

        let encryptionSalt = header.bytesView[2...9]
        let hmacSalt = header.bytesView[10...17]
        let iv = header.bytesView[18...33]

        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

        return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    private func createEngineWithKeys(encryptionKey encryptionKey: NSData, hmacKey: NSData, header: NSData) throws -> DecryptorEngineV3 {
        precondition(header.length == V3.keyHeaderSize)
        precondition(header.bytesView[0] == V3.version)
        precondition(encryptionKey.length == V3.keySize)
        precondition(hmacKey.length == V3.keySize)

        let iv = header.bytesView[2..<18]
        return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    public func final() throws -> NSData {
        guard let result = try decryptorEngine?.final() else {
            throw Error.MessageTooShort
        }
        return result
    }
}

private final class DecryptorEngineV3: CryptorType {
    private let buffer = OverflowingBuffer(capacity: V3.hmacSize)
    private var hmac: HMACV3
    private var engine: Engine

    init(encryptionKey: NSData, hmacKey: NSData, iv: NSData, header: NSData) {
        precondition(encryptionKey.length == V3.keySize)
        precondition(hmacKey.length == V3.hmacSize)
        precondition(iv.length == V3.ivSize)

        hmac = HMACV3(key: hmacKey)
        hmac.update(header)
        engine = Engine(operation: .Decrypt, key: encryptionKey, iv: iv)
    }

    func update(data: NSData) throws -> NSData {
        let overflow = buffer.update(data)
        self.hmac.update(overflow)
        return try engine.update(overflow)
    }

    func final() throws -> NSData {
        let result = try engine.final()
        let hash = hmac.final()
        if !isEqualInConsistentTime(trusted: hash, untrusted: self.buffer.final()) {
            throw Error.HMACMismatch
        }
        return result
    }
}

private final class HMACV3 {
    var context: CCHmacContext = CCHmacContext()

    init(key: NSData) {
        CCHmacInit(
            &self.context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key.bytes,
            key.length
        )
    }

    func update(data: NSData) {
        CCHmacUpdate(&self.context, data.bytes, data.length)
    }
    
    func final() -> NSData {
        let hmac = NSMutableData(length: V3.hmacSize)!
        CCHmacFinal(&self.context, hmac.mutableBytes)
        return hmac
    }
}
