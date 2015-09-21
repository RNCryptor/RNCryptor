//
//  V3.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

private enum Credential {
    case Password(String)
    case Keys(encryptionKey: [UInt8], hmacKey: [UInt8])
}

public struct RNCryptorV3 {
    static public let version = UInt8(3)
    static public let keySize = kCCKeySizeAES256

    static let ivSize   = kCCBlockSizeAES128
    static let hmacSize = Int(CC_SHA256_DIGEST_LENGTH)
    static let saltSize = 8

    static let keyHeaderSize = 1 + 1 + kCCBlockSizeAES128
    static let passwordHeaderSize = 1 + 1 + 8 + 8 + kCCBlockSizeAES128

    static public func keyForPassword(password: String, salt: [UInt8]) -> [UInt8] {
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
}

internal typealias V3 = RNCryptorV3

public final class EncryptorV3 : CryptorType {
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

    public func encrypt(data: [UInt8]) -> [UInt8] {
        return try! oneshot(data)
    }

    private func handle(data: [UInt8]) -> [UInt8] {
        var result: [UInt8]
        if let ph = pendingHeader {
            result = ph
            pendingHeader = nil
            result += data
        } else {
            result = data
        }
        hmac.update(result)
        return result
    }

    public func update(data: [UInt8]) -> [UInt8] {
        return data.withUnsafeBufferPointer {
            // It should not be possible for this to fail during encryption
            return try! handle(engine.update($0))
        }
    }

    public func final() -> [UInt8] {
        var result = try! handle(engine.final())
        result += self.hmac.final()
        return result
    }
}

public final class DecryptorV3: PasswordDecryptorType {
    static let preambleSize = 1
    static func canDecrypt(preamble: ArraySlice<UInt8>) -> Bool {
        assert(preamble.count == 1)
        return preamble[0] == 3
    }

    var requiredHeaderSize: Int {
        switch credential {
        case .Password(_): return V3.passwordHeaderSize
        case .Keys(_, _): return V3.keyHeaderSize
        }
    }

    private var buffer = [UInt8]()
    private var decryptorEngine: DecryptorEngineV3?
    private let credential: Credential

    public init(password: String) {
        credential = .Password(password)
    }

    public init(encryptionKey: [UInt8], hmacKey: [UInt8]) {
        precondition(encryptionKey.count == V3.keySize)
        precondition(hmacKey.count == V3.hmacSize)
        credential = .Keys(encryptionKey: encryptionKey, hmacKey: hmacKey)
    }

    public func decrypt(data: [UInt8]) throws -> [UInt8] {
        return try oneshot(data)
    }

    public func update(data: [UInt8]) throws -> [UInt8] {
        if let e = decryptorEngine {
            return try e.update(data)
        }

        buffer += data
        guard buffer.count >= requiredHeaderSize else {
            return []
        }

        let e = try createEngineWithCredential(credential, header: buffer[0..<requiredHeaderSize])
        decryptorEngine = e
        let body = buffer[requiredHeaderSize..<buffer.endIndex]
        buffer = []
        return try body.withUnsafeBufferPointer(e.update)
    }

    private func createEngineWithCredential(credential: Credential, header: ArraySlice<UInt8>) throws -> DecryptorEngineV3 {
        switch credential {
        case let .Password(password):
            return try createEngineWithPassword(password, header: header)
        case let .Keys(encryptionKey, hmacKey):
            return try createEngineWithKeys(encryptionKey: encryptionKey, hmacKey: hmacKey, header: header)
        }
    }

    private func createEngineWithPassword(password: String, header: ArraySlice<UInt8>) throws -> DecryptorEngineV3 {
        assert(password != "")
        precondition(header.count == V3.passwordHeaderSize)
        precondition(header[0] == V3.version)

        guard header[1] == 1 else {
            throw Error.InvalidCredentialType
        }

        let encryptionSalt = Array(header[2...9])
        let hmacSalt = Array(header[10...17])
        let iv = Array(header[18...33])

        let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

        return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }

    private func createEngineWithKeys(encryptionKey encryptionKey: [UInt8], hmacKey: [UInt8], header: ArraySlice<UInt8>) throws -> DecryptorEngineV3 {
        precondition(header.count == V3.keyHeaderSize)
        precondition(header[0] == V3.version)
        precondition(encryptionKey.count == V3.keySize)
        precondition(hmacKey.count == V3.keySize)

        let iv = Array(header[2..<18])
        return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
    }


    func final() throws -> [UInt8] {
        guard let result = try decryptorEngine?.final() else {
            throw Error.MessageTooShort
        }
        return result
    }
}

private final class DecryptorEngineV3 {
    private let buffer = OverflowingBuffer(capacity: V3.hmacSize)
    private var hmac: HMACV3
    private var engine: Engine

    init(encryptionKey: [UInt8], hmacKey: [UInt8], iv: [UInt8], header: ArraySlice<UInt8>) {
        precondition(encryptionKey.count == V3.keySize)
        precondition(hmacKey.count == V3.hmacSize)
        precondition(iv.count == V3.ivSize)

        hmac = HMACV3(key: hmacKey)
        hmac.update(header)
        engine = Engine(operation: .Decrypt, key: encryptionKey, iv: iv)
    }

    func update(data: [UInt8]) throws -> [UInt8] {
        return try data.withUnsafeBufferPointer(update)
    }

    func update(data: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        let overflow = buffer.update(data)
        self.hmac.update(overflow)
        return try overflow.withUnsafeBufferPointer {
            try engine.update($0)
        }
    }

    func final() throws -> [UInt8] {
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

    init(key: [UInt8]) {
        CCHmacInit(
            &self.context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key,
            key.count
        )
    }

    // FIXME: Hoist this repetion to Buffer type?
    func update(data: [UInt8]) {
        data.withUnsafeBufferPointer(update)
    }

    func update(data: ArraySlice<UInt8>) {
        data.withUnsafeBufferPointer(update)
    }

    func update(data: UnsafeBufferPointer<UInt8>) {
        CCHmacUpdate(&self.context, data.baseAddress, data.count)
    }
    
    func final() -> [UInt8] {
        var hmac = [UInt8](count: V3.hmacSize, repeatedValue: 0)
        CCHmacFinal(&self.context, &hmac)
        return hmac
    }
}
