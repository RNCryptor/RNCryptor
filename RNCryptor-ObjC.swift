//
//  RNCryptor-ObjC.swift
//  RNCryptor
//
//  Created by Rob Napier on 8/31/16.
//  Copyright © 2016 Rob Napier. All rights reserved.
//

import Foundation

// ObjC helper bridge for RNCryptor
// If you're not calling RNCryptor from ObjC, you don't need this file

//@objc public enum RNCryptorError: Int {
//    /// Ciphertext was corrupt or password was incorrect.
//    /// It is not possible to distinguish between these cases in the v3 data format.
//    case hmacMismatch = 1
//
//    /// Unrecognized data format. Usually this means the data is corrupt.
//    case unknownHeader = 2
//
//    /// `final()` was called before sufficient data was passed to `update(withData:)`
//    case messageTooShort
//
//    /// Memory allocation failure. This should never happen.
//    case memoryFailure
//
//    /// A password-based decryptor was used on a key-based ciphertext, or vice-versa.
//    case invalidCredentialType
//}

public final class RNEncryptor: NSObject {
    private let encryptor: RNCryptor.Encryptor
    public init(password: String) {
        encryptor = RNCryptor.Encryptor(password: password)
    }
    public func update(withData data: Data) -> Data {
        return encryptor.update(withData: data)
    }
    public func finalData() -> Data {
        return encryptor.finalData()
    }
    public func encrypt(data: Data) -> Data {
        return encryptor.encrypt(data: data)
    }
}

public final class RNDecryptor: NSObject {
    private let decryptor: RNCryptor.Decryptor

    public init(password: String) {
        decryptor = RNCryptor.Decryptor(password: password)
    }
    public func decrypt(data: Data) throws -> Data {
        return try decryptor.decrypt(data: data)
    }
    public func update(withData data: Data) throws -> Data {
        return try decryptor.update(withData: data)
    }
    public func finalData() throws -> Data {
        return try decryptor.finalData()
    }
}

public final class RNCryptorFormatV3: NSObject {
    public static let keySize = RNCryptor.FormatV3.keySize
    public static let saltSize = RNCryptor.FormatV3.saltSize
    public static func makeKey(forPassword password: String, withSalt salt: Data) -> Data {
        return RNCryptor.FormatV3.makeKey(forPassword: password, withSalt: salt)
    }
}

public final class RNEncryptorV3: NSObject {
    private let encryptor: RNCryptor.EncryptorV3
    public init(password: String) {
        encryptor = RNCryptor.EncryptorV3(password: password)
    }
    public init(encryptionKey: Data, hmacKey: Data) {
        encryptor = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
    }
    public func encrypt(data: Data) -> Data {
        return encryptor.encrypt(data: data)
    }
    public func update(withData data: Data) -> Data {
        return encryptor.update(withData: data)
    }
    public func finalData() -> Data {
        return encryptor.finalData()
    }
}

public final class RNDecryptorV3: NSObject {
    private let decryptor: RNCryptor.DecryptorV3
    public init(password: String) {
        decryptor = RNCryptor.DecryptorV3(password: password)
    }
    public init(encryptionKey: Data, hmacKey: Data) {
        decryptor = RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
    }
    public func decrypt(data: Data) throws -> Data {
        return try decryptor.decrypt(data: data)
    }
    public func update(withData data: Data) throws -> Data {
        return try decryptor.update(withData: data)
    }
    public func finalData() throws -> Data {
        return try decryptor.finalData()
    }
}
