//
//  RNCryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/12/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

public let CCErrorDomain = "com.apple.CommonCrypto"

internal let FormatVersion = 3

public enum Error: ErrorType {
    case HMACMismatch
    case UnknownHeader
    case MessageTooShort
    case MemoryFailure
    case ParameterError
}

public func randomDataOfLength(length: Int) -> [UInt8] {
    var data = [UInt8](count: length, repeatedValue: 0)
    let result = SecRandomCopyBytes(kSecRandomDefault, length, &data)
    guard result == errSecSuccess else {
        fatalError("SECURITY FAILURE: Could not generate secure random numbers: \(result).")
    }

    return data
}

internal func checkResult(result: CCCryptorStatus) throws {
    guard result == CCCryptorStatus(kCCSuccess) else {
        throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
    }
}

public typealias Encryptor = EncryptorV3

public func encrypt(data: [UInt8], password: String) throws -> [UInt8] {
    let sink = DataSink()
    let encryptor = Encryptor(password: password, sink: sink)
    try encryptor.put(data)
    try encryptor.finish()
    return sink.array
}

public func encrypt(data: [UInt8], encryptionKey: [UInt8], hmacKey: [UInt8]) throws -> [UInt8] {
    let sink = DataSink()
    let encryptor = Encryptor(encryptionKey: encryptionKey, hmacKey: hmacKey, sink: sink)
    try encryptor.put(data)
    try encryptor.finish()
    return sink.array
}

public func decrypt(data: [UInt8], password: String) throws -> [UInt8] {
    let sink = DataSink()
    let decryptor = Decryptor(password: password, sink: sink)
    try decryptor.put(data)
    try decryptor.finish()
    return sink.array
}

public func decrypt(data: [UInt8], encryptionKey: [UInt8], hmacKey: [UInt8]) throws -> [UInt8] {
    let sink = DataSink()
    let decryptor = Decryptor(encryptionKey: encryptionKey, hmacKey: hmacKey, sink: sink)
    try decryptor.put(data)
    try decryptor.finish()
    return sink.array
}