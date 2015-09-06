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

internal func randomDataOfLength(length: Int) -> [UInt8] {
    var data = [UInt8](count: length, repeatedValue: 0)
    let result = SecRandomCopyBytes(kSecRandomDefault, length, &data)
    guard result == errSecSuccess else {
        fatalError("SECURITY FAILURE: Could not generate secure random numbers: \(result).")
    }

    return data
}

internal protocol CryptorType {
    func update(data: [UInt8]) throws -> [UInt8]
    func final() throws -> [UInt8]
}

internal extension CryptorType {
    internal func process(cryptor: CryptorType, data: [UInt8]) throws -> [UInt8] {
        var result = try cryptor.update(data)
        result += try cryptor.final()
        return result
    }
}

public typealias Encryptor = EncryptorV3

