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
