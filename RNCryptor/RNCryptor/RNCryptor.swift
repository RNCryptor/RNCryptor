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
public let KeySize = kCCKeySizeAES256
public let HMACSize = Int(CC_SHA256_DIGEST_LENGTH)
public let SaltSize = 8
public let Version = UInt8(3)
public let IVSize = kCCBlockSizeAES128

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

    if result != errSecSuccess {
        fatalError("SECURITY FAILURE: Could not generate secure random numbers.")
    }

    return data
}

public func keyForPassword(password: String, salt: [UInt8]) -> [UInt8] {
    var derivedKey = [UInt8](count: KeySize, repeatedValue: 0)

    let passwordData = [UInt8](password.utf8)

    // All the crazy casting because CommonCryptor hates Swift
    let algorithm        = CCPBKDFAlgorithm(kCCPBKDF2)
    let passwordBytes    = UnsafePointer<Int8>(passwordData)
    let saltBytes        = UnsafePointer<UInt8>(salt)
    let prf              = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
    let rounds           = UInt32(10000)

    let result = CCKeyDerivationPBKDF(
        algorithm,
        passwordBytes, passwordData.count,
        saltBytes,     salt.count,
        prf,           rounds,
        &derivedKey,   derivedKey.count)

    guard result == CCCryptorStatus(kCCSuccess) else {
        fatalError("SECURITY FAILURE: Could not derive secure password.")
    }
    return derivedKey
}

internal func checkResult(result: CCCryptorStatus) throws {
    guard result == CCCryptorStatus(kCCSuccess) else {
        throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
    }
}
