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

public let RNCryptorErrorDomain = "net.robnapier.RNCryptor"

public func randomDataOfLength(length: Int) throws -> NSData {
    guard let data = NSMutableData(length: length) else {
        throw NSError(domain: RNCryptorErrorDomain, code: Int(errSecAllocate), userInfo: nil)
    }

    let result = SecRandomCopyBytes(kSecRandomDefault, length, UnsafeMutablePointer<UInt8>(data.mutableBytes))
    if result != errSecSuccess {
        throw NSError(domain: RNCryptorErrorDomain, code: Int(errno), userInfo: nil)
    }

    return data
}

public func keyForPassword(password: String, salt: NSData) throws -> NSData {
    guard let derivedKey = NSMutableData(length: kCCKeySizeAES256) else {
        throw NSError(domain: RNCryptorErrorDomain, code: Int(errSecAllocate), userInfo: nil)
    }

    guard let passwordData = password.dataUsingEncoding(NSUTF8StringEncoding) else {
        throw NSError(domain: RNCryptorErrorDomain, code: Int(errSecDecode), userInfo: nil)
    }

    let algorithm        = CCPBKDFAlgorithm(kCCPBKDF2)
    let passwordBytes    = UnsafePointer<Int8>(passwordData.bytes)
    let saltBytes        = UnsafePointer<UInt8>(salt.bytes)
    let prf              = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
    let rounds           = UInt32(10000)
    let derivedKeyBytes  = UnsafeMutablePointer<UInt8>(derivedKey.mutableBytes)

    let result = CCKeyDerivationPBKDF(
        algorithm,
        passwordBytes,   passwordData.length,
        saltBytes,       salt.length,
        prf,             rounds,
        derivedKeyBytes, derivedKey.length)

    if result != errSecSuccess {
        throw NSError(domain: RNCryptorErrorDomain, code: Int(result), userInfo: nil)
    }
    return derivedKey
}