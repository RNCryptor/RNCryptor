//
//  V3.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

let V3 = (
    version: UInt8(3),

    keySize:  kCCKeySizeAES256,
    ivSize:   kCCBlockSizeAES128,
    hmacSize: Int(CC_SHA256_DIGEST_LENGTH),
    saltSize: 8,

    keyForPassword: keyForPasswordV3
)

private func keyForPasswordV3(password: String, salt: [UInt8]) -> [UInt8] {
    var derivedKey = [UInt8](count: V3.keySize, repeatedValue: 0)

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
        fatalError("SECURITY FAILURE: Could not derive secure password: \(result).")
    }
    return derivedKey
}
