//
//  V3.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

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
            let key = RNCryptorV3Key(derivedKey) else {
                fatalError("SECURITY FAILURE: Could not derive secure password: \(result).")
        }
        return key
    }
    private init() {} // no one else may create one
}

public let RNCryptorV3 = _RNCryptorV3()

public func ==(lhs: _RNCryptorV3, rhs: _RNCryptorV3) -> Bool {
    return true // It's constant
}

public protocol FixedSizeByteArray: Equatable {
    var bytes: [UInt8] { get set }
}
public func ==<T: FixedSizeByteArray>(lhs: T, rhs: T) -> Bool {
    return lhs.bytes == rhs.bytes
}

public struct RNCryptorV3Key: FixedSizeByteArray {
    public var bytes: [UInt8]
    public init?(_ bytes: [UInt8]) {
        guard bytes.count == RNCryptorV3.keySize
            else { return nil }
        self.bytes = bytes
    }
}

internal struct RNCryptorV3IV: FixedSizeByteArray {
    var bytes: [UInt8]
     init?(_ bytes: [UInt8]) {
        guard bytes.count == RNCryptorV3.ivSize
            else { return nil }
        self.bytes = bytes
    }
}

public struct RNCryptorV3Salt: FixedSizeByteArray {
    public var bytes: [UInt8]
    public init?(_ bytes: [UInt8]) {
        guard bytes.count == RNCryptorV3.saltSize
            else { return nil }
        self.bytes = bytes
    }
}
