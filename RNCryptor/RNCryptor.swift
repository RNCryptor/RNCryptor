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
    case InvalidCredentialType
}

internal func randomDataOfLength(length: Int) -> NSData {
    let data = NSMutableData(length: length)!
    let result = SecRandomCopyBytes(kSecRandomDefault, length, UnsafeMutablePointer<UInt8>(data.mutableBytes))
    guard result == errSecSuccess else {
        fatalError("SECURITY FAILURE: Could not generate secure random numbers: \(result).")
    }

    return data
}

public protocol CryptorType {
    func update(data: NSData) throws -> NSData
    func final() throws -> NSData
}

public extension CryptorType {
    public func update(data: NSData) throws -> NSData {
        return try update(data)
    }
    internal func oneshot(data: NSData) throws -> NSData {
        let result = NSMutableData(data: try update(data))
        result.appendData(try final())
        return result
    }
}

public typealias Encryptor = EncryptorV3

/** Compare two NSData in time proportional to the untrusted data

Equatable-based comparisons genreally stop comparing at the first difference.
This can be used by attackers, in some situations,
to determine a secret value by considering the time required to compare the values.

We enumerate over the untrusted values so that the time is proportaional to the attacker's data,
which provides the attack no informatoin about the length of the secret.
*/
func isEqualInConsistentTime(trusted trusted: NSData, untrusted: NSData) -> Bool {
    // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
    // If any bytes are different, then the OR will accumulate some non-0 value.

    var result: UInt8 = untrusted.length == trusted.length ? 0 : 1  // Start with 0 (equal) only if our lengths are equal
    for (i, untrustedByte) in untrusted.bytesView.enumerate() {
        // Use mod to wrap around ourselves if they are longer than we are.
        // Remember, we already broke equality if our lengths are different.
        result |= trusted.bytesView[i % trusted.length] ^ untrustedByte
    }

    return result == 0
}
