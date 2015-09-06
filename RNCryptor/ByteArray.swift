//
//  String.swift
//  RNCryptor
//
//  Created by Rob Napier on 7/1/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

// With thanks to https://github.com/krzyzanowskim/CryptoSwift/blob/master/CryptoSwift/NSDataExtension.swift
public extension NSData {
    public var hexString : String {
        return byteArray.hexString
    }

    public var base64EncodedString: String {
        return base64EncodedStringWithOptions(NSDataBase64EncodingOptions())
    }

    public var byteArray: [UInt8] {
        var bytesArray = [UInt8](count: length, repeatedValue: 0)
        getBytes(&bytesArray, length:length)
        return bytesArray
    }

    public convenience init(bytes: [UInt8]) {
        self.init(bytes: bytes, length: bytes.count)
    }
}

public extension String {
    public init?(UTF8Bytes: [UInt8]) {
        self.init(bytes: UTF8Bytes, length: UTF8Bytes.count, encoding: NSUTF8StringEncoding)
    }

    public var byteArrayFromHexEncoding: [UInt8]? {
        let strip = [Character]([" ", "<", ">", "\n", "\t"])
        let input = characters.filter { c in !strip.contains(c)}

        guard input.count % 2 == 0 else { return nil }

        var data = [UInt8]()
        for i in 0.stride(to: input.count, by: 2) {
            guard let value = UInt8(String(input[i...i+1]), radix: 16) else { return nil }
            data.append(value)
        }

        return data
    }

    public var byteArrayFromBase64Encoding: [UInt8]? {
        return NSData(base64EncodedString: self, options: NSDataBase64DecodingOptions())?.byteArray
    }
}

public protocol ByteLike: IntegerType {}
extension UInt8: ByteLike {}
extension Int8: ByteLike {}

public extension Array where Element: ByteLike {
    public var hexString: String {
        return map { String(format:"%02x", $0.toIntMax()) }.joinWithSeparator("")
    }

    public var base64EncodedString: String {
        return data.base64EncodedString
    }

    public var data: NSData {
        return withUnsafeBufferPointer { bytes in
            return NSData(bytes: bytes.baseAddress, length: bytes.count)
        }
    }
}

/** Compare two [UInt8] in time proportional to the untrusted data

Equatable-based comparisons genreally stop comparing at the first difference.
This can be used by attackers, in some situations,
to determine a secret value by considering the time required to compare the values.

We enumerate over the untrusted values so that the time is proportaional to the attacker's data,
which provides the attack no informatoin about the length of the secret.
*/
func isEqualInConsistentTime<T: ByteLike>(trusted trusted: [T], untrusted: [T]) -> Bool {
    // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
    // If any bytes are different, then the OR will accumulate some non-0 value.

    var result: T = untrusted.count == trusted.count ? 0 : 1  // Start with 0 (equal) only if our lengths are equal
    for (i, untrustedByte) in untrusted.enumerate() {
        // Use mod to wrap around ourselves if they are longer than we are.
        // Remember, we already broke equality if our lengths are different.
        result |= trusted[i % trusted.count] ^ untrustedByte
    }

    return result == 0

}