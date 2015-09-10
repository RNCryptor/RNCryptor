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
