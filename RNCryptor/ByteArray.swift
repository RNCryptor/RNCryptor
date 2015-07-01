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
        return self.byteArray.hexString
    }

    public var base64EncodedString: String {
        return self.base64EncodedStringWithOptions(NSDataBase64EncodingOptions())
    }

    public var byteArray: [UInt8] {
        let count = self.length
        var bytesArray = [UInt8](count: count, repeatedValue: 0)
        self.getBytes(&bytesArray, length:count)
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

    public func byteArrayFromHexString() -> [UInt8]? {
        var data = [UInt8]()

        let strip = [Character]([" ", "<", ">", "\n", "\t"])
        let input = self.characters.filter { c in !strip.contains(c)}

        guard input.count % 2 == 0 else { return nil }

        for i in stride(from: 0, to: input.count, by: 2) {
            guard let value = UInt8(String(input[i...i+1]), radix: 16) else { return nil }
            data.append(value)
        }

        return data
    }

    public func bytesArrayFromBase64EncodedString() -> [UInt8]? {
        return NSData(base64EncodedString: self, options: NSDataBase64DecodingOptions())?.byteArray
    }
}

public protocol ByteLike: IntegerType {}
extension UInt8: ByteLike {}
extension Int8: ByteLike {}

public extension Array where T: ByteLike {
    public var hexString: String {
        return "".join(self.map { byte in String(format:"%02x", byte.toIntMax()) })
    }

    public var base64EncodedString: String {
        return self.data.base64EncodedString
    }

    public var data: NSData {
        return self.withUnsafeBufferPointer { bytes in
            return NSData(bytes: bytes.baseAddress, length: bytes.count)
        }
    }
}
