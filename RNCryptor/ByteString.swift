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
        let count = self.length
        var bytesArray = [UInt8](count: count, repeatedValue: 0)
        self.getBytes(&bytesArray, length:count)

        var s = "";
        for byte in bytesArray {
            s.extend(String(format:"%02X", byte))
        }
        return s
    }

    public var base64EncodedString: String {
        return self.base64EncodedStringWithOptions(NSDataBase64EncodingOptions())
    }

    public var arrayOfBytes: [UInt8] {
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

    public func bytesFromHexString() -> [UInt8]? {
        // Based on: http://stackoverflow.com/a/2505561/313633
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

    public func bytesFromBase64EncodedString() -> [UInt8]? {
        return NSData(base64EncodedString: self, options: NSDataBase64DecodingOptions())?.arrayOfBytes
    }
}

public protocol ByteLike: IntegerType {}
extension UInt8: ByteLike {}
extension Int8: ByteLike {}

public extension Array where T: ByteLike {
    public var hexString: String {
        return self.data.hexString
    }

    public var base64EncodedString: String {
        return self.data.base64EncodedString
    }

    public var data: NSData {
        return NSData(bytes: self, length: self.count)
    }
}

