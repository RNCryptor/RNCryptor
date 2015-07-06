//
//  ArrayWriter.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

public protocol Writable: class {
    func write(data: UnsafeBufferPointer<UInt8>) throws
}

// FIXME: I don't believe Swift 2b2 can avoid this code duplication
public extension Writable {
    public func write(data: [UInt8]) throws {
        try data.withUnsafeBufferPointer { try self.write($0) }
    }
    public func write(data: ArraySlice<UInt8>) throws {
        try data.withUnsafeBufferPointer { try self.write($0) }
    }
    public func write(data: NSData) throws {
        try self.write(UnsafeBufferPointer(start: UnsafePointer<UInt8>(data.bytes), count: data.length))
    }
}

public final class ArrayWriter: Writable, CustomStringConvertible {
    public var array: [UInt8] = []

    public func write(data: UnsafeBufferPointer<UInt8>) throws {
        self.array.extend(data)
    }

    // Avoid [UInt8] -> UnsafeBufferPointer conversion
    public func write(data: [UInt8]) throws {
        self.array.extend(data)
    }

    public init() {}
    public var description: String {
        return "\(self.array)"
    }
}

public final class NullWriter: Writable {
    public func write(data: UnsafeBufferPointer<UInt8>) throws {}
}

extension NSFileHandle : Writable {
    public func write(data: UnsafeBufferPointer<UInt8>) throws {
        self.writeData(NSData(bytesNoCopy: UnsafeMutablePointer(data.baseAddress), length: data.count, freeWhenDone: false))
    }

    // Avoid NSData -> UnsafeBufferPointer -> NSData conversion
    public func write(data: NSData) throws {
        self.writeData(data)
    }
}