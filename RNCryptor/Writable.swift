//
//  ArrayWriter.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

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
}

public final class ArrayWriter: Writable, CustomStringConvertible {
    public var array: [UInt8] = []

    public func write(data: UnsafeBufferPointer<UInt8>) throws {
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