//
//  BufferWriter.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

public class BufferWriter: Writable {
    public var array: [UInt8] = []

    let capacity: Int
    let sink: Writable
    public init(capacity: Int, sink: Writable) {
        self.capacity = capacity
        self.sink = sink
    }

    // FIXME: Can probably merge much of this
    public func write(data: UnsafeBufferPointer<UInt8>) throws {
        if data.count >= capacity {
            try sendAllArray(data)
        } else if array.count + data.count <= capacity {
            array.extend(data)
        } else {
            try sendSomeArray(data)
        }
    }

    private func sendAllArray(data: UnsafeBufferPointer<UInt8>) throws {
        let (send, keep) = data.splitAt(data.count - capacity)
        assert(keep.count == capacity)
        if array.count > 0 { // Send the whole current array
            try sink.write(array)
        }
        if send.count > 0 { // Send what needs sending of data
            try sink.write(send)
        }
        array = Array(keep) // Keep the rest
    }

    private func sendSomeArray(data: UnsafeBufferPointer<UInt8>) throws {
        let toSend = (array.count + data.count) - capacity
        assert(toSend > 0) // If it were <= 0, we would have extended the array
        assert(toSend < array.count) // If we would have sent everything, replaceBuffer should have been called

        let (send, keep) = array.splitAt(toSend)
        try sink.write(send)
        array = Array(keep)
        array.extend(data)
    }
}