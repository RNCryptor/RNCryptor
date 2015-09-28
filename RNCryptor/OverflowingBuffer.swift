//
//  OverflowingBuffer.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

internal class OverflowingBuffer {
    private var buffer = NSMutableData()
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
    }

    @warn_unused_result
    func update(data: NSData) -> NSData {
        if data.length >= capacity {
            return sendAllArray(data)
        } else if buffer.length + data.length <= capacity {
            buffer.appendData(data)
            return NSData()
        } else {
            return sendSomeArray(data)
        }
    }

    func final() -> NSData {
        let result = buffer
        buffer = NSMutableData() // Data belongs to caller now.
        return result
    }

    private func sendAllArray(data: NSData) -> NSData {
        let toSend = data.length - capacity
        assert(toSend >= 0)
        assert(data.length - toSend <= capacity)

        let result = NSMutableData(data: buffer)
        result.appendData(data.bytesView[0..<toSend])
        buffer.length = 0
        buffer.appendData(data.bytesView[toSend..<data.length])
        return result
    }

    private func sendSomeArray(data: NSData) -> NSData {
        let toSend = (buffer.length + data.length) - capacity
        assert(toSend > 0) // If it were <= 0, we would have extended the array
        assert(toSend < buffer.length) // If we would have sent everything, replaceBuffer should have been called

        let result = buffer.bytesView[0..<toSend]
        buffer.replaceBytesInRange(NSRange(0..<toSend), withBytes: nil, length: 0)
        buffer.appendData(data)
        return result
    }
}