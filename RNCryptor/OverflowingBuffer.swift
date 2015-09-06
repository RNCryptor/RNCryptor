//
//  OverflowingBuffer.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

internal class OverflowingBuffer {
    private var array: [UInt8] = []
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
    }

    @warn_unused_result
    func update(data: [UInt8]) -> [UInt8] {
        if data.count >= capacity {
            return sendAllArray(data)
        } else if array.count + data.count <= capacity {
            array += data
            return []
        } else {
            return sendSomeArray(data)
        }
    }

    func final() -> [UInt8] {
        return array
    }

    private func sendAllArray(data: [UInt8]) -> [UInt8] {
        let (send, keep) = data.splitAt(data.count - capacity)
        var result = [UInt8]()
        assert(keep.count == capacity)
        if array.count > 0 { // Send the whole current array
            result += array
        }
        if send.count > 0 { // Send what needs sending of data
            result += send
        }
        array = Array(keep) // Keep the rest
        return result
    }

    private func sendSomeArray(data: [UInt8]) -> [UInt8] {
        let toSend = (array.count + data.count) - capacity
        assert(toSend > 0) // If it were <= 0, we would have extended the array
        assert(toSend < array.count) // If we would have sent everything, replaceBuffer should have been called

        let (send, keep) = array.splitAt(toSend)
        array = keep + data
        return Array(send)
    }
}