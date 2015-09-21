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
        let toSend = data.count - capacity
        assert(toSend >= 0)

        let result = array + data.prefixUpTo(toSend)
        array = Array(data.dropFirst(toSend))
        return result
    }

    private func sendSomeArray(data: [UInt8]) -> [UInt8] {
        let toSend = (array.count + data.count) - capacity
        assert(toSend > 0) // If it were <= 0, we would have extended the array
        assert(toSend < array.count) // If we would have sent everything, replaceBuffer should have been called

        let result = Array(array.prefixUpTo(toSend))
        array = array.dropFirst(toSend) + data
        return result
    }
}