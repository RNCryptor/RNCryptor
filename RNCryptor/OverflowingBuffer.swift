//
//  OverflowingBuffer.swift
//
//  Copyright © 2015 Rob Napier. All rights reserved.
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

import Foundation

internal class OverflowingBuffer {
    private var buffer = NSMutableData()
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
    }

    @warn_unused_result
    func updateWithData(data: NSData) -> NSData {
        if data.length >= capacity {
            return sendAllArray(data)
        } else if buffer.length + data.length <= capacity {
            buffer.appendData(data)
            return NSData()
        } else {
            return sendSomeArray(data)
        }
    }

    func finalData() -> NSData {
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