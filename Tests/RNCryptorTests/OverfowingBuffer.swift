//
//  OverflowingBuffer.swift
//
//  Copyright © 2015 Rob Napier. All rights reserved.
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

import XCTest
@testable import RNCryptor

class OverflowingBufferTest: XCTestCase {

    // When a OverflowingBuffer receives less than its capacity, it outputs nothing and holds everything
    func testShort() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data = Data([1,2,3])
        let out = buffer.update(withData: data)
        XCTAssert(out.count == 0)
        XCTAssertEqual(buffer.finalData(), Data([1,2,3]))
    }

    // When a OverflowingBuffer receives exactly its capacity, it outputs nothing and holds everything
    func testExactly() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data = Data([1,2,3,4])
        let out = buffer.update(withData: data)
        XCTAssert(out.count == 0)
        XCTAssertEqual(buffer.finalData(), Data([1,2,3,4]))
    }

    // When a OverflowingBuffer receives more than its capacity, it outputs the earliest bytes and holds the rest
    func testOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data = Data([1,2,3,4,5])
        let out = buffer.update(withData: data)
        XCTAssertEqual(out, Data([1]))
        XCTAssertEqual(buffer.finalData(), Data([2,3,4,5]))
    }

    // When a OverflowingBuffer receives less than its capacity in multiple writes, it outputs nothing and holds everything
    func testMultiShort() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = NSMutableData(data:buffer.update(withData: Data([1])))
        out.append(buffer.update(withData: Data([2,3])))
        XCTAssert(out.length == 0)
        XCTAssertEqual(buffer.finalData(), Data([1,2,3]))
    }

    // When a OverflowingBuffer receives more than its capacity in multiple writes, it outputs the earliest bytes and holds the rest
    func testMultiOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        var out = buffer.update(withData: Data([1,2,3]))
        XCTAssertEqual(out.count, 0)

        out.append(buffer.update(withData: Data([4,5,6])))
        XCTAssertEqual(out, Data([1,2]))
        XCTAssertEqual(buffer.finalData(), Data([3,4,5,6]))
    }

    // When a OverflowingBuffer receives more than its capacity when it already had elements, it outputs the earliest bytes and holds the rest
    func testMultiMegaOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        var out = buffer.update(withData: Data([1,2,3]))
        XCTAssertEqual(out.count, 0)

        out.append(buffer.update(withData: Data([4,5,6,7,8,9])))
        XCTAssertEqual(out, Data([1,2,3,4,5]))
        XCTAssertEqual(buffer.finalData(), Data([6,7,8,9]))
    }
}
