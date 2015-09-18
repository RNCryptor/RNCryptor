//
//  OverflowingBuffer.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/28/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import XCTest
@testable import RNCryptor

class OverflowingBufferTest: XCTestCase {

    // When a OverflowingBuffer receives less than its capacity, it outputs nothing and holds everything
    func testShort() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data: [UInt8] = [1,2,3]
        let out = buffer.update(data)
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.final(), [1,2,3])
    }

    // When a OverflowingBuffer receives exactly its capacity, it outputs nothing and holds everything
    func testExactly() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data: [UInt8] = [1,2,3,4]
        let out = buffer.update(data)
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.final(), [1,2,3,4])
    }

    // When a OverflowingBuffer receives more than its capacity, it outputs the earliest bytes and holds the rest
    func testOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data: [UInt8] = [1,2,3,4,5]
        let out = buffer.update(data)
        XCTAssertEqual(out, [1])
        XCTAssertEqual(buffer.final(), [2,3,4,5])
    }

    // When a OverflowingBuffer receives less than its capacity in multiple writes, it outputs nothing and holds everything
    func testMultiShort() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = buffer.update([1]) + buffer.update([2,3])
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.final(), [1,2,3])
    }

    // When a OverflowingBuffer receives more than its capacity in multiple writes, it outputs the earliest bytes and holds the rest
    func testMultiOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = buffer.update([1,2,3]) + buffer.update([4,5,6])
        XCTAssertEqual(out, [1,2])
        XCTAssertEqual(buffer.final(), [3,4,5,6])
    }

    // When a OverflowingBuffer receives more than its capacity when it already had elements, it outputs the earliest bytes and holds the rest
    func testMultiMegaOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = buffer.update([1,2,3]) + buffer.update([4,5,6,7,8,9])
        XCTAssertEqual(out, [1,2,3,4,5])
        XCTAssertEqual(buffer.final(), [6,7,8,9])
    }
}
