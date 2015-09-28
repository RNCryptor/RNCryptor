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
        let data = NSData(bytes: [1,2,3])
        let out = buffer.update(data)
        XCTAssert(out.length == 0)
        XCTAssertEqual(buffer.final(), NSData(bytes: [1,2,3]))
    }

    // When a OverflowingBuffer receives exactly its capacity, it outputs nothing and holds everything
    func testExactly() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data = NSData(bytes: [1,2,3,4])
        let out = buffer.update(data)
        XCTAssert(out.length == 0)
        XCTAssertEqual(buffer.final(), NSData(bytes: [1,2,3,4]))
    }

    // When a OverflowingBuffer receives more than its capacity, it outputs the earliest bytes and holds the rest
    func testOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let data = NSData(bytes: [1,2,3,4,5])
        let out = buffer.update(data)
        XCTAssertEqual(out, NSData(bytes: [1]))
        XCTAssertEqual(buffer.final(), NSData(bytes: [2,3,4,5]))
    }

    // When a OverflowingBuffer receives less than its capacity in multiple writes, it outputs nothing and holds everything
    func testMultiShort() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = NSMutableData(data:buffer.update(NSData(bytes:[1])))
        out.appendData(buffer.update(NSData(bytes: [2,3])))
        XCTAssert(out.length == 0)
        XCTAssertEqual(buffer.final(), NSData(bytes: [1,2,3]))
    }

    // When a OverflowingBuffer receives more than its capacity in multiple writes, it outputs the earliest bytes and holds the rest
    func testMultiOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = NSMutableData(data: buffer.update(NSData(bytes: [1,2,3])))
        XCTAssertEqual(out.length, 0)

        out.appendData(buffer.update(NSData(bytes: [4,5,6])))
        XCTAssertEqual(out, NSData(bytes: [1,2]))
        XCTAssertEqual(buffer.final(), NSData(bytes: [3,4,5,6]))
    }

    // When a OverflowingBuffer receives more than its capacity when it already had elements, it outputs the earliest bytes and holds the rest
    func testMultiMegaOverflow() {
        let buffer = OverflowingBuffer(capacity: 4)
        let out = NSMutableData(data: buffer.update(NSData(bytes:[1,2,3])))
        XCTAssertEqual(out.length, 0)

        out.appendData(buffer.update(NSData(bytes: [4,5,6,7,8,9])))
        XCTAssertEqual(out, NSData(bytes: [1,2,3,4,5]))
        XCTAssertEqual(buffer.final(), NSData(bytes: [6,7,8,9]))
    }
}
