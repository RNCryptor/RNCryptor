//
//  BufferWriter.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/28/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import XCTest
import RNCryptor

class BufferSinkTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    // When a BufferWriter receives less than its capacity, it outputs nothing and holds everything
    func testShort() {
        let buffer = BufferWriter(capacity: 4)
        let data: [UInt8] = [1,2,3]
        let out = buffer.update(data)
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.array, [1,2,3])
    }

    // When a BufferWriter receives exactly its capacity, it outputs nothing and holds everything
    func testExactly() {
        let buffer = BufferWriter(capacity: 4)
        let data: [UInt8] = [1,2,3,4]
        let out = buffer.update(data)
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.array, [1,2,3,4])
    }

    // When a BufferWriter receives more than its capacity, it outputs the earliest bytes and holds the rest
    func testOverflow() {
        let buffer = BufferWriter(capacity: 4)
        let data: [UInt8] = [1,2,3,4,5]
        let out = buffer.update(data)
        XCTAssertEqual(out, [1])
        XCTAssertEqual(buffer.array, [2,3,4,5])
    }

    // When a BufferWriter receives less than its capacity in multiple writes, it outputs nothing and holds everything
    func testMultiShort() {
        let buffer = BufferWriter(capacity: 4)
        let out = buffer.update([1]) + buffer.update([2,3])
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.array, [1,2,3])
    }

    // When a BufferWriter receives more than its capacity in multiple writes, it outputs the earliest bytes and holds the rest
    func testMultiOverflow() {
        let buffer = BufferWriter(capacity: 4)
        let out = buffer.update([1,2,3]) + buffer.update([4,5,6])
        XCTAssertEqual(out, [1,2])
        XCTAssertEqual(buffer.array, [3,4,5,6])
    }

    // When a BufferWriter receives more than its capacity when it already had elements, it outputs the earliest bytes and holds the rest
    func testMultiMegaOverflow() {
        let buffer = BufferWriter(capacity: 4)
        let out = buffer.update([1,2,3]) + buffer.update([4,5,6,7,8,9])
        XCTAssertEqual(out, [1,2,3,4,5])
        XCTAssertEqual(buffer.array, [6,7,8,9])
    }
}
