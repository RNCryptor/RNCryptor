//
//  TruncatingBuffer.swift
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

    // When a TruncatingBuffer receives less than its capacity, it outputs nothing and holds everything
    func testShort() {
        let buffer = TruncatingBuffer(capacity: 4)
        let data: [UInt8] = [1,2,3]
        let out = buffer.update(data)
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.final(), [1,2,3])
    }

    // When a TruncatingBuffer receives exactly its capacity, it outputs nothing and holds everything
    func testExactly() {
        let buffer = TruncatingBuffer(capacity: 4)
        let data: [UInt8] = [1,2,3,4]
        let out = buffer.update(data)
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.final(), [1,2,3,4])
    }

    // When a TruncatingBuffer receives more than its capacity, it outputs the earliest bytes and holds the rest
    func testOverflow() {
        let buffer = TruncatingBuffer(capacity: 4)
        let data: [UInt8] = [1,2,3,4,5]
        let out = buffer.update(data)
        XCTAssertEqual(out, [1])
        XCTAssertEqual(buffer.final(), [2,3,4,5])
    }

    // When a TruncatingBuffer receives less than its capacity in multiple writes, it outputs nothing and holds everything
    func testMultiShort() {
        let buffer = TruncatingBuffer(capacity: 4)
        let out = buffer.update([1]) + buffer.update([2,3])
        XCTAssert(out.isEmpty)
        XCTAssertEqual(buffer.final(), [1,2,3])
    }

    // When a TruncatingBuffer receives more than its capacity in multiple writes, it outputs the earliest bytes and holds the rest
    func testMultiOverflow() {
        let buffer = TruncatingBuffer(capacity: 4)
        let out = buffer.update([1,2,3]) + buffer.update([4,5,6])
        XCTAssertEqual(out, [1,2])
        XCTAssertEqual(buffer.final(), [3,4,5,6])
    }

    // When a TruncatingBuffer receives more than its capacity when it already had elements, it outputs the earliest bytes and holds the rest
    func testMultiMegaOverflow() {
        let buffer = TruncatingBuffer(capacity: 4)
        let out = buffer.update([1,2,3]) + buffer.update([4,5,6,7,8,9])
        XCTAssertEqual(out, [1,2,3,4,5])
        XCTAssertEqual(buffer.final(), [6,7,8,9])
    }
}
