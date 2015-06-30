//
//  BufferSink.swift
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

    // When a BufferSink receives less than its capacity, it outputs nothing and holds everything
    func testShort() {
        let out = DataSink()
        let buffer = BufferSink(capacity: 4, sink: out)
        let data: [UInt8] = [1,2,3]
        do {
            try buffer.put(data)
        } catch {
            XCTFail()
        }
        XCTAssert(out.array.isEmpty)
        XCTAssertEqual(buffer.array, [1,2,3])
    }

    // When a BufferSink receives exactly its capacity, it outputs nothing and holds everything
    func testExactly() {
        let out = DataSink()
        let buffer = BufferSink(capacity: 4, sink: out)
        let data: [UInt8] = [1,2,3,4]
        do {
            try buffer.put(data)
        } catch {
            XCTFail()
        }
        XCTAssert(out.array.isEmpty)
        XCTAssertEqual(buffer.array, [1,2,3,4])
    }

    // When a BufferSink receives more than its capacity, it outputs the earliest bytes and holds the rest
    func testOverflow() {
        let out = DataSink()
        let buffer = BufferSink(capacity: 4, sink: out)
        let data: [UInt8] = [1,2,3,4,5]
        do {
            try buffer.put(data)
        } catch {
            XCTFail()
        }
        XCTAssertEqual(out.array, [1])
        XCTAssertEqual(buffer.array, [2,3,4,5])
    }

    // When a BufferSink receives less than its capacity in multiple writes, it outputs nothing and holds everything
    func testMultiShort() {
        let out = DataSink()
        let buffer = BufferSink(capacity: 4, sink: out)
        do {
            try buffer.put([1])
            try buffer.put([2,3])
        } catch {
            XCTFail()
        }
        XCTAssert(out.array.isEmpty)
        XCTAssertEqual(buffer.array, [1,2,3])
    }

    // When a BufferSink receives more than its capacity in multiple writes, it outputs the earliest bytes and holds the rest
    func testMultiOverflow() {
        let out = DataSink()
        let buffer = BufferSink(capacity: 4, sink: out)
        do {
            try buffer.put([1,2,3])
            try buffer.put([4,5,6])
        } catch {
            XCTFail()
        }
        XCTAssertEqual(out.array, [1,2])
        XCTAssertEqual(buffer.array, [3,4,5,6])
    }

    // When a BufferSink receives more than its capacity when it already had elements, it outputs the earliest bytes and holds the rest
    func testMultiMegaOverflow() {
        let out = DataSink()
        let buffer = BufferSink(capacity: 4, sink: out)
        do {
            try buffer.put([1,2,3])
            try buffer.put([4,5,6,7,8,9])
        } catch {
            XCTFail()
        }
        XCTAssertEqual(out.array, [1,2,3,4,5])
        XCTAssertEqual(buffer.array, [6,7,8,9])
    }
}
