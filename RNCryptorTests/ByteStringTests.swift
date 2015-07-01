//
//  ByteStringTests.swift
//  RNCryptor
//
//  Created by Rob Napier on 7/1/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import XCTest
import RNCryptor

class ByteStringTests: XCTestCase {
    func testArrayHexString() {
        XCTAssertEqual([UInt8]([0,1,2,3]).hexString, "00010203")
    }
}
