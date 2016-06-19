//
//  RNCryptorPerformance.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/19/16.
//  Copyright © 2016 Rob Napier. All rights reserved.
//

import XCTest
import RNCryptor

private let password = "password"

class RNCryptorPerformance: XCTestCase {

    func testOneshot() {
        let plaintext = RNCryptor.randomDataOfLength(100_000_000)
        self.measureBlock {
            _ = RNCryptor.encryptData(plaintext, password: password)
        }
    }

    func _blocks(ofSize size: Int, count: Int) -> [NSData] {
        return (1...count).map { _ in RNCryptor.randomDataOfLength(size) }
    }

    func _testIncremental(blocks: [NSData]) {
        let encryptor = RNCryptor.Encryptor(password: password)
        for block in blocks {
            encryptor.updateWithData(block)
        }
        encryptor.finalData()
    }

    func testSmallBlocks() {
        let blocks = _blocks(ofSize: 1_000, count: 100_000)
        measureBlock {
            self._testIncremental(blocks)
        }
    }

    func testLargeBlocks() {
        let blocks = _blocks(ofSize: 1_000_000, count: 100)
        measureBlock {
            self._testIncremental(blocks)
        }
    }
}
