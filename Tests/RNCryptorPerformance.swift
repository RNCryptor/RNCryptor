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
        let plaintext = RNCryptor.randomData(ofLength: 100_000_000)
        self.measure {
            _ = RNCryptor.encrypt(data: plaintext, withPassword: password)
        }
    }

    func _blocks(ofSize size: Int, count: Int) -> [Data] {
        return (1...count).map { _ in RNCryptor.randomData(ofLength: size) }
    }

    func _testIncremental(blocks: [Data]) {
        let encryptor = RNCryptor.Encryptor(password: password)
        for block in blocks {
            _ = encryptor.update(withData: block)
        }
        _ = encryptor.finalData()
    }

    func testSmallBlocks() {
        let blocks = _blocks(ofSize: 1_000, count: 100_000)
        measure {
            self._testIncremental(blocks: blocks)
        }
    }

    func testLargeBlocks() {
        let blocks = _blocks(ofSize: 1_000_000, count: 100)
        measure {
            self._testIncremental(blocks: blocks)
        }
    }
}
