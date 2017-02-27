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

    func _testIncremental(blocksOfSize blockSize: Int, count: Int) {
        var plainText = Data()
        plainText.count = blockSize

        let encryptor = RNCryptor.Encryptor(password: password)
        for _ in 1...count {
            _ = encryptor.update(withData: plainText)
        }
        _ = encryptor.finalData()
    }

    func testSmallBlocks() {
        measure {
            self._testIncremental(blocksOfSize: 1_000, count: 100_000)
        }
    }

    func testLargeBlocks() {
        measure {
            self._testIncremental(blocksOfSize: 1_000_000, count: 100)
        }
    }
}
