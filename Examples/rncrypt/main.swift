//
//  main.swift
//  rncrypt
//
//  Created by Rob Napier on 6/19/16.
//  Copyright © 2016 Rob Napier. All rights reserved.
//

import Foundation

let password = "password"

func measure(block: () -> Void) {
    print("START")
    let start = Date()
    block()
    let finish = Date()
    print("FINISH: \(finish.timeIntervalSince(start))")
}

func _testIncremental(blocksOfSize blockSize: Int, count: Int) {
    var plainText = Data()
    plainText.count = blockSize

    let encryptor = RNCryptor.Encryptor(password: password)
    for _ in 1...count {
        autoreleasepool {
        _ = encryptor.update(withData: plainText)
        }
    }
    _ = encryptor.finalData()
}

func testOneshot() {
    let plaintext = RNCryptor.randomData(ofLength: 100_000_000)
    measure {
        _ = RNCryptor.encrypt(data: plaintext, withPassword: password)
    }
}

func testSmallBlocks() {
    measure {
        _testIncremental(blocksOfSize: 1_000, count: 1_000_000)
    }
}

func testLargeBlocks() {
    measure {
        _testIncremental(blocksOfSize: 1_000_000, count: 100)
    }
}

//print("oneshot")
//testOneshot()
//
print("smallBlocks")
testSmallBlocks()

//print("largeBlocks")
//testLargeBlocks()
