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

func testOneshot() {
    let plaintext = RNCryptor.randomData(ofLength: 100_000_000)
    measure {
        _ = RNCryptor.encrypt(data: plaintext, withPassword: password)
    }
}

func testSmallBlocks() {
    let blocks = _blocks(ofSize: 1_000, count: 100_000)
    measure {
        _testIncremental(blocks: blocks)
    }
}

func testLargeBlocks() {
    let blocks = _blocks(ofSize: 1_000_000, count: 100)
    measure {
        _testIncremental(blocks: blocks)
    }
}

print("oneshot")
testOneshot()
//
//print("smallBlocks")
//testSmallBlocks()

//print("largeBlocks")
//testLargeBlocks()
