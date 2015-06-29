//
//  RNCryptorTests.swift
//  RNCryptorTests
//
//  Created by Rob Napier on 6/12/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import XCTest
import CommonCrypto

@testable import RNCryptor

let kGoodPassword = "Passw0rd!"
let kBadPassword = "NotThePassword"


extension String {
    public func dataFromHexString() -> [UInt8] {
        // Based on: http://stackoverflow.com/a/2505561/313633
        var data = [UInt8]()

        let input = self.stringByReplacingOccurrencesOfString(" ", withString: "")
            .stringByReplacingOccurrencesOfString("<", withString: "")
            .stringByReplacingOccurrencesOfString(">", withString: "")

        var string = ""

        for char in input.characters {
            string.append(char)
            if(string.characters.count == 2) {
                let scanner = NSScanner(string: string)
                var value: UInt32 = 0
                guard scanner.scanHexInt(&value) else { fatalError() }
                data.append(UInt8(value))
                string = ""
            }
        }

        return data
    }
}

class RNCryptorTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testRandomData() {
        let len = 1024
        let data = randomDataOfLength(len)
        XCTAssertEqual(data.count, len)

        let secondData = randomDataOfLength(len)
        XCTAssertNotEqual(data, secondData, "Random data this long should never be equal")
    }

    func testKDF() {
        let password = "a"
        let salt = "0102030405060708".dataFromHexString()
        let key = keyForPassword(password, salt: salt)
        let expect = "fc632b0c a6b23eff 9a9dc3e0 e585167f 5a328916 ed19f835 58be3ba9 828797cd".dataFromHexString()
        XCTAssertEqual(key, expect)
    }

    func testCryptor() {
        let data = randomDataOfLength(1024)
        let encryptKey = randomDataOfLength(RNCryptor.KeySize)
        let iv = randomDataOfLength(RNCryptor.IVSize)

        let encrypted = DataSink()
        let encryptor = Cryptor(operation: CCOperation(kCCEncrypt), key: encryptKey, IV: iv, sink: encrypted)
        try! encryptor.put(data)
        try! encryptor.finish()

        let decrypted = DataSink()
        let decryptor = Cryptor(operation: CCOperation(kCCDecrypt), key: encryptKey, IV: iv, sink: decrypted)
        try! decryptor.put(encrypted.array)
        try! decryptor.finish()

        XCTAssertEqual(decrypted.array, data)
    }

    func testKeyEncryptor() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".dataFromHexString()
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".dataFromHexString()
        let iv = "02030405060708090a0b0c0d0e0f0001".dataFromHexString()
        let plaintext = "01".dataFromHexString()
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".dataFromHexString()

        let encrypted = DataSink()
        let encryptor = Encryptor(encryptionKey: encryptKey, HMACKey: hmacKey, IV: iv, sink: encrypted)
        try! encryptor.put(plaintext)
        try! encryptor.finish()

        XCTAssertEqual(encrypted.array, ciphertext)
    }

    func testKeyDecryptor() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".dataFromHexString()
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".dataFromHexString()
        let plaintext = "01".dataFromHexString()
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".dataFromHexString()

        let decrypted = DataSink()
        let decryptor = KeyDecryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey, sink: decrypted)
        try! decryptor.put(ciphertext)
        try! decryptor.finish()

        XCTAssertEqual(decrypted.array, plaintext)
    }

    func testPasswordEncryptor() {
        let password = "thepassword"
        let encryptionSalt = "0001020304050607".dataFromHexString()
        let hmacSalt = "0102030405060708".dataFromHexString()
        let iv = "02030405060708090a0b0c0d0e0f0001".dataFromHexString()
        let plaintext = "01".dataFromHexString()
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexString()

        let encrypted = DataSink()
        let encryptor = Encryptor(password: password, encryptionSalt: encryptionSalt, hmacSalt: hmacSalt, iv: iv, sink: encrypted)

        try! encryptor.put(plaintext)
        try! encryptor.finish()

        XCTAssertEqual(encrypted.array, ciphertext)
    }
}
