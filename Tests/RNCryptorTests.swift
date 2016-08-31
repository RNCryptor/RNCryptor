//
//  RNCryptorTests.swift
//
//  Copyright © 2015 Rob Napier. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

import XCTest

@testable import RNCryptor

func randomLength() -> Int {
    return Int(arc4random_uniform(1024) + 1)
}

func randomData() -> NSData {
    return RNCryptor.randomDataOfLength(randomLength())
}

class RNCryptorTests: XCTestCase {
    func testRandomData() {
        let len = 1024
        let data = RNCryptor.randomDataOfLength(len)
        XCTAssertEqual(data.length, len)

        let secondData = RNCryptor.randomDataOfLength(len)
        XCTAssertNotEqual(data, secondData, "Random data this long should never be equal")
    }

    func testKDF() {
        let password = "a"
        let salt = "0102030405060708".dataFromHexEncoding!
        let key = V3.keyForPassword(password, salt: salt)
        let expect = "fc632b0c a6b23eff 9a9dc3e0 e585167f 5a328916 ed19f835 58be3ba9 828797cd".dataFromHexEncoding!
        XCTAssertEqual(key, expect)
    }

    func testEngine() {
        let data = randomData()
        let encryptKey = RNCryptor.randomDataOfLength(V3.keySize)
        let iv = RNCryptor.randomDataOfLength(V3.ivSize)

        let encrypted = NSMutableData()
        let encryptor = Engine(operation: .Encrypt, key: encryptKey, iv: iv)
        encrypted.appendData(encryptor.updateWithData(data))
        encrypted.appendData(encryptor.finalData())

        let decryptor = Engine(operation: .Decrypt, key: encryptKey, iv: iv)
        let decrypted = NSMutableData(data: decryptor.updateWithData(encrypted))
        decrypted.appendData(decryptor.finalData())
        XCTAssertEqual(decrypted, data)
    }

    func testKeyEncryptor() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".dataFromHexEncoding!
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".dataFromHexEncoding!
        let iv = "02030405060708090a0b0c0d0e0f0001".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".dataFromHexEncoding!

        let encryptor = RNCryptor.EncryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey, iv: iv)
        let encrypted = encryptor.encryptData(plaintext)
        XCTAssertEqual(encrypted, ciphertext)
    }

    func testKeyDecryptor() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".dataFromHexEncoding!
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".dataFromHexEncoding!

        let decryptor = RNCryptor.DecryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey)
        do {
            let decrypted = try decryptor.decryptData(ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }

    func testPasswordEncryptor() {
        let password = "thepassword"
        let encryptionSalt = "0001020304050607".dataFromHexEncoding!
        let hmacSalt = "0102030405060708".dataFromHexEncoding!
        let iv = "02030405060708090a0b0c0d0e0f0001".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexEncoding!

        let encryptor = RNCryptor.EncryptorV3(password: password, encryptionSalt: encryptionSalt, hmacSalt: hmacSalt, iv: iv)

        let encrypted = encryptor.encryptData(plaintext)
        XCTAssertEqual(encrypted, ciphertext)
    }

    func testPasswordDecryptor() {
        let password = "thepassword"
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexEncoding!

        let decryptor = RNCryptor.Decryptor(password: password)

        do {
            let decrypted = try decryptor.decryptData(ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }

    func testOneShotKey() {
        let encryptionKey = RNCryptor.randomDataOfLength(V3.keySize)
        let hmacKey = RNCryptor.randomDataOfLength(V3.keySize)
        let data = randomData()

        let ciphertext = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey).encryptData(data)

        let plaintext: NSData
        do {
            plaintext = try RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey).decryptData(ciphertext)
        } catch {
            plaintext = NSData(bytes: [0xaa])
            XCTFail("Caught: \(error)")
        }

        XCTAssertEqual(plaintext, data)
    }

    func testOneShotPassword() {
        let password = "thepassword"
        let data = randomData()

        let ciphertext = RNCryptor.Encryptor(password: password).encryptData(data)

        let plaintext: NSData
        do {
            plaintext = try RNCryptor.Decryptor(password: password).decryptData(ciphertext)
        } catch {
            plaintext = NSData(bytes: [0])
            XCTFail("Caught: \(error)")
        }

        XCTAssertEqual(plaintext, data)
    }

    func testMultipleUpdateWithData() {
        let password = "thepassword"
        let datas = (0..<10).map { _ in randomData() }
        let fullData = datas.reduce(NSMutableData()) { $0.appendData($1); return $0 }

        let encryptor = RNCryptor.Encryptor(password: password)
        let ciphertext = NSMutableData()
        for data in datas {
            ciphertext.appendData(encryptor.updateWithData(data))
        }
        ciphertext.appendData(encryptor.finalData())

        do {
            let decrypted = try RNCryptor.Decryptor(password: password).decryptData(ciphertext)
            XCTAssertEqual(fullData, decrypted)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }

    func testBadFormat() {
        let data = NSMutableData(length: randomLength())!
        do {
            try RNCryptor.Decryptor(password: "password").decryptData(data)
            XCTFail("Should not thrown")
        } catch let error as RNCryptorError {
            XCTAssertEqual(error, RNCryptorError.UnknownHeader)
        } catch {
            XCTFail("Threw wrong thing \(error)")
        }
    }

    func testBadFormatV3() {
        let data = NSMutableData(length: randomLength())!
        do {
            try RNCryptor.DecryptorV3(password: "password").decryptData(data)
            XCTFail("Should not thrown")
        } catch let error as RNCryptorError {
            XCTAssertEqual(error, RNCryptorError.UnknownHeader)
        } catch {
            XCTFail("Threw wrong thing \(error)")
        }
    }

    func testBadPassword() {
        let password = "thepassword"
        let data = randomData()

        let ciphertext = RNCryptor.Encryptor(password: password).encryptData(data)

        do {
            let _ = try RNCryptor.Decryptor(password: "wrongpassword").decryptData(ciphertext)
            XCTFail("Should have failed to decrypt")
        } catch let err as RNCryptorError {
            XCTAssertEqual(err, RNCryptorError.HMACMismatch)
        } catch {
            XCTFail("Wrong error: \(error)")
        }
    }
}
