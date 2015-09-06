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

class RNCryptorTests: XCTestCase {
    func testRandomData() {
        let len = 1024
        let data = randomDataOfLength(len)
        XCTAssertEqual(data.count, len)

        let secondData = randomDataOfLength(len)
        XCTAssertNotEqual(data, secondData, "Random data this long should never be equal")
    }

    func testKDF() {
        let password = "a"
        let salt = "0102030405060708".byteArrayFromHexEncoding!
        let key = V3.keyForPassword(password, salt: salt)
        let expect = "fc632b0c a6b23eff 9a9dc3e0 e585167f 5a328916 ed19f835 58be3ba9 828797cd".byteArrayFromHexEncoding!
        XCTAssertEqual(key, expect)
    }

    func testEngine() {
        let data = randomDataOfLength(1024)
        let encryptKey = randomDataOfLength(V3.keySize)
        let iv = randomDataOfLength(V3.ivSize)

        var encrypted = [UInt8]()
        do {
            let encryptor = Engine(operation: .Encrypt, key: encryptKey, iv: iv)
            encrypted = try encryptor.update(data) + encryptor.final()
        } catch {
            XCTFail("Caught: \(error)")
        }

        do {
            let decryptor = Engine(operation: .Decrypt, key: encryptKey, iv: iv)
            let decrypted = try decryptor.update(encrypted) + decryptor.final()
            XCTAssertEqual(decrypted, data)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }

    func testKeyEncryptor() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".byteArrayFromHexEncoding!
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".byteArrayFromHexEncoding!
        let iv = "02030405060708090a0b0c0d0e0f0001".byteArrayFromHexEncoding!
        let plaintext = "01".byteArrayFromHexEncoding!
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".byteArrayFromHexEncoding!

        let encryptor = Encryptor(encryptionKey: encryptKey, hmacKey: hmacKey, iv: iv)
        let encrypted = encryptor.encrypt(plaintext)
        XCTAssertEqual(encrypted, ciphertext)
    }

    func testKeyDecryptor() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".byteArrayFromHexEncoding!
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".byteArrayFromHexEncoding!
        let plaintext = "01".byteArrayFromHexEncoding!
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".byteArrayFromHexEncoding!

        let decryptor = Decryptor(encryptionKey: encryptKey, hmacKey: hmacKey)
        do {
            let decrypted = try decryptor.decrypt(ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }

    func testPasswordEncryptor() {
        let password = "thepassword"
        let encryptionSalt = "0001020304050607".byteArrayFromHexEncoding!
        let hmacSalt = "0102030405060708".byteArrayFromHexEncoding!
        let iv = "02030405060708090a0b0c0d0e0f0001".byteArrayFromHexEncoding!
        let plaintext = "01".byteArrayFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".byteArrayFromHexEncoding!

        let encryptor = Encryptor(password: password, encryptionSalt: encryptionSalt, hmacSalt: hmacSalt, iv: iv)

        let encrypted = encryptor.encrypt(plaintext)
        XCTAssertEqual(encrypted, ciphertext)
    }

    func testPasswordDecryptor() {
        let password = "thepassword"
        let plaintext = "01".byteArrayFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".byteArrayFromHexEncoding!

        let decryptor = Decryptor(password: password)

        do {
            let decrypted = try decryptor.decrypt(ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }

    func testOneShotKey() {
        let encryptionKey = randomDataOfLength(V3.keySize)
        let hmacKey = randomDataOfLength(V3.keySize)
        let data = randomDataOfLength(1024)

        let ciphertext = Encryptor(encryptionKey: encryptionKey, hmacKey: hmacKey).encrypt(data)

        let plaintext: [UInt8]
        do {
            plaintext = try Decryptor(encryptionKey: encryptionKey, hmacKey: hmacKey).decrypt(ciphertext)
        } catch {
            plaintext = [0xaa]
            XCTFail("Caught: \(error)")
        }

        XCTAssertEqual(plaintext, data)
    }

    func testOneShotPassword() {
        let password = "thepassword"
        let data = randomDataOfLength(1024)

        let ciphertext = Encryptor(password: password).encrypt(data)

        let plaintext: [UInt8]
        do {
            plaintext = try Decryptor(password: password).decrypt(ciphertext)
        } catch {
            plaintext = [0]
            XCTFail("Caught: \(error)")
        }
        
        XCTAssertEqual(plaintext, data)
    }
}

// FIXME: Add test (and vector) for empty input