//
//  VectorTestHelpers.swift
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

func verifyVector(_ vector: [String:String], key:String, equals actual:Data, name:String) {
    let version = vector["version"]!
    let title = vector["title"]!
    XCTAssertEqual(actual, vector[key]!.dataFromHexEncoding!, "Failed \(name) test (v\(version)): \(title)")
}

func _verifyKDF(_ vector: [String:String], name:String) {
    let key = V3.makeKey(forPassword: vector["password"]!,
                         withSalt: vector["salt_hex"]!.dataFromHexEncoding!)
    verifyVector(vector, key:"key_hex", equals:key, name: name)
}


func verify_v3_kdf(_ vector: [String:String]) {
    _verifyKDF(vector, name:"kdf")
}

func _verifyPassword(_ vector: [String:String]) {
    if Int(vector["version"]!) == Int(V3.formatVersion) {
        let encryptor = RNCryptor.EncryptorV3(password: vector["password"]!,
            encryptionSalt: vector["enc_salt_hex"]!.dataFromHexEncoding!,
            hmacSalt: vector["hmac_salt_hex"]!.dataFromHexEncoding!,
            iv: vector["iv_hex"]!.dataFromHexEncoding!)
        let ciphertext = encryptor.encrypt(data: vector["plaintext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext, name:"password encrypt")
    }

    do {
        let plaintext = try RNCryptor.decrypt(data: vector["ciphertext_hex"]!.dataFromHexEncoding!, withPassword: vector["password"]!)
        verifyVector(vector, key:"plaintext_hex", equals:plaintext, name:"password decrypt")
    } catch {
        XCTFail("\(error)")
    }
}

func verify_v3_password(_ vector: [String: String]) {
    _verifyPassword(vector)
}

func verify_v3_key(_ vector: [String: String]) {
    if Int(vector["version"]!) == Int(V3.formatVersion) {
        let encryptor = RNCryptor.EncryptorV3(
            encryptionKey: vector["enc_key_hex"]!.dataFromHexEncoding!,
            hmacKey: vector["hmac_key_hex"]!.dataFromHexEncoding!,
            iv: vector["iv_hex"]!.dataFromHexEncoding!)
        let ciphertext = encryptor.encrypt(data: vector["plaintext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext, name:"key encrypt")
    }

    let decryptor = RNCryptor.DecryptorV3(
        encryptionKey: vector["enc_key_hex"]!.dataFromHexEncoding!,
        hmacKey: vector["hmac_key_hex"]!.dataFromHexEncoding!)
    do {
        let plaintext = try decryptor.decrypt(data: vector["ciphertext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"plaintext_hex", equals:plaintext, name:"key decrypt")
    } catch {
        XCTFail("\(error)")
    }
}
