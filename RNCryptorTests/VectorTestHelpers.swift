//
//  VectorTestHelpers.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import XCTest
@testable import RNCryptor

func verifyVector(vector: [String:String], key:String, equals actual:NSData, name:String) {
    let version = vector["version"]!
    let title = vector["title"]!
    XCTAssertEqual(actual, vector[key]!.dataFromHexEncoding!, "Failed \(name) test (v\(version)): \(title)")
}

func _verifyKDF(vector: [String:String], name:String) {
    let key = RNCryptorV3.keyForPassword(vector["password"]!,
        salt:vector["salt_hex"]!.dataFromHexEncoding!)
    verifyVector(vector, key:"key_hex", equals:key, name: name)
}


func verify_v3_kdf(vector: [String:String]) {
    _verifyKDF(vector, name:"kdf")
}


func _verifyPassword(vector: [String:String]) {
    if Int(vector["version"]!) == Int(V3.version) {
        let encryptor = Encryptor(password: vector["password"]!,
            encryptionSalt: vector["enc_salt_hex"]!.dataFromHexEncoding!,
            hmacSalt: vector["hmac_salt_hex"]!.dataFromHexEncoding!,
            iv: vector["iv_hex"]!.dataFromHexEncoding!)
        let ciphertext = encryptor.encryptData(vector["plaintext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext, name:"password encrypt")
    }

    let decryptor = Decryptor(password: vector["password"]!)
    do {
        let plaintext = try decryptor.decryptData(vector["ciphertext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"plaintext_hex", equals:plaintext, name:"password decrypt")
    } catch {
        XCTFail("\(error)")
    }
}

func verify_v3_password(vector: [String: String]) {
    _verifyPassword(vector)
}

func verify_v3_key(vector: [String: String]) {
    if Int(vector["version"]!) == Int(V3.version) {
        let encryptor = Encryptor(
            encryptionKey: vector["enc_key_hex"]!.dataFromHexEncoding!,
            hmacKey: vector["hmac_key_hex"]!.dataFromHexEncoding!,
            iv: vector["iv_hex"]!.dataFromHexEncoding!)
        let ciphertext = encryptor.encryptData(vector["plaintext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext, name:"key encrypt")
    }

    let decryptor = DecryptorV3(
        encryptionKey: vector["enc_key_hex"]!.dataFromHexEncoding!,
        hmacKey: vector["hmac_key_hex"]!.dataFromHexEncoding!)
    do {
        let plaintext = try decryptor.decryptData(vector["ciphertext_hex"]!.dataFromHexEncoding!)
        verifyVector(vector, key:"plaintext_hex", equals:plaintext, name:"key decrypt")
    } catch {
        XCTFail("\(error)")
    }
}