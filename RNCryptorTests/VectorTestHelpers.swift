//
//  VectorTestHelpers.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import XCTest
@testable import RNCryptor

func verifyVector(vector: [String:String], key:String, equals actual:[UInt8], name:String) {
    let version = vector["version"]!
    let title = vector["title"]!
    XCTAssertEqual(actual, vector[key]!.byteArrayFromHexEncoding!, "Failed \(name) test (v\(version)): \(title)")
}

func _verifyKDF(vector: [String:String], name:String) {
    let key = RNCryptorV3.keyForPassword(vector["password"]!,
        salt:vector["salt_hex"]!.byteArrayFromHexEncoding!)
    verifyVector(vector, key:"key_hex", equals:key, name: name)
}


func verify_v3_kdf(vector: [String:String]) {
    _verifyKDF(vector, name:"kdf")
}


func _verifyPassword(vector: [String:String]) {
    if Int(vector["version"]!) == FormatVersion {
        let ciphertext = ArrayWriter()
        let encryptor = Encryptor(password: vector["password"]!,
            encryptionSalt: vector["enc_salt_hex"]!.byteArrayFromHexEncoding!,
            hmacSalt: vector["hmac_salt_hex"]!.byteArrayFromHexEncoding!,
            iv: vector["iv_hex"]!.byteArrayFromHexEncoding!,
            sink: ciphertext)
        do {
            try encryptor.write(vector["plaintext_hex"]!.byteArrayFromHexEncoding!)
            try encryptor.finish()
        } catch {
            XCTFail("\(error)")
        }
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext.array, name:"password encrypt")
    }

    let plaintext = ArrayWriter()
    let decryptor = Decryptor(password: vector["password"]!,
        sink: plaintext)
    do {
        try decryptor.write(vector["ciphertext_hex"]!.byteArrayFromHexEncoding!)
        try decryptor.finish()
    } catch {
        XCTFail("\(error)")
    }
    verifyVector(vector, key:"plaintext_hex", equals:plaintext.array, name:"password decrypt")
}

func verify_v3_password(vector: [String: String]) {
    _verifyPassword(vector)
}

func verify_v3_key(vector: [String: String]) {
    if Int(vector["version"]!) == FormatVersion {
        let ciphertext = ArrayWriter()
        let encryptor = Encryptor(
            encryptionKey: vector["enc_key_hex"]!.byteArrayFromHexEncoding!,
            hmacKey: vector["hmac_key_hex"]!.byteArrayFromHexEncoding!,
            iv: vector["iv_hex"]!.byteArrayFromHexEncoding!,
            sink: ciphertext)
        do {
            try encryptor.write(vector["plaintext_hex"]!.byteArrayFromHexEncoding!)
            try encryptor.finish()
        } catch {
            XCTFail("\(error)")
        }
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext.array, name:"key encrypt")
    }

    let plaintext = ArrayWriter()
    let decryptor = Decryptor(
        encryptionKey: vector["enc_key_hex"]!.byteArrayFromHexEncoding!,
        hmacKey: vector["hmac_key_hex"]!.byteArrayFromHexEncoding!,
        sink: plaintext)
    do {
        try decryptor.write(vector["ciphertext_hex"]!.byteArrayFromHexEncoding!)
        try decryptor.finish()
    } catch {
        XCTFail("\(error)")
    }
    verifyVector(vector, key:"plaintext_hex", equals:plaintext.array, name:"key decrypt")
}