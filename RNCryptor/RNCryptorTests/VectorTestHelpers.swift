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
    XCTAssertEqual(actual, vector[key]!.dataFromHexString(), "Failed \(name) test (v\(version)): \(title)")
}

func _verifyKDF(vector: [String:String], name:String) {
//    assert(vector["title"] != nil);
//    assert(vector["version"] != nil);
//    assert(vector["password"] != nil);
//    assert(vector["salt_hex"] != nil);
//    assert(vector["key_hex"] != nil);

    let key = V3.keyForPassword(vector["password"]!,
        salt:vector["salt_hex"]!.dataFromHexString())
    verifyVector(vector, key:"key_hex", equals:key, name: name)
}


func verify_v3_kdf(vector: [String:String]) {
    _verifyKDF(vector, name:"kdf")
}


func _verifyPassword(vector: [String:String]) {
//    NSCParameterAssert(vector[@"title"]);
//    NSCParameterAssert(vector[@"version"]);
//    NSCParameterAssert(vector[@"password"]);
//    NSCParameterAssert(vector[@"iv_hex"]);
//    NSCParameterAssert(vector[@"enc_salt_hex"]);
//    NSCParameterAssert(vector[@"hmac_salt_hex"]);
//    NSCParameterAssert(vector[@"plaintext_hex"]);
//    NSCParameterAssert(vector[@"ciphertext_hex"]);

    if Int(vector["version"]!) == FormatVersion {
        let ciphertext = DataSink()
        let encryptor = Encryptor(password: vector["password"]!,
            encryptionSalt: vector["enc_salt_hex"]!.dataFromHexString(),
            hmacSalt: vector["hmac_salt_hex"]!.dataFromHexString(),
            iv: vector["iv_hex"]!.dataFromHexString(),
            sink: ciphertext)
        do {
            try encryptor.put(vector["plaintext_hex"]!.dataFromHexString())
            try encryptor.finish()
        } catch {
            XCTFail("\(error)")
        }
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext.array, name:"password encrypt")
    }

    let plaintext = DataSink()
    let decryptor = Decryptor(password: vector["password"]!,
        sink: plaintext)
    do {
        try decryptor.put(vector["ciphertext_hex"]!.dataFromHexString())
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
//    NSCParameterAssert(vector[@"title"]);
//    NSCParameterAssert(vector[@"version"]);
//    NSCParameterAssert(vector[@"enc_key_hex"]);
//    NSCParameterAssert(vector[@"hmac_key_hex"]);
//    NSCParameterAssert(vector[@"iv_hex"]);
//    NSCParameterAssert(vector[@"plaintext_hex"]);
//    NSCParameterAssert(vector[@"ciphertext_hex"]);

//    NSError *error;

    if Int(vector["version"]!) == FormatVersion {
        let ciphertext = DataSink()
        let encryptor = Encryptor(
            encryptionKey: vector["enc_key_hex"]!.dataFromHexString(),
            hmacKey: vector["hmac_key_hex"]!.dataFromHexString(),
            IV: vector["iv_hex"]!.dataFromHexString(),
            sink: ciphertext)
        do {
            try encryptor.put(vector["plaintext_hex"]!.dataFromHexString())
            try encryptor.finish()
        } catch {
            XCTFail("\(error)")
        }
        verifyVector(vector, key:"ciphertext_hex", equals:ciphertext.array, name:"key encrypt")
    }

    let plaintext = DataSink()
    let decryptor = Decryptor(
        encryptionKey: vector["enc_key_hex"]!.dataFromHexString(),
        hmacKey: vector["hmac_key_hex"]!.dataFromHexString(),
        sink: plaintext)
    do {
        try decryptor.put(vector["ciphertext_hex"]!.dataFromHexString())
        try decryptor.finish()
    } catch {
        XCTFail("\(error)")
    }
    verifyVector(vector, key:"plaintext_hex", equals:plaintext.array, name:"key decrypt")
}