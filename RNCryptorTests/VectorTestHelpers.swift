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
    verifyVector(vector, key:"key_hex", equals:key.bytes, name: name)
}


func verify_v3_kdf(vector: [String:String]) {
    _verifyKDF(vector, name:"kdf")
}


func _verifyPassword(vector: [String:String]) {
    if Int(vector["version"]!) == FormatVersion {
        let encryptor = Encryptor(password: vector["password"]!,
            encryptionSalt: vector["enc_salt_hex"]!.byteArrayFromHexEncoding!,
            hmacSalt: vector["hmac_salt_hex"]!.byteArrayFromHexEncoding!,
            iv: RNCryptorV3IV(vector["iv_hex"]!.byteArrayFromHexEncoding!)!)
        do {
            let ciphertext = try encryptor.update(vector["plaintext_hex"]!.byteArrayFromHexEncoding!) + encryptor.final()
            verifyVector(vector, key:"ciphertext_hex", equals:ciphertext, name:"password encrypt")
        } catch {
            XCTFail("\(error)")
        }
    }

    let decryptor = Decryptor(password: vector["password"]!)
    do {
        let plaintext = try decryptor.update(vector["ciphertext_hex"]!.byteArrayFromHexEncoding!) + decryptor.final()
        verifyVector(vector, key:"plaintext_hex", equals:plaintext, name:"password decrypt")
    } catch {
        XCTFail("\(error)")
    }
}

func verify_v3_password(vector: [String: String]) {
    _verifyPassword(vector)
}

func verify_v3_key(vector: [String: String]) {
    if Int(vector["version"]!) == FormatVersion {
        let encryptor = Encryptor(
            encryptionKey: RNCryptorV3Key(vector["enc_key_hex"]!.byteArrayFromHexEncoding!)!,
            hmacKey: RNCryptorV3Key(vector["hmac_key_hex"]!.byteArrayFromHexEncoding!)!,
            iv: RNCryptorV3IV(vector["iv_hex"]!.byteArrayFromHexEncoding!)!)
        do {
            let ciphertext = try encryptor.update(vector["plaintext_hex"]!.byteArrayFromHexEncoding!) + encryptor.final()
            verifyVector(vector, key:"ciphertext_hex", equals:ciphertext, name:"key encrypt")
        } catch {
            XCTFail("\(error)")
        }
    }

    let decryptor = Decryptor(
        encryptionKey: RNCryptorV3Key(vector["enc_key_hex"]!.byteArrayFromHexEncoding!)!,
        hmacKey: RNCryptorV3Key(vector["hmac_key_hex"]!.byteArrayFromHexEncoding!)!)
    do {
        let plaintext = try decryptor.update(vector["ciphertext_hex"]!.byteArrayFromHexEncoding!) + decryptor.final()
        verifyVector(vector, key:"plaintext_hex", equals:plaintext, name:"key decrypt")
    } catch {
        XCTFail("\(error)")
    }
}