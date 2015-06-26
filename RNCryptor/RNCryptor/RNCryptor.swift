//
//  RNCryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/12/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

public let CCErrorDomain = "com.apple.CommonCrypto"
public let KeySize = kCCKeySizeAES256
public let HMACSize = Int(CC_SHA256_DIGEST_LENGTH)
public let SaltSize = 8
public let Version = UInt8(3)
public let IVSize = kCCBlockSizeAES128

@objc public enum Error: Int, ErrorType {
    case HMACMismatch    = 1
    case UnknownHeader
    case MessageTooShort
    case MemoryFailure
    case ParameterError
}

public func randomDataOfLength(length: Int) throws -> [UInt8] {
    var data = [UInt8](count: length, repeatedValue: 0)

    let result = SecRandomCopyBytes(kSecRandomDefault, length, &data)
    if result != errSecSuccess {
        throw NSError(domain: CCErrorDomain, code: Int(errno), userInfo: nil)
    }

    return data
}

public func keyForPassword(password: String, salt: [UInt8]) throws -> [UInt8] {
    var derivedKey = [UInt8](count: KeySize, repeatedValue: 0)

    let passwordData = [UInt8](password.utf8)

    // All the crazy casting because CommonCryptor hates Swift
    let algorithm        = CCPBKDFAlgorithm(kCCPBKDF2)
    let passwordBytes    = UnsafePointer<Int8>(passwordData)
    let saltBytes        = UnsafePointer<UInt8>(salt)
    let prf              = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
    let rounds           = UInt32(10000)

    let result = CCKeyDerivationPBKDF(
        algorithm,
        passwordBytes, passwordData.count,
        saltBytes,     salt.count,
        prf,           rounds,
        &derivedKey,   derivedKey.count)

    if result != CCCryptorStatus(kCCSuccess) {
        throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
    }
    return derivedKey
}

public protocol DataSinkType /*: SinkType -- can I express this in Swift? */ {
    mutating func put(data: UnsafeBufferPointer<UInt8>) throws
}

public extension DataSinkType {
    public mutating func put(data: [UInt8]) throws {
        try data.withUnsafeBufferPointer {
            try self.put($0)
        }
    }
}


public final class DataSink: DataSinkType, CustomStringConvertible {
    public var array: [UInt8] = []
    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        self.array.extend(data)
    }
    public init() {}
    public var description: String {
        return "\(self.array)"
    }
}

private struct HMACSink: DataSinkType {
    var sink: DataSinkType
    var context: CCHmacContext

    init(key: [UInt8], sink: DataSinkType) throws {
        self.sink = sink

        guard key.count == KeySize else {
            throw Error.ParameterError
        }

        self.context = {
            var context = CCHmacContext()
            CCHmacInit(
                &context,
                CCHmacAlgorithm(kCCHmacAlgSHA256),
                key,
                key.count
            )
            return context
            }()
    }
    mutating func put(data: UnsafeBufferPointer<UInt8>) throws {
        CCHmacUpdate(&self.context, data.baseAddress, data.count)
    }

    mutating func final() -> [UInt8] {
        var hmac = Array<UInt8>(count: HMACSize, repeatedValue: 0)
        CCHmacFinal(&self.context, &hmac)
        return hmac
    }
}

private func checkResult(result: CCCryptorStatus) throws {
    guard result == CCCryptorStatus(kCCSuccess) else {
        throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
    }
}

public struct Encryptor: DataSinkType {
    public var sink: DataSinkType

    private var cryptor: Cryptor
    private var hmacSink: HMACSink

    public init(encryptionKey: [UInt8], HMACKey: [UInt8], sink: DataSinkType) throws {
        self.sink = sink

        self.hmacSink = try HMACSink(key: HMACKey, sink: sink)

        let iv = try randomDataOfLength(IVSize)

        self.cryptor = try Cryptor(operation: CCOperation(kCCEncrypt), key: encryptionKey, IV: HMACKey, sink: self.hmacSink)

        var header = [UInt8]()
        header.extend([Version, UInt8(0)])  // FIXME: Refactor to support password option
        header.extend(iv)

        try header.withUnsafeBufferPointer {
            try self.hmacSink.put($0)
        }
    }

    public mutating func put(data: UnsafeBufferPointer<UInt8>) throws {
        try self.hmacSink.put(data)
    }

    public mutating func finish() throws {
        try self.cryptor.finish()
        try self.sink.put(self.hmacSink.final())
    }
}

public struct Cryptor: DataSinkType {
    public var sink: DataSinkType

    private let cryptor: CCCryptorRef

    public init(operation: CCOperation, key: [UInt8], IV: [UInt8], sink: DataSinkType) throws {
        self.sink = sink

        guard key.count == KeySize else {
            throw Error.ParameterError
        }

        self.cryptor = try {
            var cryptorOut = CCCryptorRef()
            try checkResult(
                CCCryptorCreate(
                    operation,
                    CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
                    key, key.count,
                    IV,
                    &cryptorOut
                )
            )
            return cryptorOut
            }()
    }

    public mutating func put(data: UnsafeBufferPointer<UInt8>) throws {
        let outputLength = CCCryptorGetOutputLength(self.cryptor, data.count, false)
        var output = Array<UInt8>(count: outputLength, repeatedValue: 0)  // FIXME: Reuse buffer
        var dataOutMoved: Int = 0
        try checkResult(CCCryptorUpdate(
            self.cryptor,
            data.baseAddress, data.count,
            &output, outputLength,
            &dataOutMoved))

        try output.withUnsafeBufferPointer {
            try self.sink.put(UnsafeBufferPointer(start: $0.baseAddress, count: dataOutMoved))
        }
    }

    public mutating func finish() throws {
        let outputLength = CCCryptorGetOutputLength(self.cryptor, 0, true)
        var output = Array<UInt8>(count: outputLength, repeatedValue: 0) // FIXME: Reuse buffer
        var dataOutMoved: Int = 0
        try checkResult(
            CCCryptorFinal(
                self.cryptor,
                &output, outputLength,
                &dataOutMoved
            )
        )

        try self.sink.put(UnsafeBufferPointer(start: output, count:dataOutMoved))
    }
}



//public func encryptData(data: NSData, encryptionKey: NSData, HMACKey: NSData) throws -> NSData {
//    guard encryptionKey.length == KeySize && HMACKey.length == KeySize
//        else { throw Error.ParameterError }
//
//    guard let message = NSMutableData(capacity: data.length + 66)
//        else { throw Error.MemoryFailure }
//
//    guard let cipherText = NSMutableData(length: data.length + IVSize)
//        else { throw Error.MemoryFailure }
//
//    guard let hmac = NSMutableData(length: HMACSize)
//        else { throw Error.MemoryFailure }
//
//    let options        = UInt8(0)
//    let encryptionSalt = try randomDataOfLength(SaltSize)
//    let HMACSalt       = try randomDataOfLength(SaltSize)
//    let iv             = try randomDataOfLength(IVSize)
//
//    var dataOutMoved = 0
//
//    let result = CCCrypt(
//        CCOperation(kCCEncrypt),
//        CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
//        encryptionKey.bytes,             encryptionKey.length,
//        iv.bytes,
//        data.bytes,                      data.length,
//        cipherText.mutableBytes,         cipherText.length,
//        &dataOutMoved)
//
//    if result != CCCryptorStatus(kCCSuccess) {
//        throw NSError(domain: CCErrorDomain, code: Int(result), userInfo: nil)
//    }
//
//    message.appendBytes([Version, options], length: 2) // version
//    message.appendData(encryptionSalt)
//    message.appendData(HMACSalt)
//    message.appendData(iv)
//    message.appendData(cipherText)
//
//    CCHmac(
//        CCHmacAlgorithm(kCCHmacAlgSHA256),
//        HMACKey.bytes, HMACKey.length,
//        message.bytes, message.length,
//        hmac.mutableBytes)
//
//    message.appendData(hmac)
//    return message
//}

//public func decryptData(data: NSData, encryptionKey: NSData, HMACKey: NSData) throws -> NSData {
//    assert(encryptionKey.length == KeySize)
//    assert(HMACKey.length == KeySize)
//
//    guard data.length > 50
//        else { throw Error.MessageTooShort }
//
//    guard let plaintext = NSMutableData(length: data.length)
//        else { throw Error.MemoryFailure }
//
//    guard let computedHMAC = NSMutableData(length: HMACSize)
//        else { throw Error.MemoryFailure }
//
//    let bytes = UnsafeBufferPointer(start: UnsafePointer<UInt8>(data.bytes), count: data.length)
//
//    let message = bytes[0..<(bytes.count - HMACSize)]
//    let hmac = bytes[(bytes.count - HMACSize)..<bytes.endIndex]
//
//    let version = message[0]
//    let options = message[1]
//    let iv = message[2..<(2+IVSize)]
//
//    guard bytes[0] == Version
//        else { throw Error.UnknownHeader }
//
//    guard bytes[1] == 0
//        else { throw Error.UnknownHeader }
//
//    let message = data.subdataWithRange(NSRange(location: 0, length: data.length - HMACSize))
//    let hmac = data.subdataWithRange(NSRange(location: data.length - HMACSize, length: HMACSize))
//
//
//    let iv = UnsafeBufferPointer(start: bytes, count: IVSize)
//    let cipherText = UnsafeBufferPointer(start: iv.baseAddress + iv.endIndex, count:
//
//
//    let iv = data.subdataWithRange(NSRange(location: 2, length: IVSize))
//    consumed += iv.length
//
//    let cipherText = data.subdataWithRange(NSRange(location: 2 + IVSize,
//        length: data.length - (consumed + HMACSize)))
//    consumed += cipherText.length
//
//
//    assert(data.length == consumed)
//
//
//
//}