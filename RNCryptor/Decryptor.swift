//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

protocol PasswordDecryptorType: CryptorType {
    static var preambleSize: Int { get }
    static func canDecrypt(preamble: ArraySlice<UInt8>) -> Bool
    init(password: String)
}

public final class Decryptor : CryptorType {
    private let decryptors: [PasswordDecryptorType.Type] = [DecryptorV3.self]
    private var buffer: [UInt8] = []
    private var decryptor: CryptorType?
    private let password: String

    public init(password: String) {
        assert(password != "")
        self.password = password
    }

    public func decrypt(data: [UInt8]) throws -> [UInt8] {
        return try oneshot(data)
    }

    func update(data: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        if let d = decryptor {
            return try d.update(data)
        }

        buffer += data

        // FIXME: This assumes that the largest preamble is smaller than the smallest possible total message.
        // Change to test decryptors as soon as we know they're large enough.
        let maxHeaderLength = decryptors.reduce(0) { max($0, $1.preambleSize) }
        guard buffer.count >= maxHeaderLength else {
            return []
        }

        for decryptorType in self.decryptors {
            if decryptorType.canDecrypt(buffer[0..<decryptorType.preambleSize]) {
                let d = decryptorType.init(password: password)
                decryptor = d
                let result = try d.update(buffer)
                buffer.removeAll()
                return result
            }
        }
        throw Error.UnknownHeader
    }

    func final() throws -> [UInt8] {
        guard let d = decryptor else {
            throw Error.UnknownHeader
        }
        return try d.final()
    }
}