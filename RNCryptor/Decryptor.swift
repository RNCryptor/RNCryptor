//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

protocol DecryptorType {
    func update(data: [UInt8]) throws -> [UInt8]
    func final() throws -> [UInt8]
}

public final class Decryptor {
    private let decryptors: [(headerLength: Int, builder: ([UInt8]) -> DecryptorType?)]
    private var buffer: [UInt8] = []

    private var decryptor: DecryptorType?

    public init(password: String) {
        assert(password != "")

        self.decryptors = [
            (RNCryptorV3.passwordHeaderSize, { DecryptorV3(password: password, header: $0) as DecryptorType? })
        ]
    }

    public init(encryptionKey: [UInt8], hmacKey: [UInt8]) {
        self.decryptors = [
            (RNCryptorV3.keyHeaderSize, { DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey, header: $0) as DecryptorType? })
        ]
    }

    @warn_unused_result
    public func update(data: [UInt8]) throws -> [UInt8] {
        if let decryptor = self.decryptor {
            return try decryptor.update(data)
        } else {
            let maxHeaderLength = decryptors.reduce(0) { max($0, $1.headerLength) }
            guard self.buffer.count + data.count >= maxHeaderLength else {
                self.buffer += data
                return []
            }

            for decryptorType in self.decryptors {
                let (dataHeader, content) = data.splitAt(decryptorType.headerLength - self.buffer.count)
                let header = self.buffer + dataHeader
                if let decryptor = decryptorType.builder(header) {
                    self.decryptor = decryptor
                    self.buffer.removeAll()
                    return try decryptor.update(Array(content)) // FIXME: Copy
                }
            }
            throw Error.UnknownHeader
        }
    }
    
    public func final() throws -> [UInt8] {
        return try self.decryptor?.final() ?? []
    }
}