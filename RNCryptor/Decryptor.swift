//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

public final class Decryptor : CryptorType {
    private let decryptors: [(headerLength: Int, builder: ([UInt8]) -> CryptorType?)]
    private var buffer: [UInt8] = []

    private var decryptor: CryptorType?

    public init(password: String) {
        assert(password != "")

        self.decryptors = [
            (V3.passwordHeaderSize, { DecryptorV3(password: password, header: $0) as CryptorType? })
        ]
    }

    public init(encryptionKey: [UInt8], hmacKey: [UInt8]) {
        self.decryptors = [
            (V3.keyHeaderSize, { DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey, header: $0) as CryptorType? })
        ]
    }

    public func decrypt(data: [UInt8]) throws -> [UInt8] {
        return try process(self, data: data)
    }

    func update(data: [UInt8], body: ([UInt8]) throws -> Void) throws {
        if let decryptor = self.decryptor {
            try decryptor.update(data, body: body)
            return
        }

        let maxHeaderLength = decryptors.reduce(0) { max($0, $1.headerLength) }
        guard self.buffer.count + data.count >= maxHeaderLength else {
            self.buffer += data
            return
        }

        for decryptorType in self.decryptors {
            let (dataHeader, content) = data.splitAt(decryptorType.headerLength - self.buffer.count)
            let header = self.buffer + dataHeader
            if let decryptor = decryptorType.builder(header) {
                self.decryptor = decryptor
                self.buffer.removeAll()
                try decryptor.update(Array(content), body: body) // FIXME: Copy
                return
            }
        }
        throw Error.UnknownHeader
    }

    func final(body: ([UInt8]) throws -> Void) throws {
        try self.decryptor?.final(body)
    }
}