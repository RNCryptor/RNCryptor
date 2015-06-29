//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

protocol DecryptorType: DataSinkType {
    func finish() throws
}

public final class Decryptor: DataSinkType {
    private let decryptors: [(headerLength: Int, builder: ([UInt8]) -> DecryptorType?)]
    private var buffer: [UInt8] = []

    private var decryptor: DecryptorType?

    init(password: String, sink: DataSinkType) {
        assert(password != "")

        self.decryptors = [
            (PasswordDecryptorV3.headerLength, { PasswordDecryptorV3(password: password, header: $0, sink: sink) as DecryptorType? })
        ]
    }

    init(encryptionKey: [UInt8], hmacKey: [UInt8], sink: DataSinkType) {
        self.decryptors = [
            (KeyDecryptorV3.headerLength, { KeyDecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey, header: $0, sink: sink) as DecryptorType? })
        ]
    }

    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        if let decryptor = self.decryptor {
            try decryptor.put(data)
        } else {
            let maxHeaderLength = decryptors.reduce(0) { max($0, $1.headerLength) }
            guard self.buffer.count + data.count >= maxHeaderLength else {
                self.buffer.extend(data)
                return
            }

            for decryptorType in self.decryptors {
                let (dataHeader, content) = data.splitAt(decryptorType.headerLength - self.buffer.count)
                let header = self.buffer + dataHeader
                if let decryptor = decryptorType.builder(header) {
                    self.decryptor = decryptor
                    self.buffer.removeAll()
                    try self.decryptor?.put(content)
                    return
                }
            }
            throw Error.UnknownHeader
        }
    }
    func finish() throws {
        try self.decryptor?.finish()
    }
}