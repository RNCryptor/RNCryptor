//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

public final class Decryptor: CryptorType, Writable {
    private let decryptors: [(headerLength: Int, builder: ([UInt8]) -> CryptorType?)]
    private var buffer: [UInt8] = []

    private var decryptor: CryptorType?

    public init(password: String, sink: Writable) {
        assert(password != "")

        self.decryptors = [
            (RNCryptorV3.passwordHeaderSize, { DecryptorV3(password: password, header: $0, sink: sink) as CryptorType? })
        ]
    }

    public init(encryptionKey: [UInt8], hmacKey: [UInt8], sink: Writable) {
        self.decryptors = [
            (RNCryptorV3.keyHeaderSize, { DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey, header: $0, sink: sink) as CryptorType? })
        ]
    }

    public func write(data: UnsafeBufferPointer<UInt8>) throws {
        if let decryptor = self.decryptor {
            try decryptor.write(data)
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
                    try self.decryptor?.write(content)
                    return
                }
            }
            throw Error.UnknownHeader
        }
    }
    
    public func finish() throws {
        try self.decryptor?.finish()
    }
}