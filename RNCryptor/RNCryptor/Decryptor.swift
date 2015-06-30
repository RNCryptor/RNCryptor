//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

public func decrypt(data: [UInt8], password: String) throws -> [UInt8] {
    let sink = DataSink()
    let decryptor = Decryptor(password: password, sink: sink)
    try decryptor.put(data)
    try decryptor.finish()
    return sink.array
}

public func decrypt(data: [UInt8], encryptionKey: [UInt8], hmacKey: [UInt8]) throws -> [UInt8] {
    let sink = DataSink()
    let decryptor = Decryptor(encryptionKey: encryptionKey, hmacKey: hmacKey, sink: sink)
    try decryptor.put(data)
    try decryptor.finish()
    return sink.array
}

protocol DecryptorType: DataSinkType {
    func finish() throws
}

public final class Decryptor: DataSinkType {
    private let decryptors: [(headerLength: Int, builder: ([UInt8]) -> DecryptorType?)]
    private var buffer: [UInt8] = []

    private var decryptor: DecryptorType?

    public init(password: String, sink: DataSinkType) {
        assert(password != "")

        self.decryptors = [
            (DecryptorV3.passwordHeaderLength, { DecryptorV3(password: password, header: $0, sink: sink) as DecryptorType? })
        ]
    }

    public init(encryptionKey: [UInt8], hmacKey: [UInt8], sink: DataSinkType) {
        self.decryptors = [
            (DecryptorV3.keyHeaderLength, { DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey, header: $0, sink: sink) as DecryptorType? })
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
    
    public func finish() throws {
        try self.decryptor?.finish()
    }
}