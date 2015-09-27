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

private extension CollectionType {
    func splitPassFail(pred: Generator.Element -> Bool) -> ([Generator.Element], [Generator.Element]) {
        var pass: [Generator.Element] = []
        var fail: [Generator.Element] = []
        for e in self {
            if pred(e) {
                pass.append(e)
            } else {
                fail.append(e)
            }
        }
        return (pass, fail)
    }
}

public final class Decryptor : CryptorType {
    private var decryptors: [PasswordDecryptorType.Type] = [DecryptorV3.self]

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

    public func decryptData(data: NSData) throws -> NSData {
        return try oneshotData(data)
    }

    public func update(data: UnsafeBufferPointer<UInt8>) throws -> [UInt8] {
        if let d = decryptor {
            return try d.update(data)
        }

        buffer += data

        let toCheck:[PasswordDecryptorType.Type]
        (toCheck, decryptors) = decryptors.splitPassFail{ self.buffer.count >= $0.preambleSize }

        for decryptorType in toCheck {
            if decryptorType.canDecrypt(buffer[0..<decryptorType.preambleSize]) {
                let d = decryptorType.init(password: password)
                decryptor = d
                let result = try d.update(buffer)
                buffer.removeAll()
                return result
            }
        }

        guard !decryptors.isEmpty else { throw Error.UnknownHeader }
        return []
    }

    public func final() throws -> [UInt8] {
        guard let d = decryptor else {
            throw Error.UnknownHeader
        }
        return try d.final()
    }
}