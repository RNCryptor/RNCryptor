//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/29/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

protocol PasswordDecryptorType: CryptorType {
    static var preambleSize: Int { get }
    static func canDecrypt(preamble: NSData) -> Bool
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

    private var buffer = NSMutableData()
    private var decryptor: CryptorType?
    private let password: String

    public init(password: String) {
        assert(password != "")
        self.password = password
    }

    public func decrypt(data: NSData) throws -> NSData {
        return try oneshot(data)
    }

    public func update(data: NSData) throws -> NSData {
        if let d = decryptor {
            return try d.update(data)
        }

        buffer.appendData(data)

        let toCheck:[PasswordDecryptorType.Type]
        (toCheck, decryptors) = decryptors.splitPassFail{ self.buffer.length >= $0.preambleSize }

        for decryptorType in toCheck {
            if decryptorType.canDecrypt(buffer.subdataWithRange(NSRange(0..<decryptorType.preambleSize))) {
                let d = decryptorType.init(password: password)
                decryptor = d
                let result = try d.update(buffer)
                buffer.length = 0
                return result
            }
        }

        guard !decryptors.isEmpty else { throw Error.UnknownHeader }
        return NSData()
    }

    public func final() throws -> NSData {
        guard let d = decryptor else {
            throw Error.UnknownHeader
        }
        return try d.final()
    }
}