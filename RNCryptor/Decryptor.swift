//
//  Decryptor.swift
//
//  Copyright © 2015 Rob Napier. All rights reserved.
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
//

import Foundation

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

@objc(RNDecryptor)
public final class Decryptor : NSObject, CryptorType {
    private var decryptors: [PasswordDecryptorType.Type] = [DecryptorV3.self]

    private var buffer = NSMutableData()
    private var decryptor: CryptorType?
    private let password: String

    public init(password: String) {
        assert(password != "")
        self.password = password
    }

    public func decryptData(data: NSData) throws -> NSData {
        return try oneshot(data)
    }

    public func updateWithData(data: NSData) throws -> NSData {
        if let d = decryptor {
            return try d.updateWithData(data)
        }

        buffer.appendData(data)

        let toCheck:[PasswordDecryptorType.Type]
        (toCheck, decryptors) = decryptors.splitPassFail{ self.buffer.length >= $0.preambleSize }

        for decryptorType in toCheck {
            if decryptorType.canDecrypt(buffer.bytesView[0..<decryptorType.preambleSize]) {
                let d = decryptorType.init(password: password)
                decryptor = d
                let result = try d.updateWithData(buffer)
                buffer.length = 0
                return result
            }
        }

        guard !decryptors.isEmpty else { throw CryptorError.UnknownHeader }
        return NSData()
    }

    public func finalData() throws -> NSData {
        guard let d = decryptor else {
            throw CryptorError.UnknownHeader
        }
        return try d.finalData()
    }
}