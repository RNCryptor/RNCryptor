//
//  RNCryptor.swift
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

public protocol CryptorType {
    init(password: String)
    func updateWithData(data: NSData) throws -> NSData
    func finalData() throws -> NSData
}

public extension CryptorType {
    internal func oneshot(data: NSData) throws -> NSData {
        let result = NSMutableData(data: try updateWithData(data))
        result.appendData(try finalData())
        return result
    }
}

@objc public enum CryptorError: Int, ErrorType {
    case HMACMismatch = 1
    case UnknownHeader
    case MessageTooShort
    case MemoryFailure
    case ParameterError
    case InvalidCredentialType
}

public typealias Encryptor = EncryptorV3

@objc(RNCryptor)
public class Cryptor: NSObject {
    public static func encryptData(data: NSData, password: String) -> NSData {
        return Encryptor(password: password).encryptData(data)
    }

    public static func decryptData(data: NSData, password: String) throws -> NSData {
        return try Decryptor(password: password).decryptData(data)
    }
}
