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
import CommonCrypto


/// The `RNCryptorType` protocol defines generic API to a mutable,
/// incremental, password-based encryptor or decryptor. Its generic
/// usage is as follows:
///
///     let cryptor = Encryptor(password: "mypassword")
///     // or Decryptor()
///
///     var result = Data()
///     for data in datas {
///         result.appendData(try cryptor.update(data))
///     }
///     result.appendData(try cryptor.final())
///
///  After calling `finalData()`, the cryptor is no longer valid.
public protocol RNCryptorType {

    /// Creates and returns a cryptor.
    ///
    /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
    init(password: String)

    /// Updates cryptor with data and returns processed data.
    ///
    /// - parameter data: Data to process. May be empty.
    /// - throws: `Error`
    /// - returns: Processed data. May be empty.
    func update(withData data: Data) throws -> Data

    /// Returns trailing data and invalidates the cryptor.
    ///
    /// - throws: `Error`
    /// - returns: Trailing data
    func finalData() throws -> Data
}

public extension RNCryptorType {
    /// Simplified, generic interface to `RNCryptorType`. Takes a data,
    /// returns a processed data. Generally you should use
    /// `RNCryptor.encrypt(data:withPassword:)`, or
    /// `RNCryptor.decrypt(data:withPassword:)` instead, but this is useful
    /// for code that is neutral on whether it is encrypting or decrypting.
    ///
    /// - throws: `Error`
    fileprivate func oneshot(data: Data) throws -> Data {
        var result = try update(withData: data)
        result.append(try finalData())
        return result
    }
}

/// RNCryptor encryption/decryption interface.
public enum RNCryptor {

    /// Errors thrown by `RNCryptorType`.
    public enum Error: Int, Swift.Error {
        /// Ciphertext was corrupt or password was incorrect.
        /// It is not possible to distinguish between these cases in the v3 data format.
        case hmacMismatch = 1

        /// Unrecognized data format. Usually this means the data is corrupt.
        case unknownHeader = 2

        /// `final()` was called before sufficient data was passed to `update(withData:)`
        case messageTooShort

        /// Memory allocation failure. This should never happen.
        case memoryFailure

        /// A password-based decryptor was used on a key-based ciphertext, or vice-versa.
        case invalidCredentialType
    }

    /// Encrypt data using password and return encrypted data.
    public static func encrypt(data: Data, withPassword password: String) -> Data {
        return Encryptor(password: password).encrypt(data: data)
    }

    /// Decrypt data using password and return decrypted data. Throws if
    /// password is incorrect or ciphertext is in the wrong format.
    /// - throws `Error`
    public static func decrypt(data: Data, withPassword password: String) throws -> Data {
        return try Decryptor(password: password).decrypt(data: data)
    }

    /// Generates random Data of given length
    /// Crashes if `length` is larger than allocatable memory, or if the system random number generator is not available.
    public static func randomData(ofLength length: Int) -> Data {
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        guard result == errSecSuccess else {
            fatalError("SECURITY FAILURE: Could not generate secure random numbers: \(result).")
        }
        return data
    }

    /// A encryptor for the latest data format. If compatibility with other RNCryptor
    /// implementations is required, you may wish to use the specific encryptor version rather
    /// than accepting "latest."
    ///
    public final class Encryptor: RNCryptorType {
        private let encryptor: EncryptorV3

        /// Creates and returns a cryptor.
        ///
        /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
        public init(password: String) {
            precondition(password != "")
            encryptor = EncryptorV3(password: password)
        }

        /// Updates cryptor with data and returns processed data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - returns: Processed data. May be empty.
        public func update(withData data: Data) -> Data {
            return encryptor.update(withData: data)
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - returns: Trailing data
        public func finalData() -> Data {
            return encryptor.finalData()
        }

        /// Simplified, generic interface to `RNCryptorType`. Takes a data,
        /// returns a processed data, and invalidates the cryptor.
        public func encrypt(data: Data) -> Data {
            return encryptor.encrypt(data: data)
        }
    }

    /// Password-based decryptor that can handle any supported format.
    public final class Decryptor : RNCryptorType {
        private var decryptors: [VersionedDecryptorType.Type] = [DecryptorV3.self]

        private var buffer = Data()
        private var decryptor: RNCryptorType?
        private let password: String

        /// Creates and returns a cryptor.
        ///
        /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
        public init(password: String) {
            assert(password != "")
            self.password = password
        }

        /// Decrypt data using password and return decrypted data, invalidating decryptor. Throws if
        /// password is incorrect or ciphertext is in the wrong format.
        /// - throws `Error`
        public func decrypt(data: Data) throws -> Data {
            return try oneshot(data: data)
        }

        /// Updates cryptor with data and returns processed data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - throws: `Error`
        /// - returns: Processed data. May be empty.
        public func update(withData data: Data) throws -> Data {
            if let d = decryptor {
                return try d.update(withData: data)
            }

            buffer.append(data)

            let toCheck:[VersionedDecryptorType.Type]
            (toCheck, decryptors) = decryptors.splitPassFail { self.buffer.count >= $0.preambleSize }

            for decryptorType in toCheck {
                if decryptorType.canDecrypt(preamble: buffer.subdata(in: 0..<decryptorType.preambleSize)) {
                    let d = decryptorType.init(password: password)
                    decryptor = d
                    let result = try d.update(withData: buffer)
                    buffer.count = 0
                    return result
                }
            }

            guard !decryptors.isEmpty else { throw Error.unknownHeader }
            return Data()
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - throws: `Error`
        /// - returns: Trailing data
        public func finalData() throws -> Data {
            guard let d = decryptor else {
                throw Error.unknownHeader
            }
            return try d.finalData()
        }
    }
}

// V3 implementaion
public extension RNCryptor {
    /// V3 format settings
    final class FormatV3 {
        /// Size of AES and HMAC keys
        public static let keySize = kCCKeySizeAES256

        /// Size of PBKDF2 salt
        public static let saltSize = 8

        /// Generate a key from a password and salt
        /// - parameters:
        ///     - password: Password to convert
        ///     - salt: Salt. Generally constructed with RNCryptor.randomDataOfLength(FormatV3.saltSize)
        /// - returns: Key of length FormatV3.keySize
        public static func makeKey(forPassword password: String, withSalt salt: Data) -> Data {

            let passwordArray = password.utf8.map(Int8.init)
            let saltArray = Array(salt)

            var derivedKey = Array<UInt8>(repeating: 0, count: keySize)

            // All the crazy casting because CommonCryptor hates Swift
            let algorithm    = CCPBKDFAlgorithm(kCCPBKDF2)
            let prf          = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
            let pbkdf2Rounds = UInt32(10000)

            let result = CCCryptorStatus(
                CCKeyDerivationPBKDF(
                    algorithm,
                    passwordArray, passwordArray.count,
                    saltArray,     saltArray.count,
                    prf,           pbkdf2Rounds,
                    &derivedKey,   keySize)
            )
            guard result == CCCryptorStatus(kCCSuccess) else {
                fatalError("SECURITY FAILURE: Could not derive secure password (\(result))")
            }
            return Data(derivedKey)
        }

        static let formatVersion = UInt8(3)
        static let ivSize = kCCBlockSizeAES128
        static let hmacSize = Int(CC_SHA256_DIGEST_LENGTH)
        static let keyHeaderSize = 1 + 1 + kCCBlockSizeAES128
        static let passwordHeaderSize = 1 + 1 + 8 + 8 + kCCBlockSizeAES128
    }

    /// Format version 3 encryptor. Use this to ensure a specific format verison
    /// or when using keys (which are inherrently versions-specific). To use
    /// "the latest encryptor" with a password, use `Encryptor` instead.
    final class EncryptorV3 : RNCryptorType {
        private let engine: Engine
        private let hmac: HMACV3
        private var pendingHeader: Data?

        /// Creates and returns an encryptor.
        ///
        /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
        public convenience init(password: String) {
            self.init(
                password: password,
                encryptionSalt: RNCryptor.randomData(ofLength: V3.saltSize),
                hmacSalt: RNCryptor.randomData(ofLength: V3.saltSize),
                iv: RNCryptor.randomData(ofLength: V3.ivSize))
        }

        /// Creates and returns an encryptor using keys.
        ///
        /// - Attention: This method requires some expertise to use correctly.
        ///              Most users should use `init(password:)` which is simpler
        ///              to use securely.
        ///
        /// Keys should not be generated directly from strings (`.dataUsingEncoding()` or similar).
        /// Ideally, keys should be random (`Cryptor.randomDataOfLength()` or some other high-quality
        /// random generator. If keys must be generated from strings, then use `FormatV3.keyForPassword(salt:)`
        /// with a random salt, or just use password-based encryption (that's what it's for).
        ///
        /// - parameters:
        ///     - encryptionKey: AES-256 key. Must be exactly FormatV3.keySize (kCCKeySizeAES256, 32 bytes)
        ///     - hmacKey: HMAC key. Must be exactly FormatV3.keySize (kCCKeySizeAES256, 32 bytes)
        public convenience init(encryptionKey: Data, hmacKey: Data) {
            self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: RNCryptor.randomData(ofLength: V3.ivSize))
        }

        /// Takes a data, returns a processed data, and invalidates the cryptor.
        public func encrypt(data: Data) -> Data {
            return try! oneshot(data: data)
        }

        /// Updates cryptor with data and returns encrypted data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - returns: Processed data. May be empty.
        public func update(withData data: Data) -> Data {
            // It should not be possible for this to fail during encryption
            return handle(data: engine.update(withData: data))
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - returns: Trailing data
        public func finalData() -> Data {
            var result = handle(data: engine.finalData())
            result.append(hmac.finalData())
            return result
        }

        // Expose random numbers for testing
        internal convenience init(encryptionKey: Data, hmacKey: Data, iv: Data) {
            let preamble = [V3.formatVersion, UInt8(0)]
            var header = Data(preamble)
            header.append(iv)
            self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }

        // Expose random numbers for testing
        internal convenience init(password: String, encryptionSalt: Data, hmacSalt: Data, iv: Data) {
            let encryptionKey = V3.makeKey(forPassword: password, withSalt: encryptionSalt)
            let hmacKey = V3.makeKey(forPassword: password, withSalt: hmacSalt)

            let preamble = [V3.formatVersion, UInt8(1)]
            var header = Data(preamble)
            header.append(encryptionSalt)
            header.append(hmacSalt)
            header.append(iv)

            self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }

        private init(encryptionKey: Data, hmacKey: Data, iv: Data, header: Data) {
            precondition(encryptionKey.count == V3.keySize)
            precondition(hmacKey.count == V3.keySize)
            precondition(iv.count == V3.ivSize)
            hmac = HMACV3(key: hmacKey)
            engine = Engine(operation: .encrypt, key: encryptionKey, iv: iv)
            pendingHeader = header
        }

        private func handle(data: Data) -> Data {
            let result: Data
            if var accum = pendingHeader {
                pendingHeader = nil
                accum.append(data)
                result = accum
            } else {
                result = data
            }
            hmac.update(withData: result)
            return result
        }
    }

    /// Format version 3 decryptor. This is required in order to decrypt
    /// using keys (since key configuration is version-specific). For password
    /// decryption, `Decryptor` is generally preferred, and will call this
    /// if appropriate.
    final class DecryptorV3: VersionedDecryptorType {
        //
        // Static methods
        //
        fileprivate static let preambleSize = 1
        fileprivate static func canDecrypt(preamble: Data) -> Bool {
            assert(preamble.count >= 1)
            return preamble[0] == 3
        }

        //
        // Private properties
        //
        private var buffer = Data()
        private var decryptorEngine: DecryptorEngineV3?
        private let credential: Credential


        /// Creates and returns a decryptor.
        ///
        /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
        public init(password: String) {
            credential = .password(password)
        }

        /// Creates and returns a decryptor using keys.
        ///
        /// - parameters:
        ///     - encryptionKey: AES-256 key. Must be exactly FormatV3.keySize (kCCKeySizeAES256, 32 bytes)
        ///     - hmacKey: HMAC key. Must be exactly FormatV3.keySize (kCCKeySizeAES256, 32 bytes)
        public init(encryptionKey: Data, hmacKey: Data) {
            precondition(encryptionKey.count == V3.keySize)
            precondition(hmacKey.count == V3.hmacSize)
            credential = .keys(encryptionKey: encryptionKey, hmacKey: hmacKey)
        }

        /// Decrypt data using password and return decrypted data. Throws if
        /// password is incorrect or ciphertext is in the wrong format.
        /// - throws `Error`
        public func decrypt(data: Data) throws -> Data {
            return try oneshot(data: data)
        }

        /// Updates cryptor with data and returns encrypted data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - returns: Processed data. May be empty.
        public func update(withData data: Data) throws -> Data {
            if let e = decryptorEngine {
                return e.update(withData: data)
            }

            buffer.append(data)
            guard buffer.count >= requiredHeaderSize else {
                return Data()
            }

            let e = try makeEngine(credential: credential, header: buffer.subdata(in: 0..<requiredHeaderSize))
            decryptorEngine = e
            let body = buffer.subdata(in: requiredHeaderSize..<buffer.count)
            buffer.count = 0
            return e.update(withData: body)
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - returns: Trailing data
        public func finalData() throws -> Data {
            guard let result = try decryptorEngine?.finalData() else {
                throw Error.messageTooShort
            }
            return result
        }

        //
        // Private functions
        //

        private var requiredHeaderSize: Int {
            switch credential {
            case .password: return V3.passwordHeaderSize
            case .keys: return V3.keyHeaderSize
            }
        }

        private func makeEngine(credential: Credential, header: Data) throws -> DecryptorEngineV3 {
            switch credential {
            case let .password(password):
                return try makeEngine(password: password, header: header)
            case let .keys(encryptionKey, hmacKey):
                return try makeEngine(encryptionKey: encryptionKey, hmacKey: hmacKey, header: header)
            }
        }

        private func makeEngine(password: String, header: Data) throws -> DecryptorEngineV3 {
            assert(password != "")
            precondition(header.count == V3.passwordHeaderSize)

            guard DecryptorV3.canDecrypt(preamble: header) else {
                throw Error.unknownHeader
            }

            guard header[1] == 1 else {
                throw Error.invalidCredentialType
            }

            let encryptionSalt = header.subdata(in: Range(2...9))
            let hmacSalt = header.subdata(in: Range(10...17))
            let iv = header.subdata(in: Range(18...33))

            let encryptionKey = V3.makeKey(forPassword: password, withSalt: encryptionSalt)
            let hmacKey = V3.makeKey(forPassword: password, withSalt: hmacSalt)

            return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }

        private func makeEngine(encryptionKey: Data, hmacKey: Data, header: Data) throws -> DecryptorEngineV3 {
            precondition(header.count == V3.keyHeaderSize)
            precondition(encryptionKey.count == V3.keySize)
            precondition(hmacKey.count == V3.keySize)

            guard DecryptorV3.canDecrypt(preamble: header) else {
                throw Error.unknownHeader
            }

            guard header[1] == 0 else {
                throw Error.invalidCredentialType
            }

            let iv = header.subdata(in: 2..<18)
            return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }
    }
}

internal enum CryptorOperation: CCOperation {
    case encrypt = 0 // CCOperation(kCCEncrypt)
    case decrypt = 1 // CCOperation(kCCDecrypt)
}

internal final class Engine {
    private let cryptor: CCCryptorRef?
    private var buffer = Data()

    init(operation: CryptorOperation, key: Data, iv: Data) {

        cryptor = key.withUnsafeBytes { (keyPtr) in
            iv.withUnsafeBytes { (ivPtr) in

                var cryptorOut: CCCryptorRef?
                let result = CCCryptorCreate(
                    operation.rawValue,
                    CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
                    keyPtr.baseAddress!, keyPtr.count,
                    ivPtr.baseAddress!,
                    &cryptorOut
                )

                // It is a programming error to create us with illegal values
                // This is an internal class, so we can constrain what is sent to us.
                // If this is ever made public, it should throw instead of asserting.
                assert(result == CCCryptorStatus(kCCSuccess))
                return cryptorOut
            }
        }
    }

    deinit {
        if cryptor != nil {
            CCCryptorRelease(cryptor)
        }
    }

    func sizeBuffer(forDataLength length: Int) -> Int {
        let size = CCCryptorGetOutputLength(cryptor, length, true)
        buffer.count = size
        return size
    }

    func update(withData data: Data) -> Data {
        let outputLength = sizeBuffer(forDataLength: data.count)
        var dataOutMoved = 0

        let result = data.withUnsafeBytes { dataPtr in
            buffer.withUnsafeMutableBytes { bufferPtr in
                return CCCryptorUpdate(
                    cryptor,
                    dataPtr.baseAddress!, dataPtr.count,
                    bufferPtr.baseAddress!, outputLength,
                    &dataOutMoved)
            }
        }

        // The only error returned by CCCryptorUpdate is kCCBufferTooSmall, which would be a programming error
        assert(result == CCCryptorStatus(kCCSuccess), "RNCRYPTOR BUG. PLEASE REPORT. (\(result)")

        buffer.count = dataOutMoved
        return buffer
    }

    func finalData() -> Data {
        let outputLength = sizeBuffer(forDataLength: 0)
        var dataOutMoved = 0

        let result = buffer.withUnsafeMutableBytes {
            CCCryptorFinal(
                cryptor,
                $0.baseAddress!, outputLength,
                &dataOutMoved
            )
        }

        // Note that since iOS 6, CCryptor will never return padding errors or other decode errors.
        // I'm not aware of any non-catastrophic (MemoryAllocation) situation in which this
        // can fail. Using assert() just in case, but we'll ignore errors in Release.
        // https://devforums.apple.com/message/920802#920802
        assert(result == CCCryptorStatus(kCCSuccess), "RNCRYPTOR BUG. PLEASE REPORT. (\(result)")

        buffer.count = dataOutMoved
        defer { buffer = Data() }
        return buffer
    }
}

internal typealias V3 = RNCryptor.FormatV3

private enum Credential {
    case password(String)
    case keys(encryptionKey: Data, hmacKey: Data)
}

private final class DecryptorEngineV3 {
    private let buffer = OverflowingBuffer(capacity: V3.hmacSize)
    private let hmac: HMACV3
    private let engine: Engine

    init(encryptionKey: Data, hmacKey: Data, iv: Data, header: Data) {
        precondition(encryptionKey.count == V3.keySize)
        precondition(hmacKey.count == V3.hmacSize)
        precondition(iv.count == V3.ivSize)

        hmac = HMACV3(key: hmacKey)
        hmac.update(withData: header)
        engine = Engine(operation: .decrypt, key: encryptionKey, iv: iv)
    }

    func update(withData data: Data) -> Data {
        let overflow = buffer.update(withData: data)
        hmac.update(withData: overflow)
        return engine.update(withData: overflow)
    }

    func finalData() throws -> Data {
        let hash = hmac.finalData()
        if !isEqualInConsistentTime(trusted: hash, untrusted: buffer.finalData()) {
            throw RNCryptor.Error.hmacMismatch
        }
        return engine.finalData()
    }
}

private final class HMACV3 {
    var context = CCHmacContext()

    init(key: Data) {
        key.withUnsafeBytes {
            CCHmacInit(
                &context,
                CCHmacAlgorithm(kCCHmacAlgSHA256),
                $0.baseAddress!,
                key.count
            )
        }
    }

    func update(withData data: Data) {
        data.withUnsafeBytes { CCHmacUpdate(&context, $0.baseAddress!, data.count) }
    }

    func finalData() -> Data {
        var hmac = Data(count: V3.hmacSize)
        hmac.withUnsafeMutableBytes { CCHmacFinal(&context, $0.baseAddress!) }
        return hmac
    }
}

// Internal protocol for version-specific decryptors.
private protocol VersionedDecryptorType: RNCryptorType {
    static var preambleSize: Int { get }
    static func canDecrypt(preamble: Data) -> Bool
    init(password: String)
}

private extension Collection {
    // Split collection into ([pass], [fail]) based on predicate.
    func splitPassFail(forPredicate predicate: (Iterator.Element) -> Bool) -> ([Iterator.Element], [Iterator.Element]) {
        var pass: [Iterator.Element] = []
        var fail: [Iterator.Element] = []
        for e in self {
            if predicate(e) {
                pass.append(e)
            } else {
                fail.append(e)
            }
        }
        return (pass, fail)
    }
}

internal final class OverflowingBuffer {
    private var buffer = Data()
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
    }

    func update(withData data: Data) -> Data {
        if data.count >= capacity {
            return sendAll(data: data)
        } else if buffer.count + data.count <= capacity {
            buffer.append(data)
            return Data()
        } else {
            return sendSome(data: data)
        }
    }

    func finalData() -> Data {
        let result = buffer
        buffer.count = 0
        return result
    }

    private func sendAll(data: Data) -> Data {
        let toSend = data.count - capacity
        assert(toSend >= 0)
        assert(data.count - toSend <= capacity)

        var result = buffer
        result.append(data.subdata(in: 0..<toSend))

        buffer.count = 0
        buffer.append(data.subdata(in: toSend..<data.count)) // TODO: Appending here to avoid later buffer growth, but maybe just buffer = data.subdata would be better
        return result
    }

    private func sendSome(data: Data) -> Data {
        let toSend = (buffer.count + data.count) - capacity
        assert(toSend > 0) // If it were <= 0, we would have extended the array
        assert(toSend < buffer.count) // If we would have sent everything, replaceBuffer should have been called

        let result = buffer.subdata(in: 0..<toSend)
        buffer.replaceSubrange(0..<toSend, with: Data())
        buffer.append(data)
        return result
    }
}

/** Compare two Datas in time proportional to the untrusted data

Equatable-based comparisons generally stop comparing at the first difference.
This can be used by attackers, in some situations,
to determine a secret value by considering the time required to compare the values.

We enumerate over the untrusted values so that the time is proportaional to the attacker's data,
which provides the attack no information about the length of the secret.
*/
private func isEqualInConsistentTime(trusted: Data, untrusted: Data) -> Bool {
    // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
    // If any bytes are different, then the OR will accumulate some non-0 value.
    
    var result: UInt8 = untrusted.count == trusted.count ? 0 : 1  // Start with 0 (equal) only if our lengths are equal
    for (i, untrustedByte) in untrusted.enumerated() {
        // Use mod to wrap around ourselves if they are longer than we are.
        // Remember, we already broke equality if our lengths are different.
        result |= trusted[i % trusted.count] ^ untrustedByte
    }
    
    return result == 0
}
