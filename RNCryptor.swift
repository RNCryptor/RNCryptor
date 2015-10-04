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

/// The `RNCryptorType` protocol defines generic API to a mutable,
/// incremental, password-based encryptor or decryptor. Its generic
/// usage is as follows:
///
///     let cryptor = Encryptor(password: "mypassword")
///     // or Decryptor()
///
///     var result NSMutableData
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
    func updateWithData(data: NSData) throws -> NSData

    /// Returns trailing data and invalidates the cryptor.
    ///
    /// - throws: `Error`
    /// - returns: Trailing data
    func finalData() throws -> NSData
}

public extension RNCryptorType {
    /// Simplified, generic interface to `RNCryptorType`. Takes a data,
    /// returns a processed data. Generally you should use
    /// `RNCryptor.encryptData(password:)`, or
    /// `RNCryptor.decryptData(password:)` instead, but this is useful
    /// for code that is neutral on whether it is encrypting or decrypting.
    ///
    /// - throws: `Error`
    private func oneshot(data: NSData) throws -> NSData {
        let result = NSMutableData(data: try updateWithData(data))
        result.appendData(try finalData())
        return result
    }
}

// FIXME: Move this to RNCryptor.Error if @objc can rename it correctly.
/// Errors thrown by `RNCryptorType`.
@objc public enum RNCryptorError: Int, ErrorType {
    /// Ciphertext was corrupt or password was incorrect.
    /// It is not possible to distinguish between these cases in the v3 data format.
    case HMACMismatch = 1

    /// Unrecognized data format. Usually this means the data is corrupt.
    case UnknownHeader = 2

    /// `final()` was called before sufficient data was passed to `updateWithData()`
    case MessageTooShort

    /// Memory allocation failure. This should never happen.
    case MemoryFailure

    /// A password-based decryptor was used on a key-based ciphertext, or vice-versa.
    case InvalidCredentialType
}

/// RNCryptor encryption/decryption interface.
public class RNCryptor: NSObject {

    /// Encrypt data using password and return encrypted data.
    public static func encryptData(data: NSData, password: String) -> NSData {
        return Encryptor(password: password).encryptData(data)
    }

    /// Decrypt data using password and return decrypted data. Throws if
    /// password is incorrect or ciphertext is in the wrong format.
    /// - throws `Error`
    public static func decryptData(data: NSData, password: String) throws -> NSData {
        return try Decryptor(password: password).decryptData(data)
    }

    /// Generates random NSData of given length
    /// Crashes if `length` is larger than allocatable memory, or if the system random number generator is not available.
    public static func randomDataOfLength(length: Int) -> NSData {
        let data = NSMutableData(length: length)!
        let result = SecRandomCopyBytes(kSecRandomDefault, length, UnsafeMutablePointer<UInt8>(data.mutableBytes))
        guard result == errSecSuccess else {
            fatalError("SECURITY FAILURE: Could not generate secure random numbers: \(result).")
        }

        return data
    }

    /// A encryptor for the latest data format. If compatibility with other RNCryptor
    /// implementations is required, you may wish to use the specific encryptor version rather
    /// than accepting "latest."
    ///
    @objc(RNEncryptor)
    public final class Encryptor: NSObject, RNCryptorType {
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
        public func updateWithData(data: NSData) -> NSData {
            return encryptor.updateWithData(data)
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - returns: Trailing data
        public func finalData() -> NSData {
            return encryptor.finalData()
        }

        /// Simplified, generic interface to `RNCryptorType`. Takes a data,
        /// returns a processed data, and invalidates the cryptor.
        public func encryptData(data: NSData) -> NSData {
            return encryptor.encryptData(data)
        }
    }

    /// Password-based decryptor that can handle any supported format.
    @objc(RNDecryptor)
    public final class Decryptor : NSObject, RNCryptorType {
        private var decryptors: [VersionedDecryptorType.Type] = [DecryptorV3.self]

        private var buffer = NSMutableData()
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
        public func decryptData(data: NSData) throws -> NSData {
            return try oneshot(data)
        }

        /// Updates cryptor with data and returns processed data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - throws: `Error`
        /// - returns: Processed data. May be empty.
        public func updateWithData(data: NSData) throws -> NSData {
            if let d = decryptor {
                return try d.updateWithData(data)
            }

            buffer.appendData(data)

            let toCheck:[VersionedDecryptorType.Type]
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

            guard !decryptors.isEmpty else { throw RNCryptorError.UnknownHeader }
            return NSData()
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - throws: `Error`
        /// - returns: Trailing data
        public func finalData() throws -> NSData {
            guard let d = decryptor else {
                throw RNCryptorError.UnknownHeader
            }
            return try d.finalData()
        }
    }
}

// V3 implementaion
public extension RNCryptor {
    /// V3 format settings
    @objc(RNCryptorFormatV3)
    public final class FormatV3: NSObject {
        /// Size of AES and HMAC keys
        public static let keySize = kCCKeySizeAES256

        /// Size of PBKDF2 salt
        public static let saltSize = 8

        /// Generate a key from a password and salt
        /// - parameters:
        ///     - password: Password to convert
        ///     - salt: Salt. Generally constructed with RNCryptor.randomDataOfLength(FormatV3.saltSize)
        /// - returns: Key of length FormatV3.keySize
        public static func keyForPassword(password: String, salt: NSData) -> NSData {
            let derivedKey = NSMutableData(length: keySize)!
            let derivedKeyPtr = UnsafeMutablePointer<UInt8>(derivedKey.mutableBytes)

            let passwordData = password.dataUsingEncoding(NSUTF8StringEncoding)!
            let passwordPtr = UnsafePointer<Int8>(passwordData.bytes)

            let saltPtr = UnsafePointer<UInt8>(salt.bytes)

            // All the crazy casting because CommonCryptor hates Swift
            let algorithm     = CCPBKDFAlgorithm(kCCPBKDF2)
            let prf           = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
            let pbkdf2Rounds  = UInt32(10000)

            let result = CCKeyDerivationPBKDF(
                algorithm,
                passwordPtr,   passwordData.length,
                saltPtr,       salt.length,
                prf,           pbkdf2Rounds,
                derivedKeyPtr, derivedKey.length)

            guard result == CCCryptorStatus(kCCSuccess) else {
                fatalError("SECURITY FAILURE: Could not derive secure password (\(result)): \(derivedKey).")
            }
            return derivedKey
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
    @objc(RNEncryptorV3)
    public final class EncryptorV3 : NSObject, RNCryptorType {
        private var engine: Engine
        private var hmac: HMACV3
        private var pendingHeader: NSData?

        /// Creates and returns an encryptor.
        ///
        /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
        public convenience init(password: String) {
            self.init(
                password: password,
                encryptionSalt: RNCryptor.randomDataOfLength(V3.saltSize),
                hmacSalt: RNCryptor.randomDataOfLength(V3.saltSize),
                iv: RNCryptor.randomDataOfLength(V3.ivSize))
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
        public convenience init(encryptionKey: NSData, hmacKey: NSData) {
            self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: RNCryptor.randomDataOfLength(V3.ivSize))
        }

        /// Takes a data, returns a processed data, and invalidates the cryptor.
        public func encryptData(data: NSData) -> NSData {
            return try! oneshot(data)
        }

        /// Updates cryptor with data and returns encrypted data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - returns: Processed data. May be empty.
        public func updateWithData(data: NSData) -> NSData {
            // It should not be possible for this to fail during encryption
            return handle(engine.updateWithData(data))
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - returns: Trailing data
        public func finalData() -> NSData {
            let result = NSMutableData(data: handle(engine.finalData()))
            result.appendData(hmac.finalData())
            return result
        }

        // Expose random numbers for testing
        internal convenience init(encryptionKey: NSData, hmacKey: NSData, iv: NSData) {
            let preamble = [V3.formatVersion, UInt8(0)]
            let header = NSMutableData(bytes: preamble, length: preamble.count)
            header.appendData(iv)
            self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }

        // Expose random numbers for testing
        internal convenience init(password: String, encryptionSalt: NSData, hmacSalt: NSData, iv: NSData) {
            let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
            let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

            // TODO: This chained-+ is very slow to compile in Swift 2b5 (http://www.openradar.me/21842206)
            // let header = [V3.version, UInt8(1)] + encryptionSalt + hmacSalt + iv
            let preamble = [V3.formatVersion, UInt8(1)]
            let header = NSMutableData(bytes: preamble, length: preamble.count)
            header.appendData(encryptionSalt)
            header.appendData(hmacSalt)
            header.appendData(iv)

            self.init(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }

        private init(encryptionKey: NSData, hmacKey: NSData, iv: NSData, header: NSData) {
            precondition(encryptionKey.length == V3.keySize)
            precondition(hmacKey.length == V3.keySize)
            precondition(iv.length == V3.ivSize)
            hmac = HMACV3(key: hmacKey)
            engine = Engine(operation: .Encrypt, key: encryptionKey, iv: iv)
            pendingHeader = header
        }

        private func handle(data: NSData) -> NSData {
            var result: NSData
            if let ph = pendingHeader {
                let accum = NSMutableData(data: ph)
                pendingHeader = nil
                accum.appendData(data)
                result = accum
            } else {
                result = data
            }
            hmac.updateWithData(result)
            return result
        }
    }

    /// Format version 3 decryptor. This is required in order to decrypt
    /// using keys (since key configuration is version-specific). For password
    /// decryption, `Decryptor` is generally preferred, and will call this
    /// if appropriate.
    @objc(RNDecryptorV3)
    public final class DecryptorV3: NSObject, VersionedDecryptorType {
        //
        // Static methods
        //
        private static let preambleSize = 1
        private static func canDecrypt(preamble: NSData) -> Bool {
            assert(preamble.length >= 1)
            return preamble.bytesView[0] == 3
        }

        //
        // Private properties
        //
        private var buffer = NSMutableData()
        private var decryptorEngine: DecryptorEngineV3?
        private let credential: Credential


        /// Creates and returns a decryptor.
        ///
        /// - parameter password: Non-empty password string. This will be interpretted as UTF-8.
        public init(password: String) {
            credential = .Password(password)
        }

        /// Creates and returns a decryptor using keys.
        ///
        /// - parameters:
        ///     - encryptionKey: AES-256 key. Must be exactly FormatV3.keySize (kCCKeySizeAES256, 32 bytes)
        ///     - hmacKey: HMAC key. Must be exactly FormatV3.keySize (kCCKeySizeAES256, 32 bytes)
        public init(encryptionKey: NSData, hmacKey: NSData) {
            precondition(encryptionKey.length == V3.keySize)
            precondition(hmacKey.length == V3.hmacSize)
            credential = .Keys(encryptionKey: encryptionKey, hmacKey: hmacKey)
        }

        /// Decrypt data using password and return decrypted data. Throws if
        /// password is incorrect or ciphertext is in the wrong format.
        /// - throws `Error`
        public func decryptData(data: NSData) throws -> NSData {
            return try oneshot(data)
        }

        /// Updates cryptor with data and returns encrypted data.
        ///
        /// - parameter data: Data to process. May be empty.
        /// - returns: Processed data. May be empty.
        public func updateWithData(data: NSData) throws -> NSData {
            if let e = decryptorEngine {
                return e.updateWithData(data)
            }

            buffer.appendData(data)
            guard buffer.length >= requiredHeaderSize else {
                return NSData()
            }

            let e = try createEngineWithCredential(credential, header: buffer.bytesView[0..<requiredHeaderSize])
            decryptorEngine = e
            let body = buffer.bytesView[requiredHeaderSize..<buffer.length]
            buffer.length = 0
            return e.updateWithData(body)
        }

        /// Returns trailing data and invalidates the cryptor.
        ///
        /// - returns: Trailing data
        public func finalData() throws -> NSData {
            guard let result = try decryptorEngine?.finalData() else {
                throw RNCryptorError.MessageTooShort
            }
            return result
        }

        //
        // Private functions
        //

        private var requiredHeaderSize: Int {
            switch credential {
            case .Password(_): return V3.passwordHeaderSize
            case .Keys(_, _): return V3.keyHeaderSize
            }
        }

        private func createEngineWithCredential(credential: Credential, header: NSData) throws -> DecryptorEngineV3 {
            switch credential {
            case let .Password(password):
                return try createEngineWithPassword(password, header: header)
            case let .Keys(encryptionKey, hmacKey):
                return try createEngineWithKeys(encryptionKey: encryptionKey, hmacKey: hmacKey, header: header)
            }
        }

        private func createEngineWithPassword(password: String, header: NSData) throws -> DecryptorEngineV3 {
            assert(password != "")
            precondition(header.length == V3.passwordHeaderSize)

            guard DecryptorV3.canDecrypt(header) else {
                throw RNCryptorError.UnknownHeader
            }

            guard header.bytesView[1] == 1 else {
                throw RNCryptorError.InvalidCredentialType
            }

            let encryptionSalt = header.bytesView[2...9]
            let hmacSalt = header.bytesView[10...17]
            let iv = header.bytesView[18...33]

            let encryptionKey = V3.keyForPassword(password, salt: encryptionSalt)
            let hmacKey = V3.keyForPassword(password, salt: hmacSalt)

            return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }

        private func createEngineWithKeys(encryptionKey encryptionKey: NSData, hmacKey: NSData, header: NSData) throws -> DecryptorEngineV3 {
            precondition(header.length == V3.keyHeaderSize)
            precondition(encryptionKey.length == V3.keySize)
            precondition(hmacKey.length == V3.keySize)

            guard DecryptorV3.canDecrypt(header) else {
                throw RNCryptorError.UnknownHeader
            }

            guard header.bytesView[1] == 0 else {
                throw RNCryptorError.InvalidCredentialType
            }

            let iv = header.bytesView[2..<18]
            return DecryptorEngineV3(encryptionKey: encryptionKey, hmacKey: hmacKey, iv: iv, header: header)
        }
    }
}

internal enum CryptorOperation: CCOperation {
    case Encrypt = 0 // CCOperation(kCCEncrypt)
    case Decrypt = 1 // CCOperation(kCCDecrypt)
}

internal final class Engine {
    private let cryptor: CCCryptorRef
    private var buffer = NSMutableData()

    init(operation: CryptorOperation, key: NSData, iv: NSData) {
        var cryptorOut = CCCryptorRef()
        let result = CCCryptorCreate(
            operation.rawValue,
            CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
            key.bytes, key.length,
            iv.bytes,
            &cryptorOut
        )
        cryptor = cryptorOut

        // It is a programming error to create us with illegal values
        // This is an internal class, so we can constrain what is sent to us.
        // If this is ever made public, it should throw instead of asserting.
        assert(result == CCCryptorStatus(kCCSuccess))
    }

    deinit {
        if cryptor != CCCryptorRef() {
            CCCryptorRelease(cryptor)
        }
    }

    func sizeBufferForDataOfLength(length: Int) -> Int {
        let size = CCCryptorGetOutputLength(cryptor, length, true)
        buffer.length = size
        return size
    }

    func updateWithData(data: NSData) -> NSData {
        let outputLength = sizeBufferForDataOfLength(data.length)
        var dataOutMoved: Int = 0

        let result = CCCryptorUpdate(
            cryptor,
            data.bytes, data.length,
            buffer.mutableBytes, outputLength,
            &dataOutMoved)

        // The only error returned by CCCryptorUpdate is kCCBufferTooSmall, which would be a programming error
        assert(result == CCCryptorStatus(kCCSuccess), "RNCRYPTOR BUG. PLEASE REPORT.")

        buffer.length = dataOutMoved
        return buffer
    }

    func finalData() -> NSData {
        let outputLength = sizeBufferForDataOfLength(0)
        var dataOutMoved: Int = 0

        let result = CCCryptorFinal(
            cryptor,
            buffer.mutableBytes, outputLength,
            &dataOutMoved
        )

        // Note that since iOS 6, CCryptor will never return padding errors or other decode errors.
        // I'm not aware of any non-catestrophic (MemoryAllocation) situation in which this
        // can fail. Using assert() just in case, but we'll ignore errors in Release.
        // https://devforums.apple.com/message/920802#920802
        assert(result == CCCryptorStatus(kCCSuccess), "RNCRYPTOR BUG. PLEASE REPORT.")

        buffer.length = dataOutMoved
        return buffer
    }
}

internal typealias V3 = RNCryptor.FormatV3

private enum Credential {
    case Password(String)
    case Keys(encryptionKey: NSData, hmacKey: NSData)
}

private final class DecryptorEngineV3 {
    private let buffer = OverflowingBuffer(capacity: V3.hmacSize)
    private var hmac: HMACV3
    private var engine: Engine

    init(encryptionKey: NSData, hmacKey: NSData, iv: NSData, header: NSData) {
        precondition(encryptionKey.length == V3.keySize)
        precondition(hmacKey.length == V3.hmacSize)
        precondition(iv.length == V3.ivSize)

        hmac = HMACV3(key: hmacKey)
        hmac.updateWithData(header)
        engine = Engine(operation: .Decrypt, key: encryptionKey, iv: iv)
    }

    func updateWithData(data: NSData) -> NSData {
        let overflow = buffer.updateWithData(data)
        hmac.updateWithData(overflow)
        return engine.updateWithData(overflow)
    }

    func finalData() throws -> NSData {
        let result = engine.finalData()
        let hash = hmac.finalData()
        if !isEqualInConsistentTime(trusted: hash, untrusted: buffer.finalData()) {
            throw RNCryptorError.HMACMismatch
        }
        return result
    }
}

private final class HMACV3 {
    var context: CCHmacContext = CCHmacContext()

    init(key: NSData) {
        CCHmacInit(
            &context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key.bytes,
            key.length
        )
    }

    func updateWithData(data: NSData) {
        CCHmacUpdate(&context, data.bytes, data.length)
    }

    func finalData() -> NSData {
        let hmac = NSMutableData(length: V3.hmacSize)!
        CCHmacFinal(&context, hmac.mutableBytes)
        return hmac
    }
}

// Internal protocol for version-specific decryptors.
private protocol VersionedDecryptorType: RNCryptorType {
    static var preambleSize: Int { get }
    static func canDecrypt(preamble: NSData) -> Bool
    init(password: String)
}

private extension CollectionType {
    // Split collection into ([pass], [fail]) based on predicate.
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

internal class OverflowingBuffer {
    private var buffer = NSMutableData()
    let capacity: Int

    init(capacity: Int) {
        self.capacity = capacity
    }

    @warn_unused_result
    func updateWithData(data: NSData) -> NSData {
        if data.length >= capacity {
            return sendAllArray(data)
        } else if buffer.length + data.length <= capacity {
            buffer.appendData(data)
            return NSData()
        } else {
            return sendSomeArray(data)
        }
    }

    func finalData() -> NSData {
        let result = buffer
        buffer = NSMutableData() // Data belongs to caller now.
        return result
    }

    private func sendAllArray(data: NSData) -> NSData {
        let toSend = data.length - capacity
        assert(toSend >= 0)
        assert(data.length - toSend <= capacity)

        let result = NSMutableData(data: buffer)
        result.appendData(data.bytesView[0..<toSend])
        buffer.length = 0
        buffer.appendData(data.bytesView[toSend..<data.length])
        return result
    }

    private func sendSomeArray(data: NSData) -> NSData {
        let toSend = (buffer.length + data.length) - capacity
        assert(toSend > 0) // If it were <= 0, we would have extended the array
        assert(toSend < buffer.length) // If we would have sent everything, replaceBuffer should have been called

        let result = buffer.bytesView[0..<toSend]
        buffer.replaceBytesInRange(NSRange(0..<toSend), withBytes: nil, length: 0)
        buffer.appendData(data)
        return result
    }
}

private extension NSData {
    var bytesView: BytesView { return BytesView(self) }
}

private struct BytesView: CollectionType {
    let data: NSData
    init(_ data: NSData) { self.data = data }
    
    subscript (position: Int) -> UInt8 {
        return UnsafePointer<UInt8>(data.bytes)[position]
    }
    subscript (bounds: Range<Int>) -> NSData {
        return data.subdataWithRange(NSRange(bounds))
    }
    var startIndex: Int = 0
    var endIndex: Int { return data.length }
}

/** Compare two NSData in time proportional to the untrusted data

Equatable-based comparisons genreally stop comparing at the first difference.
This can be used by attackers, in some situations,
to determine a secret value by considering the time required to compare the values.

We enumerate over the untrusted values so that the time is proportaional to the attacker's data,
which provides the attack no informatoin about the length of the secret.
*/
private func isEqualInConsistentTime(trusted trusted: NSData, untrusted: NSData) -> Bool {
    // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
    // If any bytes are different, then the OR will accumulate some non-0 value.
    
    var result: UInt8 = untrusted.length == trusted.length ? 0 : 1  // Start with 0 (equal) only if our lengths are equal
    for (i, untrustedByte) in untrusted.bytesView.enumerate() {
        // Use mod to wrap around ourselves if they are longer than we are.
        // Remember, we already broke equality if our lengths are different.
        result |= trusted.bytesView[i % trusted.length] ^ untrustedByte
    }
    
    return result == 0
}
