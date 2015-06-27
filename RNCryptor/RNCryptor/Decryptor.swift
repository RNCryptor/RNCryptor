//
//  Decryptor.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

//public final class Decryptor: DataSinkType {
//    private let sink: DataSinkType
//
//    private var cryptor: Cryptor?
//    private var hmacSink: HMACSink?
//
//    private var buffer: [UInt8]
//
//    internal init(sink: DataSinkType) throws {
//        self.sink = sink
//    }
//
//    public func put(data: UnsafeBufferPointer<UInt8>) throws {
//        try self.cryptor?.put(data)
//    }
//
//    public func finish() throws {
//        try self.cryptor.finish()
//        try self.sink.put(self.hmacSink.final())
//    }
//}
