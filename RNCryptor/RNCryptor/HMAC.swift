//
//  hmac.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

internal final class HMACSink: DataSinkType {
    var sink: DataSinkType
    var context: CCHmacContext = CCHmacContext()

    init(key: [UInt8], sink: DataSinkType) throws {
        self.sink = sink

        guard key.count == KeySize else {
            throw Error.ParameterError
        }
        CCHmacInit(
            &self.context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key,
            key.count
        )
    }

    func put(data: UnsafeBufferPointer<UInt8>) throws {
        CCHmacUpdate(&self.context, data.baseAddress, data.count)
        try self.sink.put(data)
    }

    func final() -> [UInt8] {
        var hmac = Array<UInt8>(count: HMACSize, repeatedValue: 0)
        CCHmacFinal(&self.context, &hmac)
        return hmac
    }
}
