//
//  hmac.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

internal final class HMACSink: DataSinkType {
    var context: CCHmacContext = CCHmacContext()

    init(key: [UInt8]) {
        CCHmacInit(
            &self.context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key,
            key.count
        )
    }

    func put(data: UnsafeBufferPointer<UInt8>) throws {
        CCHmacUpdate(&self.context, data.baseAddress, data.count)
    }

    func final() -> [UInt8] {
        var hmac = Array<UInt8>(count: RNCryptorV3.hmacSize, repeatedValue: 0)
        CCHmacFinal(&self.context, &hmac)
        return hmac
    }
}
