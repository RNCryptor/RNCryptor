//
//  hmac.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import CommonCrypto

internal final class HMACWriter {
    var context: CCHmacContext = CCHmacContext()

    init(key: [UInt8]) {
        CCHmacInit(
            &self.context,
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            key,
            key.count
        )
    }

    func update(data: [UInt8]) {
        data.withUnsafeBufferPointer { buf in
            CCHmacUpdate(&self.context, buf.baseAddress, buf.count)
        }
    }

    func final() -> [UInt8] {
        var hmac = Array<UInt8>(count: RNCryptorV3.hmacSize, repeatedValue: 0)
        CCHmacFinal(&self.context, &hmac)
        return hmac
    }
}
