//
//  Data.swift
//  RNCryptor
//
//  Created by Rob Napier on 9/28/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

internal extension NSData {
    var bytesView: BytesView { return BytesView(self) }
}

internal struct BytesView: CollectionType {
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
