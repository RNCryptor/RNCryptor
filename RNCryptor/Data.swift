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

//internal extension NSMutableData {
//    var mutableBytesView: MutableBytesView { return MutableBytesView(self) }
//}

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

//internal struct MutableBytesView: RangeReplaceableCollectionType {
//    let data: NSMutableData
//    init(_ data: NSMutableData) { self.data = data }
//    init() { self.data = NSMutableData() }
//
//    subscript (position: Int) -> UInt8 {
//        return UnsafePointer<UInt8>(data.bytes)[position]
//    }
//    subscript (bounds: Range<Int>) -> NSData {
//        return data.subdataWithRange(NSRange(bounds))
//    }
//    var startIndex: Int = 0
//    var endIndex: Int { return data.length }
//
//    func replaceRange<C : CollectionType where C.Generator.Element == UInt8>(subRange: Range<Int>, with newElements: C) {
//        let replace = [UInt8](newElements)
//        data.replaceBytesInRange(NSRange(subRange), withBytes: replace, length: replace.count)
//    }
//}