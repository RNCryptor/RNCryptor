//
//  Sliceable.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

extension Sliceable {
    func splitAt(index: Index) -> (SubSlice, SubSlice) {
        return (self[startIndex..<index], self[index..<endIndex])
    }
}

extension UnsafeBufferPointer: Sliceable {
    public subscript (bounds: Range<Index>) -> UnsafeBufferPointer<T> {
        return(UnsafeBufferPointer(start: self.baseAddress + bounds.startIndex, count: bounds.count))
    }
}
