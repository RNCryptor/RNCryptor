//
//  Sliceable.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

extension CollectionType {
    func splitAt(index: Index) -> (SubSequence, SubSequence) {
        return (self[startIndex..<index], self[index..<endIndex])
    }
}
