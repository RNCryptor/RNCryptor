//
//  String.swift
//  RNCryptor
//
//  Created by Rob Napier on 7/1/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

extension String {
    init?(UTF8String: UnsafePointer<UInt8>) {
        self.init(UTF8String: UnsafePointer<Int8>(UTF8String))
    }
}