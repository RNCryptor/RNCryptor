//
//  TeeWriter.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

public final class TeeWriter: Writable {
    let writers: [Writable]

    init(_ sinks: Writable...) {
        self.writers = sinks
    }
    public func write(data: UnsafeBufferPointer<UInt8>) throws {
        for writer in self.writers {
            try writer.write(data)
        }
    }
}
