//
//  TeeSink.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/27/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

import Foundation

public final class TeeSink: DataSinkType {
    let sinks: [DataSinkType]

    init(_ sinks: DataSinkType...) {
        self.sinks = sinks
    }
    public func put(data: UnsafeBufferPointer<UInt8>) throws {
        for sink in self.sinks {
            try sink.put(data)
        }
    }
}
