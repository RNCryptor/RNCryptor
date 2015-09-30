//
//  Data.swift
//
//  Copyright © 2015 Rob Napier. All rights reserved.
//
//  This code is licensed under the MIT License:
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
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

/** Compare two NSData in time proportional to the untrusted data

Equatable-based comparisons genreally stop comparing at the first difference.
This can be used by attackers, in some situations,
to determine a secret value by considering the time required to compare the values.

We enumerate over the untrusted values so that the time is proportaional to the attacker's data,
which provides the attack no informatoin about the length of the secret.
*/
internal func isEqualInConsistentTime(trusted trusted: NSData, untrusted: NSData) -> Bool {
    // The point of this routine is XOR the bytes of each data and accumulate the results with OR.
    // If any bytes are different, then the OR will accumulate some non-0 value.

    var result: UInt8 = untrusted.length == trusted.length ? 0 : 1  // Start with 0 (equal) only if our lengths are equal
    for (i, untrustedByte) in untrusted.bytesView.enumerate() {
        // Use mod to wrap around ourselves if they are longer than we are.
        // Remember, we already broke equality if our lengths are different.
        result |= trusted.bytesView[i % trusted.length] ^ untrustedByte
    }

    return result == 0
}
