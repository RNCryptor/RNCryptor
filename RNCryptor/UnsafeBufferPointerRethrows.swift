//
//  UnsafeBufferPointerRethrows.swift
//  RNCryptor
//
//  Created by Rob Napier on 6/26/15.
//  Copyright © 2015 Rob Napier. All rights reserved.
//

//
// This is just needed until withUnsafe* has rethrows
//

private enum Result<T> {
    case Success(T)
    case Failure(ErrorType)

    func value() throws -> T {
        switch self {
        case .Success(let value): return value
        case .Failure(let err): throw err
        }
    }

    init(@noescape f: () throws -> T) {
        do    { self = .Success(try f()) }
        catch { self = .Failure(error) }
    }
}

internal extension Array {
    func withUnsafeBufferPointer<R>(@noescape body: (UnsafeBufferPointer<T>) throws -> R) throws -> R {
        return try self.withUnsafeBufferPointer { buf in
            return Result{ try body(buf) }}.value()
    }

    mutating func withUnsafeMutableBufferPointer<R>(@noescape body: (inout UnsafeMutableBufferPointer<T>) throws -> R) throws-> R {
        return try self.withUnsafeMutableBufferPointer { (inout buf: UnsafeMutableBufferPointer<T>) in
            return Result{try body(&buf)}}.value()
    }
}

internal extension ArraySlice {
    func withUnsafeBufferPointer<R>(@noescape body: (UnsafeBufferPointer<T>) throws -> R) throws -> R {
        return try self.withUnsafeBufferPointer { buf in
            return Result{ try body(buf) }}.value()
    }

    mutating func withUnsafeMutableBufferPointer<R>(@noescape body: (inout UnsafeMutableBufferPointer<T>) throws -> R) throws-> R {
        return try self.withUnsafeMutableBufferPointer { (inout buf: UnsafeMutableBufferPointer<T>) in
            return Result{try body(&buf)}}.value()
    }
}
