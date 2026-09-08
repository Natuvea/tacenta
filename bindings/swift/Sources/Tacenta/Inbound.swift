// The Swift form of the inbound stream (decision 0090, item 8 of the list
// before the packages): the generated `Inbound` as an `AsyncSequence`, so an
// app writes `for try await message in client.inbound()`. Hand-written,
// since UniFFI cannot emit the conformance; it is the one source in this
// package that is not generated. build-xcframework.sh ships it beside the
// generated Tacenta.swift and CI type-checks the two together.

extension Inbound: AsyncSequence {
    public typealias Element = Message

    public struct AsyncIterator: AsyncIteratorProtocol {
        let inbound: Inbound

        /// The next message, awaiting mail if none is buffered. Never nil:
        /// the sequence ends only by throwing.
        public mutating func next() async throws -> Message? {
            try await inbound.next()
        }
    }

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(inbound: self)
    }
}
