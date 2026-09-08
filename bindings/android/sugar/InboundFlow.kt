// The Kotlin form of the inbound stream (decision 0090, item 8 of the list
// before the packages): the generated `Inbound` as a `Flow`, so an app
// writes `client.inbound().asFlow().collect { message -> ... }`. Hand-written,
// since UniFFI cannot emit a Flow; it is the one source in this library that
// is not generated, and the conformance run compiles it too.
package uniffi.tacenta_ffi

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * This inbound's messages as a Flow: one at a time, as they arrive, from
 * the generated `next`. It ends only by throwing; cancelling the collector
 * ends it too.
 */
fun Inbound.asFlow(): Flow<Message> = flow<Message> {
    // Explicit type argument: inference does not reach past the
    // never-ending loop on every Kotlin target.
    while (true) emit(next())
}
