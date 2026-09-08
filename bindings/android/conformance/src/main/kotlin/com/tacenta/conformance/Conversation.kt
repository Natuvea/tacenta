// The conversation every check of the Kotlin head runs: two users sign up and
// in, find each other, message both ways, and one resumes from exported state
// and receives again. The same steps, line for line, as the TypeScript head's
// sdk/typescript/conformance/conversation.mjs and the Swift head's
// bindings/swift/conformance/Conversation.swift; tooling/check-conformance-lines.sh
// keeps the three saying the same thing. Kept apart from the JVM entry point
// so a device run can compile the same file.
package com.tacenta.conformance

import uniffi.tacenta_ffi.Address
import uniffi.tacenta_ffi.ClientException
import uniffi.tacenta_ffi.Message
import uniffi.tacenta_ffi.RestoreOutcome
import uniffi.tacenta_ffi.Tenant
import uniffi.tacenta_ffi.asFlow
import java.util.UUID
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first

class Mismatch(message: String) : Exception(message)

private fun suffix() = UUID.randomUUID().toString().replace("-", "").take(8)

fun show(address: Address) = "${address.user}/${address.device}"

private fun expect(ok: Boolean, message: () -> String) {
    if (!ok) throw Mismatch(message())
}

/** The kind a call fails with, as the other heads spell it, or "accepted"
 *  if it did not fail. */
private suspend fun kindOf(call: suspend () -> Unit): String {
    return try {
        call()
        "accepted"
    } catch (e: ClientException) {
        // The subclass name, lowerCamel: SignInRefused -> signInRefused.
        val name = e::class.simpleName ?: "unknown"
        name.replaceFirstChar { it.lowercase() }
    } catch (e: Throwable) {
        "an untyped error: $e"
    }
}

private fun expectTexts(messages: List<Message>, expected: List<String>, what: String) {
    val got = messages.map { String(it.plaintext) }
    expect(got == expected) { "$what $got, expected $expected" }
}

/** Run the conversation on [tenant], reporting each step through [log].
 *  Throws on the first mismatch. */
suspend fun conversation(tenant: Tenant, log: (String) -> Unit) {
    val a = "conform-a-${suffix()}"
    val b = "conform-b-${suffix()}"
    val password = "p-${suffix()}-${suffix()}"
    tenant.signUp(a, password)
    tenant.signUp(b, password)
    log("signed up $a and $b")

    val alice = tenant.signIn(a, password)
    val bob = tenant.signIn(b, password)
    log("signed in as ${show(alice.address())} and ${show(bob.address())}")

    val refused = kindOf { tenant.signIn(a, "$password-wrong") }
    expect(refused == "signInRefused") { "a wrong password was refused as $refused" }
    log("a wrong password was refused as $refused")
    val taken = kindOf { tenant.signUp(a, password) }
    expect(taken == "usernameTaken") { "a second sign-up was refused as $taken" }
    log("a second sign-up was refused as $taken")

    val toBob = alice.find(b)?.address ?: throw Mismatch("find($b) gave null, expected ${show(bob.address())}")
    expect(toBob == bob.address()) { "find($b) gave ${show(toBob)}, expected ${show(bob.address())}" }
    expect(alice.find("nobody-${suffix()}") == null) { "find of a stranger was not null" }
    log("found $b at ${show(toBob)}")

    val nobody = kindOf {
        alice.send(Address("${toBob.user.substringBefore("/")}/nobody-${suffix()}", 1u), "to no one".toByteArray())
    }
    expect(nobody == "notFound") { "a send to an unregistered address was refused as $nobody" }
    log("a send to an unregistered address was refused as $nobody")

    alice.send(toBob, "conformance: first contact".toByteArray())
    val inbox = bob.receive()
    expectTexts(inbox, listOf("conformance: first contact"), "$b received")
    expect(inbox[0].from == alice.address()) { "from was ${show(inbox[0].from)}" }
    log("$b received the first message from ${show(inbox[0].from)}")

    bob.send(alice.address(), "conformance: reply".toByteArray())
    expectTexts(alice.receive(), listOf("conformance: reply"), "$a received")
    log("$a received the reply")

    // A receive left pending does not hold the client: a send goes through
    // meanwhile, and the pending receive gets the reply it provokes.
    coroutineScope {
        val pending = async { alice.receive() }
        alice.send(toBob, "conformance: while receiving".toByteArray())
        expectTexts(bob.receive(), listOf("conformance: while receiving"), "$b received while $a was receiving")
        bob.send(alice.address(), "conformance: to the pending receive".toByteArray())
        expectTexts(pending.await(), listOf("conformance: to the pending receive"), "the pending receive of $a")
    }
    log("$a sent while its own receive was pending, and that receive got the reply")

    // The stream form: the same receive underneath, one message at a time.
    bob.send(alice.address(), "conformance: through the stream".toByteArray())
    val streamed = alice.inbound().asFlow().first()
    expectTexts(listOf(streamed), listOf("conformance: through the stream"), "the inbound stream of $a")
    log("$a took the next message from its inbound stream")

    val state = alice.exportState()
    val again = tenant.signInWithState(a, password, state)
    val outcome = again.restoreOutcome()
    expect(outcome == RestoreOutcome.RESUMED) { "the restore outcome of $a was $outcome" }
    bob.send(again.address(), "conformance: after resume".toByteArray())
    expectTexts(again.receive(), listOf("conformance: after resume"), "resumed $a received")
    log("$a resumed from ${state.size} bytes of state and received again")
}
