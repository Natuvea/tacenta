// The conversation every check of the Swift head runs: two users sign up and
// in, find each other, message both ways, and one resumes from exported state
// and receives again. The same steps, line for line, as the TypeScript head's
// sdk/typescript/conformance/conversation.mjs and the Kotlin head's
// bindings/android/conformance Conversation.kt; tooling/check-conformance-lines.sh
// keeps the three saying the same thing.
import Foundation
import Tacenta

struct Mismatch: Error, CustomStringConvertible { let description: String }

private func suffix() -> String { String(UInt32.random(in: 0 ..< 0xFFFF_FFFF), radix: 16) }

func show(_ address: Address) -> String { "\(address.user)/\(address.device)" }

private func expect(_ ok: Bool, _ message: @autoclosure () -> String) throws {
    if !ok { throw Mismatch(description: message()) }
}

/// The kind a call fails with, as the other heads spell it, or "accepted"
/// if it did not fail.
private func kindOf(_ call: () async throws -> Void) async -> String {
    do {
        try await call()
        return "accepted"
    } catch let error as ClientError {
        // The case name, lowerCamel: `SignInRefused(reason: ...)` -> signInRefused.
        let name = String(describing: error).split(separator: "(")[0]
        return name.prefix(1).lowercased() + name.dropFirst()
    } catch {
        return "an untyped error: \(error)"
    }
}

private func expectTexts(_ messages: [Message], _ expected: [String], _ what: String) throws {
    let got = messages.map { String(decoding: $0.plaintext, as: UTF8.self) }
    try expect(got == expected, "\(what) \(got), expected \(expected)")
}

/// Run the conversation on `tenant`, reporting each step through `log`.
/// Throws on the first mismatch.
func conversation(_ tenant: Tenant, _ log: (String) -> Void) async throws {
    let a = "conform-a-\(suffix())"
    let b = "conform-b-\(suffix())"
    let password = "p-\(suffix())-\(suffix())"
    try await tenant.signUp(username: a, password: password)
    try await tenant.signUp(username: b, password: password)
    log("signed up \(a) and \(b)")

    let alice = try await tenant.signIn(username: a, password: password)
    let bob = try await tenant.signIn(username: b, password: password)
    log("signed in as \(show(alice.address())) and \(show(bob.address()))")

    let refused = await kindOf { _ = try await tenant.signIn(username: a, password: "\(password)-wrong") }
    try expect(refused == "signInRefused", "a wrong password was refused as \(refused)")
    log("a wrong password was refused as \(refused)")
    let taken = await kindOf { try await tenant.signUp(username: a, password: password) }
    try expect(taken == "usernameTaken", "a second sign-up was refused as \(taken)")
    log("a second sign-up was refused as \(taken)")

    guard let toBob = try await alice.find(username: b)?.address else {
        throw Mismatch(description: "find(\(b)) gave nil, expected \(show(bob.address()))")
    }
    try expect(toBob == bob.address(), "find(\(b)) gave \(show(toBob)), expected \(show(bob.address()))")
    try expect(try await alice.find(username: "nobody-\(suffix())") == nil, "find of a stranger was not nil")
    log("found \(b) at \(show(toBob))")

    let nobody = await kindOf {
        try await alice.send(to: Address(user: "\(toBob.user.split(separator: "/")[0])/nobody-\(suffix())", device: 1),
                       message: Data("to no one".utf8))
    }
    try expect(nobody == "notFound", "a send to an unregistered address was refused as \(nobody)")
    log("a send to an unregistered address was refused as \(nobody)")

    try await alice.send(to: toBob, message: Data("conformance: first contact".utf8))
    let inbox = try await bob.receive()
    try expectTexts(inbox, ["conformance: first contact"], "\(b) received")
    try expect(inbox[0].from == alice.address(), "from was \(show(inbox[0].from))")
    log("\(b) received the first message from \(show(inbox[0].from))")

    try await bob.send(to: alice.address(), message: Data("conformance: reply".utf8))
    try expectTexts(try await alice.receive(), ["conformance: reply"], "\(a) received")
    log("\(a) received the reply")

    // A receive left pending does not hold the client: a send goes through
    // meanwhile, and the pending receive gets the reply it provokes.
    async let pending = alice.receive()
    try await alice.send(to: toBob, message: Data("conformance: while receiving".utf8))
    try expectTexts(try await bob.receive(), ["conformance: while receiving"], "\(b) received while \(a) was receiving")
    try await bob.send(to: alice.address(), message: Data("conformance: to the pending receive".utf8))
    try expectTexts(try await pending, ["conformance: to the pending receive"], "the pending receive of \(a)")
    log("\(a) sent while its own receive was pending, and that receive got the reply")

    // The stream form: the same receive underneath, one message at a time.
    try await bob.send(to: alice.address(), message: Data("conformance: through the stream".utf8))
    var streamed: [Message] = []
    for try await message in alice.inbound() {
        streamed.append(message)
        break
    }
    try expectTexts(streamed, ["conformance: through the stream"], "the inbound stream of \(a)")
    log("\(a) took the next message from its inbound stream")

    let state = try await alice.exportState()
    let again = try await tenant.signInWithState(username: a, password: password, state: state)
    let outcome = try await again.restoreOutcome()
    try expect(outcome == .resumed, "the restore outcome of \(a) was \(outcome)")
    try await bob.send(to: again.address(), message: Data("conformance: after resume".utf8))
    try expectTexts(try await again.receive(), ["conformance: after resume"], "resumed \(a) received")
    log("\(a) resumed from \(state.count) bytes of state and received again")
}
