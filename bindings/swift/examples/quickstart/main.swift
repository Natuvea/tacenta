// A minimal command-line app that consumes the Tacenta Swift SDK exactly
// as a real app would: sign up two throwaway users in a tenant, open a
// session, send an end-to-end encrypted message, and read it back.
//
// Run against hosted Tacenta with a tenant API key:
//     swift run quickstart tct_your_key_here
// or against a local gateway with `Tenant.connectVia(apiKey:url:)`.
//
// This is the Swift analogue of `tacenta try` — proof the packaged SDK is
// usable from a plain Swift Package, not just that the bindings compile.
import Foundation
import Tacenta

let apiKey = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
guard !apiKey.isEmpty else {
    print("usage: quickstart <tenant-api-key>")
    exit(1)
}

func suffix() -> String { String(UInt32.random(in: 0 ..< 0xFFFF_FFFF), radix: 16) }

do {
    // One handle per tenant: it discovers the services from the server's
    // document, so no host or port appears here (decision record 0090).
    let tenant = try await Tenant.connect(apiKey: apiKey)

    let alice = "alice-\(suffix())"
    let bob = "bob-\(suffix())"
    let password = "correct-horse-battery-staple"

    try await tenant.signUp(username: alice, password: password)
    try await tenant.signUp(username: bob, password: password)

    let clientA = try await tenant.signIn(username: alice, password: password)
    let clientB = try await tenant.signIn(username: bob, password: password)

    guard let bobContact = try await clientA.find(username: bob) else {
        print("could not find \(bob)"); exit(1)
    }
    try await clientA.send(to: bobContact.address, message: Data("hello from swift".utf8))
    print("→ \(alice) sent an encrypted message to \(bob)")

    for message in try await clientB.receive() {
        let text = String(decoding: message.plaintext, as: UTF8.self)
        print("← \(bob) received \"\(text)\", decrypted on device")
    }
    print("end to end: the server only ever saw ciphertext.")
} catch {
    print("error: \(error)")
    exit(1)
}
