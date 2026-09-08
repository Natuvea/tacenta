// The Swift head's conformance run (decision 0090, choice 6): the conversation
// in Conversation.swift, through the packaged Swift SDK, against whichever
// server the document URL names (hosted Tacenta by default), once over the
// services' own ports and once over the WebSocket carriage, printing a
// transcript a reader can check line by line. Exit status is the verdict.
// Not a test: it needs a real tenant.
//
//   TACENTA_API_KEY=tct_... swift run conformance
//   TACENTA_DOCUMENT_URL=http://127.0.0.1:4780/.well-known/tacenta ...
import Foundation
import Tacenta

let environment = ProcessInfo.processInfo.environment
guard let apiKey = environment["TACENTA_API_KEY"], !apiKey.isEmpty else {
    FileHandle.standardError.write(Data("TACENTA_API_KEY is not set\n".utf8))
    exit(2)
}
let documentUrl = environment["TACENTA_DOCUMENT_URL"] ?? "https://tacenta.com/.well-known/tacenta"

// Line-buffered even into a pipe, so the transcript keeps up with the run.
setvbuf(stdout, nil, _IOLBF, 0)
let started = Date()
func log(_ line: String) {
    print(String(format: "%6dms  %@", Int(Date().timeIntervalSince(started) * 1000), line))
}

do {
    log("document \(documentUrl)")
    let tenant = try await Tenant.connectVia(apiKey: apiKey, url: documentUrl)
    log("over TCP, the services' own ports")
    try await conversation(tenant, log)
    let carried = try tenant.websocket()
    log("over the WebSocket carriage")
    try await conversation(carried, log)
    log("PASS")
    exit(0)
} catch {
    log("FAIL \(error)")
    exit(1)
}
