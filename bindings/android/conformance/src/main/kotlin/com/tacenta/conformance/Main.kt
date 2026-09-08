// The Kotlin head's conformance run (decision 0090, choice 6): the conversation
// in Conversation.kt, through the generated Kotlin bindings, against whichever
// server the document URL names (hosted Tacenta by default), once over the
// services' own ports and once over the WebSocket carriage, printing a
// transcript a reader can check line by line. Exit status is the verdict.
// Not a test: it needs a real tenant.
//
//   TACENTA_API_KEY=tct_... ./gradlew -p conformance -q run
//   TACENTA_DOCUMENT_URL=http://127.0.0.1:4780/.well-known/tacenta ...
package com.tacenta.conformance

import uniffi.tacenta_ffi.Tenant
import kotlin.system.exitProcess
import kotlinx.coroutines.runBlocking

private val started = System.currentTimeMillis()

private fun log(line: String) {
    println("${(System.currentTimeMillis() - started).toString().padStart(6)}ms  $line")
}

fun main() {
    val apiKey = System.getenv("TACENTA_API_KEY")
    if (apiKey.isNullOrEmpty()) {
        System.err.println("TACENTA_API_KEY is not set")
        exitProcess(2)
    }
    val documentUrl = System.getenv("TACENTA_DOCUMENT_URL") ?: "https://tacenta.com/.well-known/tacenta"
    // The verdict is the exit status; the process ends after the coroutine
    // has returned, so the SDK's handles are released rather than killed.
    val verdict = runBlocking {
        try {
            log("document $documentUrl")
            val tenant = Tenant.connectVia(apiKey, documentUrl)
            log("over TCP, the services' own ports")
            conversation(tenant, ::log)
            val carried = tenant.websocket()
            log("over the WebSocket carriage")
            conversation(carried, ::log)
            log("PASS")
            0
        } catch (e: Throwable) {
            // Throwable, not Exception: a library that fails to load is an Error,
            // and the transcript must show that as a FAIL line too.
            log("FAIL ${e.message ?: e.toString()}")
            1
        }
    }
    exitProcess(verdict)
}
