// The Kotlin head's reference (decision 0090, step 5): Dokka over the Kotlin
// UniFFI generates plus the hand-written file beside it, as a plain JVM
// module so the release workflow needs no Android SDK to document the API
// an app calls. The same sources the conformance program compiles.
//
// From the repository root:
//   bindings/android/generate-kotlin.sh debug target/kotlin
// then, from bindings/android:
//   ./gradlew -p reference -q dokkaHtml
// TACENTA_KOTLIN_BINDINGS names the generated source; the output lands in
// reference/build/dokka/html.
plugins {
    kotlin("jvm") version "2.0.20"
    id("org.jetbrains.dokka") version "1.9.20"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}

val repo = rootDir.resolve("../../..").normalize()
val bindings = System.getenv("TACENTA_KOTLIN_BINDINGS")?.let(::file) ?: repo.resolve("target/kotlin")

// The generated tree already carries the one hand-written source (the
// inbound Flow), copied in by generate-kotlin.sh.
sourceSets["main"].kotlin.srcDir(bindings)

tasks.dokkaHtml {
    moduleName.set("Tacenta")
    dokkaSourceSets.configureEach {
        // The generated file's internals (the FFI glue) are not the API.
        suppressInheritedMembers.set(true)
        perPackageOption {
            matchingRegex.set("uniffi\\.tacenta_ffi")
            skipDeprecated.set(true)
        }
    }
}
