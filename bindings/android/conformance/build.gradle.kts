// The Kotlin head's conformance run (decision 0090, choice 6) as a plain JVM
// program: the same Kotlin UniFFI generates for the .aar, bound through JNA to
// the FFI library built for the host, so the head runs on the release runner
// without an emulator. What differs from the .aar is only the library the
// bindings load; the Kotlin an app calls is identical.
//
// Inputs, from the repository root, through the same recipe build-aar.sh uses:
//   bindings/android/generate-kotlin.sh debug target/kotlin
// then, from bindings/android:
//   TACENTA_API_KEY=tct_... ./gradlew -p conformance -q run
// TACENTA_KOTLIN_BINDINGS names the generated source (the release pipeline
// compiles this program against the .aar's copy) and TACENTA_FFI_LIB_DIR
// the directory holding the host library (target/debug by default).
plugins {
    kotlin("jvm") version "2.0.20"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // UniFFI's generated Kotlin binds the native library through JNA.
    implementation("net.java.dev.jna:jna:5.14.0")
    // The generated Kotlin's suspend functions ride on coroutines.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}

val repo = rootDir.resolve("../../..").normalize()
val bindings = System.getenv("TACENTA_KOTLIN_BINDINGS")?.let(::file) ?: repo.resolve("target/kotlin")
val libDir = System.getenv("TACENTA_FFI_LIB_DIR")?.let(::file) ?: repo.resolve("target/debug")

sourceSets["main"].kotlin.srcDir(bindings)

application {
    mainClass = "com.tacenta.conformance.MainKt"
}

tasks.named<JavaExec>("run") {
    systemProperty("jna.library.path", libDir.absolutePath)
}
