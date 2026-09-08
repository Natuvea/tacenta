plugins {
    id("com.android.library") version "8.7.0"
    id("org.jetbrains.kotlin.android") version "2.0.20"
}

// The release this .aar belongs to; tooling/check-versions.sh keeps it in
// step with the workspace and the tag.
version = "1.11.5"

android {
    namespace = "com.tacenta.sdk"
    compileSdk = 35

    defaultConfig {
        // 24 matches the API level build-aar.sh links the native libraries
        // against; raising one means raising the other.
        minSdk = 24
    }

    // build-aar.sh writes the generated Kotlin (which now carries the one
    // hand-written source, the inbound Flow, copied in by generate-kotlin.sh)
    // and the per-ABI .so files here before this module is assembled.
    sourceSets["main"].java.srcDirs("src/main/java")
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // UniFFI's generated Kotlin binds the native library through JNA.
    // JNA is dual-licensed Apache-2.0 or LGPL-2.1; Tacenta uses it under
    // Apache-2.0 (recorded in THIRD_PARTY_NOTICES).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}
