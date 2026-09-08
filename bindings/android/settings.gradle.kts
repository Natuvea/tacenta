// The Tacenta Android SDK: one library module that packages the Rust FFI
// shared libraries and the generated Kotlin bindings into an .aar.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "tacenta-android"
include(":lib")
