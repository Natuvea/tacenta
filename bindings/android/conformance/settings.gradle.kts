// The Kotlin head's conformance run: its own Gradle build rather than a
// subproject of ../settings.gradle.kts, because Gradle configures every
// included project and the Android plugin needs an SDK to configure, which a
// JVM run does not use. Run with the wrapper one directory up.
rootProject.name = "tacenta-conformance"
