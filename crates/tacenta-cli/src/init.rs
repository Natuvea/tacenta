//! `tacenta init <language> [directory]`: scaffold the language's quickstart
//! with the developer's API key already in place (decision 0090). The sample is the
//! one the site's language page shows and the repository tests, so what a
//! developer runs first is what the documentation promised.
//!
//! There is no registry package to install yet (decision 0090), so every scaffold depends on the SDK built from a
//! checkout, the way the site describes, and says so in its README.

use std::path::{Path, PathBuf};

/// The heads a scaffold exists for, spelt as the site's `/sdk/<language>`.
pub const LANGUAGES: [&str; 4] = ["typescript", "swift", "kotlin", "rust"];

/// One file of a scaffold: its path under the directory and its contents.
pub struct File {
    pub path: &'static str,
    pub contents: String,
}

/// The scaffold for `language` with `api_key` in place, or `None` for a
/// language this command does not know. `checkout` is where the README
/// tells the developer to build the SDK from.
pub fn scaffold(language: &str, api_key: &str) -> Option<Vec<File>> {
    let files = match language {
        "typescript" => typescript(api_key),
        "swift" => swift(api_key),
        "kotlin" => kotlin(api_key),
        "rust" => rust(api_key),
        _ => return None,
    };
    Some(files)
}

/// Write `files` under `dir`, which must not already hold any of them.
pub fn write(dir: &Path, files: &[File]) -> Result<Vec<PathBuf>, String> {
    let mut written = Vec::with_capacity(files.len());
    for file in files {
        let path = dir.join(file.path);
        if path.exists() {
            return Err(format!(
                "{} already exists; choose another directory or move it aside",
                path.display()
            ));
        }
    }
    for file in files {
        let path = dir.join(file.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, &file.contents)
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

fn file(path: &'static str, contents: String) -> File {
    File { path, contents }
}

fn readme(language: &str, build: &str, run: &str) -> File {
    file(
        "README.md",
        format!(
            "# A Tacenta {language} app\n\n\
             Scaffolded by `tacenta init {language}`, with your tenant's API key already in\n\
             the sample. The key is a secret: keep this directory out of version control,\n\
             or move the key into your app's configuration before committing.\n\n\
             The SDK is not on a package registry yet, so it is built from a checkout of\n\
             the `tacenta` repository, as https://tacenta.com/sdk/{language} describes:\n\n\
             ```bash\n{build}\n```\n\n\
             Then, from this directory:\n\n\
             ```bash\n{run}\n```\n\n\
             The sample signs two users up in your tenant, sends one message between them,\n\
             and prints it decrypted on the receiving side. The generated reference for\n\
             this head is at https://tacenta.com/dl/reference/{language}/ and the whole\n\
             surface, head by head, at https://tacenta.com/dl/sdk/SURFACE.md.\n",
        ),
    )
}

fn typescript(api_key: &str) -> Vec<File> {
    vec![
        file(
            "index.mjs",
            format!(
                r#"// The Tacenta TypeScript head, from Node. `npm install` the package built
// from the repository first (see README.md), then `node index.mjs`.
import {{ Tacenta }} from "@tacenta/sdk";

const tenant = await Tacenta.connect("{api_key}");
await tenant.signUp("alice", "correct horse");
await tenant.signUp("bob", "correct horse");

const alice = await tenant.signIn("alice", "correct horse");
const bob = await tenant.signIn("bob", "correct horse");

const toBob = await alice.find("bob");
if (toBob) await alice.send(toBob, "hello from node");

for await (const m of bob.inbound()) {{
  console.log(m.from, m.text());
  break;
}}
"#
            ),
        ),
        file(
            "package.json",
            r#"{
  "name": "tacenta-app",
  "private": true,
  "type": "module",
  "scripts": {
    "start": "node index.mjs"
  },
  "dependencies": {
    "@tacenta/sdk": "file:../tacenta/sdk/typescript"
  }
}
"#
            .to_owned(),
        ),
        readme(
            "typescript",
            "git clone https://github.com/Natuvea/tacenta ../tacenta\ncd ../tacenta/sdk/typescript && npm install && npm run build:wasm && npm run build",
            "npm install\nnpm start",
        ),
    ]
}

fn swift(api_key: &str) -> Vec<File> {
    vec![
        file(
            "Package.swift",
            r#"// swift-tools-version:5.9
import PackageDescription

// The Tacenta Swift head as a local package: build it from the repository
// first (see README.md), then `swift run`.
let package = Package(
    name: "tacenta-app",
    platforms: [.macOS(.v12)],
    dependencies: [.package(path: "../tacenta/bindings/swift")],
    targets: [
        .executableTarget(
            name: "tacenta-app",
            dependencies: [.product(name: "Tacenta", package: "swift")],
            path: "Sources"
        ),
    ]
)
"#
            .to_owned(),
        ),
        file(
            "Sources/main.swift",
            format!(
                r#"import Foundation
import Tacenta

let apiKey = "{api_key}"
let password = "correct-horse-battery-staple"

do {{
    let tenant = try await Tenant.connect(apiKey: apiKey)
    try await tenant.signUp(username: "alice", password: password)
    try await tenant.signUp(username: "bob", password: password)

    let alice = try await tenant.signIn(username: "alice", password: password)
    let bob = try await tenant.signIn(username: "bob", password: password)

    if let toBob = try await alice.find(username: "bob") {{
        try await alice.send(to: toBob.address, message: Data("hello from swift".utf8))
    }}

    for try await message in bob.inbound() {{
        print(message.from.user, String(decoding: message.plaintext, as: UTF8.self))
        break
    }}
}} catch {{
    print("error: \(error)")
    exit(1)
}}
"#
            ),
        ),
        readme(
            "swift",
            "git clone https://github.com/Natuvea/tacenta ../tacenta\n(cd ../tacenta && bindings/swift/build-xcframework.sh)",
            "swift run",
        ),
    ]
}

fn kotlin(api_key: &str) -> Vec<File> {
    vec![
        file(
            "src/main/kotlin/Main.kt",
            format!(
                r#"// The Tacenta Kotlin head, from the JVM: the same Kotlin the Android .aar
// carries, bound to the library built for this machine (see README.md).
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import uniffi.tacenta_ffi.Tenant
import uniffi.tacenta_ffi.asFlow

fun main() = runBlocking {{
    val apiKey = "{api_key}"
    val password = "correct-horse-battery-staple"

    val tenant = Tenant.connect(apiKey)
    tenant.signUp("alice", password)
    tenant.signUp("bob", password)

    val alice = tenant.signIn("alice", password)
    val bob = tenant.signIn("bob", password)

    alice.find("bob")?.let {{ toBob ->
        alice.send(toBob.address, "hello from kotlin".toByteArray())
    }}

    val message = bob.inbound().asFlow().first()
    println("${{message.from.user}} ${{message.plaintext.decodeToString()}}")
}}
"#
            ),
        ),
        file(
            "build.gradle.kts",
            r#"// A JVM project against the Kotlin the repository generates and the FFI
// library built for this machine; an Android app takes the .aar instead
// (see README.md).
plugins {
    kotlin("jvm") version "2.0.20"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}

val tacenta = rootDir.resolve("../tacenta")
sourceSets["main"].kotlin.srcDir(tacenta.resolve("target/kotlin"))
sourceSets["main"].kotlin.srcDir(tacenta.resolve("bindings/android/lib/src/main/kotlin"))

application {
    mainClass = "MainKt"
}

tasks.named<JavaExec>("run") {
    systemProperty("jna.library.path", tacenta.resolve("target/release").absolutePath)
}
"#
            .to_owned(),
        ),
        file(
            "settings.gradle.kts",
            "rootProject.name = \"tacenta-app\"\n".to_owned(),
        ),
        readme(
            "kotlin",
            "git clone https://github.com/Natuvea/tacenta ../tacenta\n(cd ../tacenta && bindings/android/generate-kotlin.sh release target/kotlin)\n# For an Android app, bindings/android/build-aar.sh produces the .aar instead.",
            "gradle run",
        ),
    ]
}

fn rust(api_key: &str) -> Vec<File> {
    vec![
        file(
            "Cargo.toml",
            r#"[package]
name = "tacenta-app"
version = "0.1.0"
edition = "2024"

# The Tacenta Rust head, from a checkout beside this directory (see README.md).
[dependencies]
tacenta-client = { path = "../tacenta/crates/tacenta-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
"#
            .to_owned(),
        ),
        file(
            "src/main.rs",
            format!(
                r#"use tacenta_client::Tacenta;

#[tokio::main]
async fn main() -> Result<(), tacenta_client::Error> {{
    let tenant = Tacenta::connect("{api_key}").await?;
    tenant.sign_up("alice", "correct horse").await?;
    tenant.sign_up("bob", "correct horse").await?;

    let mut alice = tenant.sign_in("alice", "correct horse").await?;
    let mut bob = tenant.sign_in("bob", "correct horse").await?;

    let to_bob = alice.find("bob").await?.expect("bob signed up");
    alice.send(&to_bob.address, b"hello from rust").await?;

    for message in bob.receive().await? {{
        println!("{{}}: {{:?}}", message.from.user, message.plaintext);
    }}
    Ok(())
}}
"#
            ),
        ),
        readme(
            "rust",
            "git clone https://github.com/Natuvea/tacenta ../tacenta",
            "cargo run",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_scaffolds_with_the_key_in_place_and_a_readme() {
        for language in LANGUAGES {
            let files = scaffold(language, "tct_example_key").unwrap();
            assert!(files.iter().any(|f| f.path == "README.md"), "{language}");
            let with_key = files
                .iter()
                .filter(|f| f.contents.contains("tct_example_key"))
                .count();
            assert_eq!(with_key, 1, "{language}: the key goes in exactly one file");
            assert!(
                files.iter().all(|f| !f.contents.contains("your_api_key")),
                "{language}: no placeholder survives"
            );
        }
        assert!(scaffold("cobol", "tct_x").is_none());
    }

    #[test]
    fn writing_refuses_to_clobber() {
        let dir = std::env::temp_dir().join(format!("tacenta-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let files = scaffold("rust", "tct_example_key").unwrap();
        let written = write(&dir, &files).unwrap();
        assert_eq!(written.len(), files.len());
        assert!(write(&dir, &files).unwrap_err().contains("already exists"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
