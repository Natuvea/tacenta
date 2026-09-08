//! The Rust head checks itself against the surface manifest (decision 0090), in both directions: every Rust symbol `sdk/surface.json`
//! names must be a public function in the named type's own `impl` block,
//! and every public function in those blocks must be a row of the manifest
//! or listed under `unlisted` with its reason. Parity with the other heads
//! is therefore a failing test, not a table someone updates, and the facade
//! cannot grow unrecorded.

use std::collections::BTreeSet;
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `pub fn` / `pub async fn` names inside every inherent `impl` block
/// whose header matches `header` (a substring such as `impl Tacenta {` or
/// `Client<P> {`), located by brace depth from the header line. Trait impls
/// (`impl X for Y`) never match because the header test excludes ` for `.
fn methods_of(source: &str, header: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut depth = 0i32;
    let mut inside = false;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !inside
            && trimmed.starts_with("impl")
            && trimmed.contains(header)
            && !trimmed.contains(" for ")
        {
            inside = true;
            depth = 0;
        }
        if inside {
            if depth == 1
                && let Some(rest) = trimmed
                    .strip_prefix("pub async fn ")
                    .or_else(|| trimmed.strip_prefix("pub fn "))
            {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                names.insert(name);
            }
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if depth <= 0 && line.contains('}') {
                inside = false;
            }
        }
    }
    names
}

#[test]
fn the_rust_facade_and_the_manifest_agree_both_ways() {
    let manifest: serde_json::Value =
        serde_json::from_str(&read("../../sdk/surface.json")).expect("sdk/surface.json parses");
    let pools = [
        (
            "Tacenta",
            methods_of(&read("src/tenant.rs"), "impl Tacenta {"),
        ),
        ("Client", methods_of(&read("src/lib.rs"), "Client<P> {")),
    ];
    assert!(
        pools.iter().all(|(_, p)| !p.is_empty()),
        "found no impl blocks: {pools:?}"
    );

    // Manifest -> code.
    let mut named: Vec<(String, String)> = Vec::new();
    for object in manifest["objects"].as_array().expect("objects") {
        for call in object["calls"].as_array().expect("calls") {
            if let Some(symbol) = call["rust"].as_str() {
                let (ty, name) = symbol.split_once("::").expect("Type::fn");
                named.push((ty.to_owned(), name.to_owned()));
            }
        }
    }
    let missing: Vec<String> = named
        .iter()
        .filter(|(ty, name)| {
            let pool = &pools
                .iter()
                .find(|(t, _)| t == ty)
                .unwrap_or_else(|| panic!("unknown type {ty}"))
                .1;
            !pool.contains(name)
        })
        .map(|(ty, name)| format!("{ty}::{name}"))
        .collect();
    assert!(
        missing.is_empty(),
        "sdk/surface.json names Rust symbols the facade does not have: {missing:?}"
    );

    // Code -> manifest or unlisted.
    let unlisted = &manifest["unlisted"]["rust"];
    let mut unrecorded = Vec::new();
    for (ty, pool) in &pools {
        for name in pool {
            let in_rows = named.iter().any(|(t, n)| t == ty && n == name);
            let excused = unlisted[ty].get(name).is_some();
            if !in_rows && !excused {
                unrecorded.push(format!("{ty}::{name}"));
            }
        }
    }
    assert!(
        unrecorded.is_empty(),
        "public calls on the facade that are neither a row of sdk/surface.json nor listed under unlisted.rust: {unrecorded:?}"
    );
}

/// The variants of `pub enum <name>` in `source`, by brace depth from the
/// header line.
fn variants_of(source: &str, name: &str) -> BTreeSet<String> {
    let header = format!("pub enum {name} ");
    let mut names = BTreeSet::new();
    let mut inside = false;
    let mut depth = 0i32;
    for line in source.lines() {
        let t = line.trim_start();
        if !inside && t.starts_with(&header) {
            inside = true;
            depth = 0;
        }
        if inside {
            // A comment or attribute line neither names a variant nor
            // counts toward the braces: a doc comment may quote one.
            if t.starts_with("//") || t.starts_with('#') || t.is_empty() {
                continue;
            }
            if depth == 1 {
                let v: String = t
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !v.is_empty() {
                    names.insert(v);
                }
            }
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if depth <= 0 && line.contains('}') {
                break;
            }
        }
    }
    names
}

#[test]
fn the_error_kinds_and_the_manifest_agree_both_ways() {
    let manifest: serde_json::Value =
        serde_json::from_str(&read("../../sdk/surface.json")).expect("sdk/surface.json parses");
    let kinds = variants_of(&read("src/lib.rs"), "ErrorKind");
    assert!(!kinds.is_empty(), "found no ErrorKind variants");
    let named: BTreeSet<String> = manifest["errors"]["kinds"]
        .as_array()
        .expect("errors.kinds")
        .iter()
        .filter_map(|k| k["rust"].as_str())
        .map(|symbol| {
            symbol
                .strip_prefix("ErrorKind::")
                .expect("ErrorKind::<variant>")
                .to_owned()
        })
        .collect();
    assert_eq!(
        named, kinds,
        "sdk/surface.json's error kinds and ErrorKind's variants differ"
    );
}

/// `ErrorKind::as_str()` is the spelling the string-carrying heads use (the
/// wasm head throws it, the TypeScript head matches it), so it must be the
/// manifest's `typescript` column, kind for kind.
#[test]
fn the_kind_names_are_the_manifests_typescript_column() {
    use tacenta_client::ErrorKind;
    let manifest: serde_json::Value =
        serde_json::from_str(&read("../../sdk/surface.json")).expect("sdk/surface.json parses");
    let all = [
        ErrorKind::Network,
        ErrorKind::Discovery,
        ErrorKind::UnknownTenant,
        ErrorKind::UsernameTaken,
        ErrorKind::InvalidUsername,
        ErrorKind::WeakPassword,
        ErrorKind::SignUpRefused,
        ErrorKind::SignInRefused,
        ErrorKind::IdentityMismatch,
        ErrorKind::NotFound,
        ErrorKind::RateLimited,
        ErrorKind::ServerFailure,
        ErrorKind::State,
        ErrorKind::StoreUnavailable,
        ErrorKind::InvalidArgument,
        ErrorKind::Internal,
    ];
    let mut expected: Vec<(String, String)> = manifest["errors"]["kinds"]
        .as_array()
        .expect("errors.kinds")
        .iter()
        .map(|k| {
            let rust = k["rust"]
                .as_str()
                .expect("rust")
                .trim_start_matches("ErrorKind::");
            let ts = k["typescript"]
                .as_str()
                .expect("typescript")
                .trim_matches('"');
            (rust.to_owned(), ts.to_owned())
        })
        .collect();
    expected.sort();
    let mut actual: Vec<(String, String)> = all
        .iter()
        .map(|k| (format!("{k:?}"), k.as_str().to_owned()))
        .collect();
    actual.sort();
    assert_eq!(
        actual, expected,
        "ErrorKind::as_str and the manifest's typescript column differ"
    );
}
