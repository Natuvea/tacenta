//! Decoder robustness (cold read section 8, adopted): structure-aware mutation
//! of valid encodings plus random bytes, with a tracking allocator. Asserts
//! that no decoder panics, that none requests a large allocation from a small
//! input, and that no input a decoder accepts re-encodes to different bytes.
//! The two tests share the global allocator's counter, so they take a lock.
use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tacenta_group::*;

struct Tracking;
static MAX_ALLOC: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        MAX_ALLOC.fetch_max(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        MAX_ALLOC.fetch_max(n, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Tracking = Tracking;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn g() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}
fn m(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

#[derive(Default, Debug)]
struct Stats {
    inputs: usize,
    ok: usize,
    panics: usize,
    max_alloc: usize,
    worst_alloc_input_len: usize,
    slowest_micros: u128,
}

fn run(stats: &mut Stats, len: usize, f: impl FnOnce() -> bool) {
    MAX_ALLOC.store(0, Ordering::Relaxed);
    let t = Instant::now();
    let r = catch_unwind(AssertUnwindSafe(f));
    let micros = t.elapsed().as_micros();
    stats.inputs += 1;
    stats.slowest_micros = stats.slowest_micros.max(micros);
    let alloc = MAX_ALLOC.load(Ordering::Relaxed);
    if alloc > stats.max_alloc {
        stats.max_alloc = alloc;
        stats.worst_alloc_input_len = len;
    }
    match r {
        Ok(true) => stats.ok += 1,
        Ok(false) => {}
        Err(_) => stats.panics += 1,
    }
}

/// All variants of a valid encoding: prefixes, single-byte overwrites, 4-byte
/// and 2-byte length-field overwrites with extreme values, deletions, and some
/// random insertions.
fn variants(valid: &[u8], rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut out = vec![valid.to_vec()];
    for n in 0..valid.len() {
        out.push(valid[..n].to_vec());
    }
    for i in 0..valid.len() {
        for v in [0x00u8, 0x01, 0x7f, 0x80, 0xff, (rng.next() & 0xff) as u8] {
            let mut c = valid.to_vec();
            c[i] = v;
            out.push(c);
        }
        let mut c = valid.to_vec();
        c.remove(i);
        out.push(c);
    }
    for i in 0..valid.len().saturating_sub(4) {
        for v in [
            u32::MAX,
            0x7fff_ffff,
            0x0001_0000,
            0x0000_ffff,
            0x0000_2000,
            0x0100_0000,
        ] {
            let mut c = valid.to_vec();
            c[i..i + 4].copy_from_slice(&v.to_be_bytes());
            out.push(c);
        }
    }
    for i in 0..valid.len().saturating_sub(2) {
        let mut c = valid.to_vec();
        c[i..i + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        out.push(c);
    }
    for _ in 0..200 {
        let mut c = valid.to_vec();
        let at = (rng.next() as usize) % (c.len() + 1);
        let n = 1 + (rng.next() as usize) % 8;
        for _ in 0..n {
            c.insert(at, (rng.next() & 0xff) as u8);
        }
        out.push(c);
    }
    out
}

fn randoms(rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|_| {
            let len = (rng.next() as usize) % 9000;
            (0..len).map(|_| (rng.next() & 0xff) as u8).collect()
        })
        .collect()
}

fn report(name: &str, s: &Stats) {
    println!(
        "gc-fuzz {name:<28} inputs={:<8} accepted={:<6} panics={} max_single_alloc_bytes={} (input len {}) slowest_micros={}",
        s.inputs, s.ok, s.panics, s.max_alloc, s.worst_alloc_input_len, s.slowest_micros
    );
}

#[test]
fn gc_fuzz_every_group_decoder() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let alice = m("alice-key-alice-key-alice-key-32");
    let bob = m("bob-key-bob-key-bob-key-bob-key-32");
    let carol = m("carol-key-carol-key-carol-key-32");
    let mut members = vec![alice.clone(), bob.clone(), carol.clone()];
    members.sort_by(|a, b| a.identity().cmp(b.identity()));
    let roster = Roster::new(
        g(),
        1,
        [3; 32],
        alice.clone(),
        POLICY_VERSION_V1,
        false,
        members.clone(),
    )
    .unwrap();
    let genesis = Roster::new(
        g(),
        0,
        [0; 32],
        alice.clone(),
        POLICY_VERSION_V1,
        false,
        vec![alice.clone()],
    )
    .unwrap();
    let ctx = ApplicationContext::new(
        g(),
        2,
        [4; 32],
        alice.clone(),
        bob.clone(),
        9,
        b"payload".to_vec(),
    )
    .unwrap();
    let invitation = Invitation::new(
        InvitationId::new([1; 16]),
        g(),
        bob.clone(),
        0,
        [2; 32],
        POLICY_VERSION_V1,
        100,
    )
    .unwrap();
    let bootstrap = InvitationBootstrap::new(invitation.clone(), genesis.clone()).unwrap();
    let acceptance =
        InvitationAcceptance::new(g(), InvitationId::new([1; 16]), 0, [2; 32]).unwrap();
    let revocation =
        InvitationRevocation::new(g(), InvitationId::new([1; 16]), 0, [2; 32]).unwrap();
    let mut book = InvitationBook::new(g());
    book.create(
        &alice,
        &alice,
        std::slice::from_ref(&alice),
        invitation.clone(),
        0,
    )
    .unwrap();
    let mut receiver = GroupReceiver::new(roster.clone(), [9; 32], bob.clone());
    let future = ApplicationContext::new(
        g(),
        2,
        [4; 32],
        alice.clone(),
        bob.clone(),
        1,
        b"f".to_vec(),
    )
    .unwrap();
    assert_eq!(
        receiver.receive(&future, &alice, [5; 32]),
        ReceiveDisposition::Deferred
    );
    let cur = ApplicationContext::new(
        g(),
        1,
        [9; 32],
        alice.clone(),
        bob.clone(),
        1,
        b"c".to_vec(),
    )
    .unwrap();
    assert!(matches!(
        receiver.receive(&cur, &alice, [6; 32]),
        ReceiveDisposition::Accepted { .. }
    ));
    let view = RosterView::accept_genesis(&alice, genesis.clone(), [1; 32]).unwrap();
    let send = LogicalSend::new(
        &roster,
        [7; 32],
        alice.clone(),
        3,
        vec![bob.clone(), carol.clone()],
        b"hi".to_vec(),
    )
    .unwrap();

    // outbox transcript: TCGI, TCGP, TCGH, TCGA
    let intent = send.encode_intent().unwrap();
    let lp = |v: &[u8]| {
        let mut o = (v.len() as u32).to_be_bytes().to_vec();
        o.extend_from_slice(v);
        o
    };
    let mut tcgi = b"TCGI".to_vec();
    tcgi.extend_from_slice(&lp(&intent));
    let context = send.application_context(&bob).unwrap().encode().unwrap();
    let progress = |tag: &[u8], suffix: &[u8]| {
        let mut o = tag.to_vec();
        o.extend_from_slice(&lp(&context));
        o.extend_from_slice(&[0; 32]);
        o.extend_from_slice(&lp(b"ciphertext"));
        o.extend_from_slice(suffix);
        o
    };
    let tcgp = progress(b"TCGP", &[]);
    let tcgh = progress(b"TCGH", &[1, 0]);
    let tcga = progress(b"TCGA", &[]);

    let mut all: Vec<(&str, Stats)> = vec![];
    macro_rules! fuzz {
        ($name:expr, $valid:expr, $decode:expr) => {{
            let valid: Vec<u8> = $valid;
            let mut stats = Stats::default();
            let mut corpus = variants(&valid, &mut rng);
            corpus.extend(randoms(&mut rng, 3000));
            for input in corpus {
                let len = input.len();
                run(&mut stats, len, || {
                    let f = $decode;
                    f(&input)
                });
            }
            report($name, &stats);
            all.push(($name, stats));
        }};
    }
    fuzz!("Roster::decode", roster.encode().unwrap(), |b: &[u8]| {
        Roster::decode(b).is_ok()
    });
    fuzz!(
        "ApplicationContext::decode",
        ctx.encode().unwrap(),
        |b: &[u8]| ApplicationContext::decode(b).is_ok()
    );
    fuzz!(
        "GroupPayload::decode(roster)",
        GroupPayload::Roster(roster.clone()).encode().unwrap(),
        |b: &[u8]| GroupPayload::decode(b).is_ok()
    );
    fuzz!(
        "GroupPayload::decode(app)",
        GroupPayload::Application(ctx.clone()).encode().unwrap(),
        |b: &[u8]| GroupPayload::decode(b).is_ok()
    );
    fuzz!(
        "GroupPayload::decode(boot)",
        GroupPayload::InvitationBootstrap(bootstrap.clone())
            .encode()
            .unwrap(),
        |b: &[u8]| GroupPayload::decode(b).is_ok()
    );
    fuzz!(
        "InvitationBootstrap::decode",
        bootstrap.encode().unwrap(),
        |b: &[u8]| InvitationBootstrap::decode(b).is_ok()
    );
    fuzz!(
        "InvitationAcceptance::decode",
        acceptance.encode().unwrap(),
        |b: &[u8]| InvitationAcceptance::decode(b).is_ok()
    );
    fuzz!(
        "InvitationRevocation::decode",
        revocation.encode().unwrap(),
        |b: &[u8]| InvitationRevocation::decode(b).is_ok()
    );
    fuzz!(
        "InvitationBook::decode_state",
        book.encode_state().unwrap(),
        |b: &[u8]| InvitationBook::decode_state(b, g()).is_ok()
    );
    fuzz!(
        "GroupReceiver::decode_state",
        receiver.encode_state().unwrap(),
        |b: &[u8]| GroupReceiver::decode_state(b, |_| [9; 32], |_| [5; 32]).is_ok()
    );
    fuzz!(
        "RosterView::decode_state",
        view.encode_state().unwrap(),
        |b: &[u8]| RosterView::decode_state(b, &alice, |_| [1; 32]).is_ok()
    );
    fuzz!(
        "LogicalSend::decode_intent",
        intent.clone(),
        |b: &[u8]| LogicalSend::decode_intent(b).is_ok()
    );
    // transcript: each record kind alone (the recovery function takes a list)
    for (name, record) in [
        ("TCGI", tcgi.clone()),
        ("TCGP", tcgp.clone()),
        ("TCGH", tcgh.clone()),
        ("TCGA", tcga.clone()),
    ] {
        let mut stats = Stats::default();
        let mut corpus = variants(&record, &mut rng);
        corpus.extend(randoms(&mut rng, 1000).into_iter().map(|mut r| {
            let mut v = name.as_bytes().to_vec();
            v.append(&mut r);
            v
        }));
        for input in corpus {
            let len = input.len();
            let prefix = if name == "TCGI" {
                vec![]
            } else {
                vec![tcgi.clone()]
            };
            run(&mut stats, len, || {
                let mut entries = prefix.clone();
                entries.push(input.clone());
                GroupOutbox::recover_from_transcript(g(), &entries, |_| [0; 32]).is_ok()
            });
        }
        report(&format!("recover_from_transcript {name}"), &stats);
        all.push(("recover", stats));
    }
    let total_panics: usize = all.iter().map(|(_, s)| s.panics).sum();
    let worst = all.iter().map(|(_, s)| s.max_alloc).max().unwrap();
    println!("gc-fuzz TOTAL panics={total_panics} worst_single_alloc_bytes={worst}");
    assert_eq!(total_panics, 0);
    // The largest legitimate request is a receiver state's entry vector: at
    // most 512 entries of about 120 bytes. 131,072 leaves room for that and
    // refuses a decoder that sizes an allocation from an untrusted count.
    assert!(worst < 131_072, "a decoder requested {worst} bytes");
}

/// Canonicality: any input a decoder accepts must re-encode to the same bytes.
#[test]
fn gc_fuzz_canonical_round_trip_every_group_decoder() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let alice = m("alice-key-alice-key-alice-key-32");
    let bob = m("bob-key-bob-key-bob-key-bob-key-32");
    let mut members = vec![alice.clone(), bob.clone()];
    members.sort_by(|a, b| a.identity().cmp(b.identity()));
    let roster = Roster::new(
        g(),
        1,
        [3; 32],
        alice.clone(),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap();
    let genesis = Roster::new(
        g(),
        0,
        [0; 32],
        alice.clone(),
        POLICY_VERSION_V1,
        false,
        vec![alice.clone()],
    )
    .unwrap();
    let ctx = ApplicationContext::new(
        g(),
        2,
        [4; 32],
        alice.clone(),
        bob.clone(),
        9,
        b"payload".to_vec(),
    )
    .unwrap();
    let invitation = Invitation::new(
        InvitationId::new([1; 16]),
        g(),
        bob.clone(),
        0,
        [2; 32],
        POLICY_VERSION_V1,
        100,
    )
    .unwrap();
    let bootstrap = InvitationBootstrap::new(invitation.clone(), genesis.clone()).unwrap();
    let acceptance =
        InvitationAcceptance::new(g(), InvitationId::new([1; 16]), 0, [2; 32]).unwrap();
    let revocation =
        InvitationRevocation::new(g(), InvitationId::new([1; 16]), 0, [2; 32]).unwrap();
    let mut book = InvitationBook::new(g());
    book.create(
        &alice,
        &alice,
        std::slice::from_ref(&alice),
        invitation.clone(),
        0,
    )
    .unwrap();
    let send = LogicalSend::new(
        &roster,
        [7; 32],
        alice.clone(),
        3,
        vec![bob.clone()],
        b"hi".to_vec(),
    )
    .unwrap();
    let mut receiver = GroupReceiver::new(roster.clone(), [9; 32], bob.clone());
    let cur = ApplicationContext::new(
        g(),
        1,
        [9; 32],
        alice.clone(),
        bob.clone(),
        1,
        b"c".to_vec(),
    )
    .unwrap();
    receiver.receive(&cur, &alice, [6; 32]);
    let view = RosterView::accept_genesis(&alice, genesis.clone(), [1; 32]).unwrap();

    let mut total_non_canonical = 0usize;
    macro_rules! canon {
        ($name:expr, $valid:expr, $roundtrip:expr) => {{
            let valid: Vec<u8> = $valid;
            let mut corpus = variants(&valid, &mut rng);
            corpus.extend(randoms(&mut rng, 2000));
            let (mut accepted, mut non_canonical) = (0usize, 0usize);
            let mut first: Option<Vec<u8>> = None;
            for input in corpus {
                let f = $roundtrip;
                if let Some(back) = f(&input) {
                    accepted += 1;
                    if back != input {
                        non_canonical += 1;
                        first.get_or_insert(input.clone());
                    }
                }
            }
            println!("gc-canon {:<28} accepted={accepted:<6} non_canonical_accepted={non_canonical} example_len={:?}", $name, first.as_ref().map(|v| v.len()));
            total_non_canonical += non_canonical;
        }};
    }
    canon!("Roster", roster.encode().unwrap(), |b: &[u8]| {
        Roster::decode(b).ok().and_then(|r| r.encode().ok())
    });
    canon!("ApplicationContext", ctx.encode().unwrap(), |b: &[u8]| {
        ApplicationContext::decode(b)
            .ok()
            .and_then(|r| r.encode().ok())
    });
    canon!(
        "GroupPayload(roster)",
        GroupPayload::Roster(roster.clone()).encode().unwrap(),
        |b: &[u8]| GroupPayload::decode(b).ok().and_then(|r| r.encode().ok())
    );
    canon!(
        "GroupPayload(app)",
        GroupPayload::Application(ctx.clone()).encode().unwrap(),
        |b: &[u8]| GroupPayload::decode(b).ok().and_then(|r| r.encode().ok())
    );
    canon!(
        "InvitationBootstrap",
        bootstrap.encode().unwrap(),
        |b: &[u8]| InvitationBootstrap::decode(b)
            .ok()
            .and_then(|r| r.encode().ok())
    );
    canon!(
        "InvitationAcceptance",
        acceptance.encode().unwrap(),
        |b: &[u8]| InvitationAcceptance::decode(b)
            .ok()
            .and_then(|r| r.encode().ok())
    );
    canon!(
        "InvitationRevocation",
        revocation.encode().unwrap(),
        |b: &[u8]| InvitationRevocation::decode(b)
            .ok()
            .and_then(|r| r.encode().ok())
    );
    canon!(
        "InvitationBook state",
        book.encode_state().unwrap(),
        |b: &[u8]| InvitationBook::decode_state(b, g())
            .ok()
            .and_then(|r| r.encode_state().ok())
    );
    canon!(
        "LogicalSend intent",
        send.encode_intent().unwrap(),
        |b: &[u8]| LogicalSend::decode_intent(b)
            .ok()
            .and_then(|r| r.encode_intent().ok())
    );
    canon!(
        "GroupReceiver state",
        receiver.encode_state().unwrap(),
        |b: &[u8]| GroupReceiver::decode_state(b, |_| [9; 32], |_| [0; 32])
            .ok()
            .and_then(|r| r.encode_state().ok())
    );
    canon!(
        "RosterView state",
        view.encode_state().unwrap(),
        |b: &[u8]| RosterView::decode_state(b, &alice, |_| [1; 32])
            .ok()
            .and_then(|r| r.encode_state().ok())
    );
    println!("gc-canon TOTAL non_canonical_accepted={total_non_canonical}");
    assert_eq!(total_non_canonical, 0);
}
