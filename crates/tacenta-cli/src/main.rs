//! The `tacenta` CLI.
//!
//!   tacenta try [<api-key>]              send a test message round trip
//!   tacenta chat [<api-key>]             echo chat, each step shown
//!   tacenta chat --as <name> [--to <n>]  two-terminal chat between two users
//!   tacenta context create <name>        save an API key and make it active
//!   tacenta context list|use|active|delete
//!   tacenta keys create [--label <text>] mint a tenant API key
//!   tacenta keys list|revoke <prefix>
//!
//! `try` signs up two throwaway users in your tenant, sends an end-to-end
//! encrypted message from one to the other, and echoes it back — a full round
//! trip between two of your own users, with the encryption on your machine.
//!
//! It resolves the tenant API key from, in order: the inline argument, the
//! `TACENTA_API_KEY` environment variable, then the active context saved with
//! `tacenta context create`.
//!
//! `keys` manages the tenant's actual API keys through the gateway (decision
//! record 0048) — a different, tenant-admin credential from the API key
//! `context`/`try` use, so it prompts for the tenant's email and password
//! fresh each time rather than reading a saved context; there is no tenant
//! session yet for the gateway to hold instead.
//!
//! Environment (one or the other, never both):
//! - `TACENTA_HOST` — the server host (default `tacenta.com`). `try` and `chat`
//!   fetch `https://{host}/.well-known/tacenta`, the service document that says
//!   where the four TCP services are (decision 0090), so no port is
//!   known here; `keys` reaches the gateway at `https://` that same host.
//! - `TACENTA_GATEWAY_URL` — the gateway's full base URL instead, for pointing
//!   every command at a locally-run gateway (e.g. `http://127.0.0.1:4780`):
//!   `keys` posts there, and `try`/`chat` fetch the service document from
//!   there. A gateway run with no `GATEWAY_SERVICE_HOST` publishes a loopback
//!   document, so `cargo run -p tacenta-server` and `cargo run -p
//!   tacenta-gateway` are the whole local setup.
//!
//! `TACENTA_TRANSPORT=websocket` makes `try` and `chat` reach the services
//! over the document's WebSocket carriage (`/v1/ws/...` on the gateway)
//! instead of their TCP ports: the path a browser takes, checked from here.
//!
//! The service document is cached (`~/.cache/tacenta/service.toml`) for the
//! five minutes the gateway says it may be, so a second `try` within that
//! time does not fetch it again.

mod cache;
mod config;
mod gateway;
mod init;

use std::io::Write as _;

use rand::{RngCore as _, TryRngCore as _};
use tacenta_client::{Client, ClientTls, Tacenta};

const MESSAGE: &[u8] = b"hello from tacenta";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\n  error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("try") => try_cmd(args.next()).await,
        Some("chat") => chat_cmd(args).await,
        Some("context") | Some("ctx") => context_cmd(args),
        Some("keys") => keys_cmd(args).await,
        Some("init") => init_cmd(args),
        None | Some("help") | Some("-h") | Some("--help") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'. run `tacenta help`")),
    }
}

// --- try: the round trip -----------------------------------------------------

async fn try_cmd(explicit_key: Option<String>) -> Result<(), String> {
    let api_key = resolve_key(explicit_key)?;
    let tenant = tenant(&api_key).await?;

    print_journey(3);

    // Two fresh throwaway users each run, so re-running never collides with a
    // device already bound under trust-on-first-use.
    let sender = Cred::random("you");
    let responder = Cred::random("echo");

    eprintln!(
        "  signing up two users in your tenant: {} and {}...",
        sender.name, responder.name
    );
    let mut you = provision(&tenant, &sender).await?;
    let mut echo = provision(&tenant, &responder).await?;

    // The sender finds the responder in the tenant directory and sends. `find`
    // returns the responder's device address and primes the session.
    eprintln!(
        "  {} is sending an encrypted message to {}...",
        sender.name, responder.name
    );
    let target = you
        .find(&responder.name)
        .await
        .map_err(friendly)?
        .ok_or_else(|| format!("could not find {} in your tenant", responder.name))?;
    you.send(&target.address, MESSAGE).await.map_err(friendly)?;
    println!("  → {} sent \"{}\"", sender.name, text(MESSAGE));

    // The responder receives it and echoes it straight back on the same session.
    let incoming = wait_for_message(&mut echo).await?;
    echo.send(&incoming.from, &incoming.plaintext)
        .await
        .map_err(friendly)?;
    println!("  ↔ {} received it and echoed it back", responder.name);

    // The sender reads the reply — decrypted locally.
    let reply = wait_for_message(&mut you).await?;
    println!(
        "  ← {} got \"{}\" back, decrypted on your device",
        sender.name,
        text(&reply.plaintext),
    );
    println!("\n  end to end: both users are yours, and the server only ever saw ciphertext.");
    // Lead with an action, not links: the round trip is the moment of most
    // intent, and `tacenta chat` lets you keep using it with your own words
    // before the harder step of writing app code.
    println!("\n  next:");
    println!("    chat with your own words   tacenta chat");
    println!("    build it into an app       https://tacenta.com/sdk");
    println!("    what is proven             https://tacenta.com/assurance");
    println!("    tell us what broke         https://tacenta.com/sdk#feedback");
    Ok(())
}

// --- chat: interactive, the rung between `try` and an SDK integration --------

/// `tacenta chat` in two shapes:
///
/// - no `--as`: an echo chat that narrates each step (entered, encrypted, sent,
///   received, decrypted) so the encryption is *visible* — the teaching demo.
/// - `--as <name> [--to <name>]`: a real two-terminal chat between two of your
///   own users. One side names the other with `--to`; the other learns its peer
///   from the first message it receives.
///
/// Either way *you* type the messages, which is the "now what?" that `try`'s
/// canned round trip leaves unanswered.
async fn chat_cmd(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut as_name: Option<String> = None;
    let mut to_name: Option<String> = None;
    let mut key: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--as" => as_name = Some(args.next().ok_or("--as needs a name")?),
            "--to" => to_name = Some(args.next().ok_or("--to needs a name")?),
            other if !other.starts_with('-') && key.is_none() => key = Some(other.to_owned()),
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }
    if to_name.is_some() && as_name.is_none() {
        return Err(
            "--to needs --as: name yourself first, e.g. `tacenta chat --as me --to them`".into(),
        );
    }
    let api_key = resolve_key(key)?;
    let tenant = tenant(&api_key).await?;

    match as_name {
        None => chat_echo(&tenant).await,
        Some(name) => chat_peer(&tenant, &name, to_name).await,
    }
}

/// The tenant handle: where the services are comes from the server's service
/// document (decision 0090), fetched from the same gateway base URL
/// `keys` uses, or taken from the cache while that is fresh. Only a document
/// the handle accepted is cached, so a refused one is fetched again next
/// time rather than refused again from the cache.
async fn tenant(api_key: &str) -> Result<Tacenta, String> {
    let tls = ClientTls::web_pki();
    let url = format!(
        "{}{}",
        gateway::resolve_base_url()?,
        tacenta_client::WELL_KNOWN_PATH
    );
    let tenant = match cache::load().filter(|c| c.is_fresh_for(&url)) {
        Some(cached) => Tacenta::from_discovered(api_key, &url, &cached.document, &tls)
            .await
            .map_err(friendly)?,
        None => {
            let doc = Tacenta::fetch_document(&url, &tls)
                .await
                .map_err(friendly)?;
            let tenant = Tacenta::from_discovered(api_key, &url, &doc, &tls)
                .await
                .map_err(friendly)?;
            // A cache; if it cannot be written, the next run fetches again.
            let _ = cache::save(&cache::CachedService {
                url,
                fetched_at: cache::CachedService::now(),
                document: doc,
            });
            tenant
        }
    };
    match std::env::var("TACENTA_TRANSPORT").as_deref() {
        Ok("websocket") => tenant.websocket().map_err(friendly),
        Ok("tcp") | Err(_) => Ok(tenant),
        Ok(other) => Err(format!(
            "TACENTA_TRANSPORT is {other:?}; it must be `tcp` or `websocket`"
        )),
    }
}

fn print_chat_next() {
    println!("\n  next:");
    println!("    build it into an app   https://tacenta.com/sdk");
    println!("    what is proven         https://tacenta.com/assurance");
    println!("    tell us what broke     https://tacenta.com/sdk#feedback");
}

/// A one-line map of the getting-started path with the current step marked, so
/// the sense of place exists in the terminal too, not only on the website — the
/// terminal is where the "now what?" gulf actually is.
fn print_journey(here: usize) {
    let steps = ["get a key", "install", "try", "chat", "build"];
    let mapped: Vec<String> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i + 1 == here {
                format!("[{s}]")
            } else {
                (*s).to_string()
            }
        })
        .collect();
    eprintln!("  step {here} of 5:  {}", mapped.join("  ·  "));
    eprintln!();
}

/// The echo demo: type a line, watch it go through every step. Turn-based, so
/// the whole round trip can be narrated in order.
async fn chat_echo(tenant: &Tacenta) -> Result<(), String> {
    print_journey(4);
    let sender = Cred::random("you");
    let responder = Cred::random("echo");
    eprintln!(
        "  signing you in as {} and starting an echo bot ({}), both users in your tenant...",
        sender.name, responder.name
    );
    let mut you = provision(tenant, &sender).await?;
    let mut echo = provision(tenant, &responder).await?;
    let target = you
        .find(&responder.name)
        .await
        .map_err(friendly)?
        .ok_or_else(|| format!("could not find {} in your tenant", responder.name))?;

    eprintln!();
    eprintln!("  chatting with an echo bot. each line is shown at every step, so you");
    eprintln!("  can see the encryption happen. ctrl-d or /quit to leave.");
    eprintln!();

    let stdin = std::io::stdin();
    loop {
        print!("  > ");
        std::io::stdout()
            .flush()
            .map_err(|e| format!("could not write to stdout: {e}"))?;

        let mut line = String::new();
        let n = stdin
            .read_line(&mut line)
            .map_err(|e| format!("could not read input: {e}"))?;
        if n == 0 {
            eprintln!("\n  (end of input)");
            break; // ctrl-d
        }
        let msg = line.trim_end_matches(['\n', '\r']);
        let trimmed = msg.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "/quit" || trimmed == "/exit" {
            break;
        }

        // Each step, spelled out. It is honest: this is literally the pipeline.
        println!("    entered      {}", text(msg.as_bytes()));
        you.send(&target.address, msg.as_bytes())
            .await
            .map_err(friendly)?;
        println!("    encrypted →  sent as ciphertext (all the server sees)");

        match wait_for_message(&mut echo).await {
            Ok(incoming) => {
                if let Err(e) = echo.send(&incoming.from, &incoming.plaintext).await {
                    eprintln!("  ! the echo bot could not reply: {}", friendly(e));
                    continue;
                }
            }
            Err(e) => {
                eprintln!("  ! the echo bot did not receive it: {e}");
                continue;
            }
        }

        match wait_for_message(&mut you).await {
            Ok(reply) => {
                println!("    received  ←  ciphertext came back");
                println!("    decrypted    {}", text(&reply.plaintext));
            }
            Err(e) => eprintln!("  ! no reply came back: {e}"),
        }
    }
    print_chat_next();
    Ok(())
}

/// A real two-terminal chat between two of your own users. `receive` blocks, so
/// stdin is read on a side thread and fed through a channel while the main loop
/// polls [`Client::drain`](tacenta_client::Client::drain) for incoming mail
/// between sends — that is how one process both listens and lets you type.
///
/// Terminal echo and incoming lines interleave without raw-mode terminal
/// control; a polished TUI is a later step. What matters here is that it is a
/// genuine session between two devices, not a puppeted one.
async fn chat_peer(tenant: &Tacenta, as_name: &str, to_name: Option<String>) -> Result<(), String> {
    print_journey(4);
    // A random suffix keeps names unique, so re-running never collides with a
    // device already bound under trust-on-first-use.
    let me_cred = Cred::random(as_name);
    eprintln!("  signing you in as {}...", me_cred.name);
    let mut me = provision(tenant, &me_cred).await?;

    // With `--to`, resolve the peer now and speak first. Without it, wait to
    // learn the peer from whoever messages us.
    let mut peer = None;
    if let Some(to) = &to_name {
        let contact = me.find(to).await.map_err(friendly)?.ok_or_else(|| {
            format!(
                "could not find '{to}' — is the other terminal running, and is that its exact name?"
            )
        })?;
        peer = Some(contact.address);
    }

    eprintln!();
    eprintln!(
        "  you are {}. messages are end-to-end encrypted; the server routes only",
        me_cred.name
    );
    eprintln!("  ciphertext. ctrl-d or /quit to leave.");
    if peer.is_none() {
        eprintln!();
        eprintln!("  open another terminal and run:");
        eprintln!("      tacenta chat --as <name> --to {}", me_cred.name);
    }
    eprintln!();

    // stdin blocks, so read it off-thread and hand lines to the loop.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => break, // EOF or error drops tx, closing the channel
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    'chat: loop {
        // Send anything typed since the last tick.
        loop {
            match rx.try_recv() {
                Ok(line) => {
                    let msg = line.trim_end_matches(['\n', '\r']);
                    let trimmed = msg.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed == "/quit" || trimmed == "/exit" {
                        break 'chat;
                    }
                    match &peer {
                        Some(addr) => {
                            me.send(addr, msg.as_bytes()).await.map_err(friendly)?;
                            println!("    → sent (encrypted)");
                        }
                        None => {
                            eprintln!("  (no one connected yet — waiting for the other terminal)")
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break 'chat, // stdin closed
            }
        }

        // Check for incoming; learn the peer from the first message.
        for msg in me.drain().await.map_err(friendly)? {
            let who = msg.from.user.clone();
            println!("  ← {}: {}", who, text(&msg.plaintext));
            if peer.is_none() {
                eprintln!("  (connected to {who})");
                peer = Some(msg.from.clone());
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    print_chat_next();
    Ok(())
}

/// Resolve the tenant API key: inline argument, then `TACENTA_API_KEY`, then the
/// active context.
fn resolve_key(explicit: Option<String>) -> Result<String, String> {
    if let Some(k) = explicit {
        return validate_key(k);
    }
    if let Ok(k) = std::env::var("TACENTA_API_KEY")
        && !k.is_empty()
    {
        return validate_key(k);
    }
    if let Some(ctx) = config::load().active() {
        return Ok(ctx.api_key.clone());
    }
    Err(
        "no API key. pass it inline (`tacenta try <api-key>`), set TACENTA_API_KEY, \
         or save one with `tacenta context create <name>`"
            .into(),
    )
}

fn validate_key(k: String) -> Result<String, String> {
    if k.starts_with("tct_") {
        Ok(k)
    } else {
        Err("that does not look like an API key (it starts with tct_)".into())
    }
}

// --- context: the credential store -------------------------------------------

fn context_cmd(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    match args.next().as_deref() {
        Some("create") | Some("add") => ctx_create(args),
        Some("list") | Some("ls") => ctx_list(),
        Some("use") => ctx_use(args.next()),
        Some("active") | Some("current") => ctx_active(),
        Some("delete") | Some("rm") => ctx_delete(args.next()),
        _ => Err("usage: tacenta context <create|list|use|active|delete> [name]".into()),
    }
}

fn ctx_create(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut name: Option<String> = None;
    let mut key: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--api-key" => key = Some(args.next().ok_or("--api-key needs a value")?),
            other if !other.starts_with('-') && name.is_none() => name = Some(other.to_owned()),
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }
    let name = name.ok_or("usage: tacenta context create <name> [--api-key <key>]")?;

    // No key inline: prompt without echoing it to the terminal.
    let key = match key {
        Some(k) => k,
        None => rpassword::prompt_password("  API key: ")
            .map_err(|e| format!("could not read the API key: {e}"))?,
    };
    let key = validate_key(key.trim().to_owned())?;

    let mut cfg = config::load();
    match cfg.contexts.iter_mut().find(|c| c.name == name) {
        Some(c) => c.api_key = key,
        None => cfg.contexts.push(config::Context {
            name: name.clone(),
            api_key: key,
        }),
    }
    cfg.active_context = Some(name.clone());
    config::save(&cfg)?;
    println!("  saved context '{name}' and set it active");
    println!("  run:  tacenta try");
    Ok(())
}

fn ctx_list() -> Result<(), String> {
    let cfg = config::load();
    if cfg.contexts.is_empty() {
        println!("  no contexts. create one with `tacenta context create <name>`");
        return Ok(());
    }
    let active = cfg.active_context.as_deref();
    for c in &cfg.contexts {
        let mark = if Some(c.name.as_str()) == active {
            "*"
        } else {
            " "
        };
        println!("  {mark} {}", c.name);
    }
    Ok(())
}

fn ctx_use(name: Option<String>) -> Result<(), String> {
    let name = name.ok_or("usage: tacenta context use <name>")?;
    let mut cfg = config::load();
    if cfg.get(&name).is_none() {
        return Err(format!("no context named '{name}'"));
    }
    cfg.active_context = Some(name.clone());
    config::save(&cfg)?;
    println!("  active context: {name}");
    Ok(())
}

fn ctx_active() -> Result<(), String> {
    match config::load().active() {
        Some(c) => println!("  {}", c.name),
        None => println!("  (none)"),
    }
    Ok(())
}

fn ctx_delete(name: Option<String>) -> Result<(), String> {
    let name = name.ok_or("usage: tacenta context delete <name>")?;
    let mut cfg = config::load();
    let before = cfg.contexts.len();
    cfg.contexts.retain(|c| c.name != name);
    if cfg.contexts.len() == before {
        return Err(format!("no context named '{name}'"));
    }
    if cfg.active_context.as_deref() == Some(name.as_str()) {
        cfg.active_context = None;
    }
    config::save(&cfg)?;
    println!("  deleted context '{name}'");
    Ok(())
}

// --- keys: tenant API-key management -----------------------------------------

async fn keys_cmd(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    match args.next().as_deref() {
        Some("create") => keys_create(args).await,
        Some("list") | Some("ls") => keys_list().await,
        Some("revoke") | Some("rm") => keys_revoke(args.next()).await,
        _ => Err("usage: tacenta keys <create|list|revoke> [args]".into()),
    }
}

async fn keys_create(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut label: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--label" => label = Some(args.next().ok_or("--label needs a value")?),
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }

    let email = prompt_email()?;
    let password = rpassword::prompt_password("  tenant password: ")
        .map_err(|e| format!("could not read the password: {e}"))?;

    let base = gateway::resolve_base_url()?;
    let created = gateway::create_key(&base, &email, &password, label.as_deref()).await?;
    println!("  key created: {}", created.key_prefix);
    println!(
        "  this API key is shown once. store it somewhere safe now:\n\n    {}\n",
        created.api_key
    );
    println!(
        "  use it with:  tacenta context create <name> --api-key {}",
        created.api_key
    );
    Ok(())
}

async fn keys_list() -> Result<(), String> {
    let email = prompt_email()?;
    let password = rpassword::prompt_password("  tenant password: ")
        .map_err(|e| format!("could not read the password: {e}"))?;

    let base = gateway::resolve_base_url()?;
    let listed = gateway::list_keys(&base, &email, &password).await?;
    if listed.keys.is_empty() {
        println!("  no keys");
        return Ok(());
    }
    for k in &listed.keys {
        let label = k.label.as_deref().unwrap_or("(no label)");
        println!("  {}  {}  created_at={}", k.prefix, label, k.created_at);
    }
    Ok(())
}

async fn keys_revoke(prefix: Option<String>) -> Result<(), String> {
    let prefix = prefix.ok_or("usage: tacenta keys revoke <prefix>")?;
    let email = prompt_email()?;
    let password = rpassword::prompt_password("  tenant password: ")
        .map_err(|e| format!("could not read the password: {e}"))?;

    let base = gateway::resolve_base_url()?;
    let revoked = gateway::revoke_key(&base, &email, &password, &prefix).await?;
    if revoked.revoked {
        println!("  revoked {prefix}");
    } else {
        println!("  no key with prefix {prefix}");
    }
    Ok(())
}

/// Prompt for the tenant email on stdin. Not a secret, so echoed normally —
/// only the password after it is hidden.
fn prompt_email() -> Result<String, String> {
    print!("  tenant email: ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("could not write to stdout: {e}"))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("could not read the email: {e}"))?;
    let email = line.trim().to_owned();
    if email.is_empty() {
        return Err("no email given".into());
    }
    Ok(email)
}

fn print_help() {
    eprintln!(
        "tacenta - end-to-end encrypted messaging\n\
         \n\
         usage:\n\
        \x20 tacenta try [<api-key>]          send a test message round trip\n\
        \x20 tacenta chat [<api-key>]         echo chat, each step shown\n\
        \x20 tacenta chat --as <name>         two-terminal chat (other side --to)\n\
        \x20 tacenta context create <name>    save an API key and make it active\n\
        \x20 tacenta context list             list saved contexts\n\
        \x20 tacenta context use <name>       switch the active context\n\
        \x20 tacenta context active           print the active context\n\
        \x20 tacenta context delete <name>    remove a context\n\
        \x20 tacenta keys create [--label]    mint a tenant API key\n\
        \x20 tacenta keys list                list the tenant's keys\n\
        \x20 tacenta keys revoke <prefix>     revoke a tenant key\n\
        \x20 tacenta init <language> [dir]    scaffold an app with your key in place\n\
         \n\
         `try` and `init` take the key from the inline argument (`--api-key`\n\
         for init), then TACENTA_API_KEY, then the active context. `init`\n\
         knows typescript, swift, kotlin and rust. `keys` prompts for the tenant's email and\n\
         password, a different credential from the API key context/try use."
    );
}

// --- init: an app scaffolded with the key in place ---------------------------

/// `tacenta init <language> [directory] [--api-key <key>]`: the language's
/// quickstart, with the key already in the sample, the way the site's
/// language page shows it (decision 0090).
fn init_cmd(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut language: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut key: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--api-key" => key = Some(args.next().ok_or("--api-key needs a value")?),
            other if other.starts_with('-') => {
                return Err(format!("unexpected argument '{other}'"));
            }
            other if language.is_none() => language = Some(other.to_owned()),
            other if dir.is_none() => dir = Some(other.to_owned()),
            other => return Err(format!("unexpected argument '{other}'")),
        }
    }
    let usage = format!(
        "usage: tacenta init <{}> [directory] [--api-key <key>]",
        init::LANGUAGES.join("|")
    );
    let language = language.ok_or_else(|| usage.clone())?;
    let files = init::scaffold(&language, "")
        .ok_or_else(|| format!("no scaffold for '{language}'. {usage}"))?;
    drop(files);
    let api_key = resolve_key(key)?;
    let files = init::scaffold(&language, &api_key).expect("checked above");
    let dir = std::path::PathBuf::from(dir.unwrap_or_else(|| format!("tacenta-{language}")));
    let written = init::write(&dir, &files)?;

    print_journey(5);
    eprintln!("  scaffolded a {language} app in {}:", dir.display());
    for path in &written {
        eprintln!("    {}", path.display());
    }
    eprintln!();
    eprintln!("  your API key is in the sample: keep the directory out of version control.");
    eprintln!("  the README says how to build the SDK from a checkout and run the sample;");
    eprintln!("  there is no package to install yet, so that is the install line for now.");
    println!("\n  next:");
    println!(
        "    build and run it          see {}/README.md",
        dir.display()
    );
    println!("    the {language} page         https://tacenta.com/sdk/{language}");
    println!("    tell us what broke        https://tacenta.com/sdk#feedback");
    Ok(())
}

// --- helpers -----------------------------------------------------------------

/// A throwaway account: a random username under `prefix` and a random password.
struct Cred {
    name: String,
    password: String,
}

impl Cred {
    fn random(prefix: &str) -> Cred {
        let mut seed = [0u8; 4];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut seed);
        let name = format!("{prefix}-{:08x}", u32::from_le_bytes(seed));
        let mut p = [0u8; 16];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut p);
        let password = p.iter().map(|b| format!("{b:02x}")).collect();
        Cred { name, password }
    }
}

/// Sign up a throwaway user in the tenant and sign in, returning a connected
/// client. Where the services are is the tenant handle's business.
async fn provision(tenant: &Tacenta, cred: &Cred) -> Result<Client, String> {
    tenant
        .sign_up(&cred.name, &cred.password)
        .await
        .map_err(friendly)?;
    tenant
        .sign_in(&cred.name, &cred.password)
        .await
        .map_err(friendly)
}

/// `receive` blocks until mail arrives, so bound it with a timeout — otherwise a
/// message that never comes would hang the command forever.
async fn wait_for_message(client: &mut Client) -> Result<tacenta_client::Received, String> {
    let wait = std::time::Duration::from_secs(15);
    match tokio::time::timeout(wait, client.receive()).await {
        Ok(Ok(batch)) => batch
            .into_iter()
            .next()
            .ok_or_else(|| "the delivery was empty".to_owned()),
        Ok(Err(e)) => Err(friendly(e)),
        Err(_) => Err("no message arrived within 15s".into()),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn friendly(e: tacenta_client::Error) -> String {
    format!("{e}")
}
