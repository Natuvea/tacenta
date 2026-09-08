//! Core protocol engine, shared by the server and every client binding.
//!
//! Session and group state machines live here, on top of the protocol
//! primitives from the pinned `open-tacenta` dependency and the encodings from
//! `tacenta-wire`.

pub mod crypto;
pub mod persist;
pub mod session;
pub mod user;

pub use session::Session;
pub use tacenta_wire::WIRE_VERSION;
pub use user::User;
