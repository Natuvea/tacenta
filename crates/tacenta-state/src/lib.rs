//! Delivery state machines, generic over the message type.
//!
//! This crate is part of the verified zone: dependency-free, written in
//! the Aeneas-friendly subset (no `unsafe`, no `?` operator, no
//! panicking paths), and translated to Lean to be proved against the
//! specification (`spec/Tacenta/Session.lean`, `spec/Tacenta/User.lean`).
//! Genericity over the message type `T` is what keeps the translation
//! free of this workspace's other crates; `tacenta-core` instantiates
//! `T` with its envelope type.

#![allow(clippy::question_mark)]

pub mod session;
pub mod user;

pub use session::Session;
pub use user::User;
