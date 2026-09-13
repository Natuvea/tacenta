//! Private operation stages used by the client coordinator.
//!
//! A prepared send owns the exact bytes that reached the transport boundary.
//! Retrying it therefore cannot encrypt again or advance a ratchet a second
//! time. It is deliberately private while durable outbox storage is introduced
//! by GC-03.

#[derive(Clone, Debug)]
pub(crate) struct PreparedSend {
    request: Vec<u8>,
}

impl PreparedSend {
    pub(crate) fn new(request: Vec<u8>) -> Self {
        Self { request }
    }

    pub(crate) fn request(&self) -> &[u8] {
        &self.request
    }
}
