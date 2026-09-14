//! Private operation stages used by the client coordinator.
//!
//! A prepared send owns the exact bytes that reached the transport boundary.
//! Retrying it therefore cannot encrypt again or advance a ratchet a second
//! time. It is deliberately private while durable outbox storage is introduced
//! by GC-03.

use tacenta_relay::{DeviceAddr, Request, encode_request};

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

/// An acknowledgement prepared only after the caller has processed a fetched
/// delivery prefix.  Fetching carries no acknowledgement bytes by itself,
/// which leaves the durable receive coordinator a concrete boundary at which
/// to record every disposition before it lets the cumulative ACK leave.
#[derive(Clone, Debug)]
pub(crate) struct PreparedAcknowledgement {
    request: Vec<u8>,
}

impl PreparedAcknowledgement {
    pub(crate) fn for_fetched(
        device: &DeviceAddr,
        first_sequence: u64,
        count: usize,
    ) -> Option<Self> {
        if count == 0 {
            return None;
        }
        let count = u64::try_from(count).ok()?;
        let up_to = first_sequence.checked_add(count)?;
        Some(Self {
            request: encode_request(&Request::Ack {
                device: device.clone(),
                up_to,
            }),
        })
    }

    pub(crate) fn request(&self) -> &[u8] {
        &self.request
    }
}

#[cfg(test)]
mod tests {
    use super::{PreparedAcknowledgement, PreparedSend};
    use tacenta_relay::{DeviceAddr, Request, encode_request};

    #[test]
    fn a_retry_keeps_the_exact_prepared_request() {
        let prepared = PreparedSend::new(vec![0, 1, 2, 0xff]);
        let retry = prepared.clone();
        assert_eq!(prepared.request(), retry.request());
    }

    #[test]
    fn acknowledgement_is_prepared_only_for_the_processed_delivery_prefix() {
        let device = DeviceAddr::new("+bob", 1);
        let acknowledgement = PreparedAcknowledgement::for_fetched(&device, 41, 3)
            .expect("a non-empty, in-range prefix has an acknowledgement");

        assert_eq!(
            acknowledgement.request(),
            encode_request(&Request::Ack { device, up_to: 44 })
        );
        assert!(
            PreparedAcknowledgement::for_fetched(&DeviceAddr::new("+bob", 1), 41, 0).is_none(),
            "an empty poll must not prepare an ACK"
        );
    }

    #[test]
    fn acknowledgement_refuses_an_overflowing_delivery_prefix() {
        assert!(
            PreparedAcknowledgement::for_fetched(&DeviceAddr::new("+bob", 1), u64::MAX, 1,)
                .is_none()
        );
    }
}
