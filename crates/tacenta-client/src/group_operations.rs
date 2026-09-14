//! The client-side bridge between bounded group policy and the core helper.
//!
//! It does not perform pairwise encryption or transport. Its caller supplies
//! the ciphertext produced for the canonical application context, and this
//! module records the standalone core's commitment of that exact context with
//! the immutable recipient record before the durable coordinator can hand it
//! off.

use tacenta_core::crypto::groups::payload_commitment;
use tacenta_group::{Error as GroupError, LogicalSend, Member, RecipientProgress};

pub(crate) fn bind_prepared_ciphertext(
    logical_send: &mut LogicalSend,
    recipient: &Member,
    ciphertext: Vec<u8>,
) -> Result<RecipientProgress, GroupError> {
    let context = logical_send.application_context(recipient)?.encode()?;
    let commitment = payload_commitment(&context);
    logical_send
        .record_prepared(recipient, commitment, ciphertext)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::bind_prepared_ciphertext;
    use tacenta_group::{DIGEST_LEN, GroupId, LogicalSend, Member, POLICY_VERSION_V1, Roster};

    fn alice() -> Member {
        Member::new(b"alice-key".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob-key".to_vec(), vec![1])
    }

    fn logical_send() -> LogicalSend {
        let group_id = GroupId::new(*b"bounded-group-id");
        let roster = Roster::new(
            group_id,
            1,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap();
        LogicalSend::new(
            &roster,
            [5; DIGEST_LEN],
            alice(),
            7,
            vec![bob()],
            b"hello".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn prepared_ciphertext_carries_the_cores_exact_context_commitment() {
        let mut send = logical_send();
        let progress = bind_prepared_ciphertext(&mut send, &bob(), vec![1, 2, 3]).unwrap();
        let context = send.application_context(&bob()).unwrap().encode().unwrap();
        assert_eq!(
            progress.context_commitment,
            Some(tacenta_core::crypto::groups::payload_commitment(&context))
        );
        assert_eq!(progress.ciphertext, Some(vec![1, 2, 3]));
    }
}
