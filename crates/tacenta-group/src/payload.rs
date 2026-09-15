//! The authenticated inner payload carried by a `group` relay envelope.

use crate::{ApplicationContext, Error, InvitationAcceptance, InvitationBootstrap, Roster};

const GROUP_PAYLOAD_DOMAIN: &[u8] = b"Tacenta Group Payload v1";
const APPLICATION_TAG: u8 = 1;
const ROSTER_TAG: u8 = 2;
const INVITATION_BOOTSTRAP_TAG: u8 = 3;
const INVITATION_ACCEPTANCE_TAG: u8 = 4;
const MAX_GROUP_PAYLOAD_LEN: usize = 8_192;

/// A bounded group relay payload. The outer relay envelope says this is group
/// traffic; this explicit inner variant selects the application or control
/// parser before either state machine is invoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupPayload {
    Application(ApplicationContext),
    Roster(Roster),
    InvitationBootstrap(InvitationBootstrap),
    InvitationAcceptance(InvitationAcceptance),
}

impl GroupPayload {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (tag, value) = match self {
            Self::Application(context) => (APPLICATION_TAG, context.encode()?),
            Self::Roster(roster) => (ROSTER_TAG, roster.encode()?),
            Self::InvitationBootstrap(bootstrap) => (INVITATION_BOOTSTRAP_TAG, bootstrap.encode()?),
            Self::InvitationAcceptance(acceptance) => {
                (INVITATION_ACCEPTANCE_TAG, acceptance.encode()?)
            }
        };
        let length = u32::try_from(value.len()).map_err(|_| Error::Malformed)?;
        let mut out = Vec::with_capacity(GROUP_PAYLOAD_DOMAIN.len() + 5 + value.len());
        out.extend_from_slice(GROUP_PAYLOAD_DOMAIN);
        out.push(tag);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&value);
        if out.len() > MAX_GROUP_PAYLOAD_LEN {
            return Err(Error::Malformed);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_GROUP_PAYLOAD_LEN || !bytes.starts_with(GROUP_PAYLOAD_DOMAIN) {
            return Err(Error::Malformed);
        }
        let mut cursor = &bytes[GROUP_PAYLOAD_DOMAIN.len()..];
        let (tag, rest) = cursor.split_first().ok_or(Error::Malformed)?;
        cursor = rest;
        let (length, value) = cursor.split_at_checked(4).ok_or(Error::Malformed)?;
        let length = usize::try_from(u32::from_be_bytes(
            length.try_into().map_err(|_| Error::Malformed)?,
        ))
        .map_err(|_| Error::Malformed)?;
        if value.len() != length {
            return Err(Error::Malformed);
        }
        match *tag {
            APPLICATION_TAG => Ok(Self::Application(ApplicationContext::decode(value)?)),
            ROSTER_TAG => Ok(Self::Roster(Roster::decode(value)?)),
            INVITATION_BOOTSTRAP_TAG => Ok(Self::InvitationBootstrap(InvitationBootstrap::decode(
                value,
            )?)),
            INVITATION_ACCEPTANCE_TAG => Ok(Self::InvitationAcceptance(
                InvitationAcceptance::decode(value)?,
            )),
            _ => Err(Error::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DIGEST_LEN, GroupId, InvitationAcceptance, InvitationId, Member, POLICY_VERSION_V1,
    };

    fn alice() -> Member {
        Member::new(b"alice".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob".to_vec(), vec![1])
    }

    fn roster() -> Roster {
        Roster::new(
            GroupId::new(*b"bounded-group-id"),
            1,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap()
    }

    #[test]
    fn application_and_control_payloads_have_distinct_canonical_tags() {
        let application = GroupPayload::Application(
            ApplicationContext::new(
                GroupId::new(*b"bounded-group-id"),
                1,
                [7; DIGEST_LEN],
                alice(),
                bob(),
                2,
                b"hello".to_vec(),
            )
            .unwrap(),
        );
        let control = GroupPayload::Roster(roster());
        let application_bytes = application.encode().unwrap();
        let control_bytes = control.encode().unwrap();
        assert_ne!(application_bytes, control_bytes);
        assert_eq!(GroupPayload::decode(&application_bytes), Ok(application));
        assert_eq!(GroupPayload::decode(&control_bytes), Ok(control));

        let acceptance = GroupPayload::InvitationAcceptance(
            InvitationAcceptance::new(
                GroupId::new(*b"bounded-group-id"),
                InvitationId::new([9; 16]),
                0,
                [7; DIGEST_LEN],
            )
            .unwrap(),
        );
        let acceptance_bytes = acceptance.encode().unwrap();
        assert_ne!(acceptance_bytes, control_bytes);
        assert_eq!(GroupPayload::decode(&acceptance_bytes), Ok(acceptance));
    }

    #[test]
    fn payload_decoder_refuses_unknown_type_and_trailing_bytes() {
        let mut unknown = GroupPayload::Roster(roster()).encode().unwrap();
        unknown[GROUP_PAYLOAD_DOMAIN.len()] = 99;
        assert_eq!(GroupPayload::decode(&unknown), Err(Error::Malformed));

        let mut trailing = GroupPayload::Roster(roster()).encode().unwrap();
        trailing.push(0);
        assert_eq!(GroupPayload::decode(&trailing), Err(Error::Malformed));
    }
}
