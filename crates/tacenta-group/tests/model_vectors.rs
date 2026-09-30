//! Replays the traces the Lean model `spec/Tacenta/Group.lean` generated
//! (`contracts/vectors/group-v1.json`, decision 0137) against the Rust
//! `tacenta-group` types. For every step the model says whether the operation
//! is accepted and what the group holds afterwards (revision, roster,
//! invitations); the Rust types must agree, including the revision numbers.
//!
//! The book has no roster, so the driver below does what the client's
//! coordinator does around it: build the successor roster, let the roster view
//! accept it, and only then admit the invitation, all on candidates that are
//! kept only if every part accepts. A closure is a successor with the same
//! members and the closed flag set.

use serde_json::Value;
use tacenta_group::*;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/vectors/group-v1.json"
));

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn member(value: &Value) -> Member {
    let byte = |field: &str| u8::try_from(value[field].as_u64().expect(field)).expect("range");
    Member::new(vec![byte("identity")], vec![byte("device")])
}

fn number(value: &Value, field: &str) -> u64 {
    value[field].as_u64().unwrap_or_else(|| panic!("{field}"))
}

/// A stand-in commitment: one distinct value per revision.
fn digest_for(revision: u64) -> [u8; DIGEST_LEN] {
    [u8::try_from(revision).expect("small revision") + 1; DIGEST_LEN]
}

fn sorted(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by(|left, right| {
        left.identity()
            .cmp(right.identity())
            .then_with(|| left.device().cmp(right.device()))
    });
    members
}

struct World {
    authority: Member,
    view: RosterView,
    book: InvitationBook,
}

impl World {
    fn new(authority: Member) -> Self {
        let genesis = Roster::new(
            group(),
            0,
            [0; DIGEST_LEN],
            authority.clone(),
            POLICY_VERSION_V1,
            false,
            vec![authority.clone()],
        )
        .unwrap();
        Self {
            view: RosterView::accept_genesis(&authority, genesis, digest_for(0)).unwrap(),
            book: InvitationBook::new(group()),
            authority,
        }
    }

    fn revision(&self) -> u64 {
        self.view.roster().revision
    }

    fn successor(&self, members: Vec<Member>) -> Result<Roster, Error> {
        self.successor_with(members, false)
    }

    fn successor_with(&self, members: Vec<Member>, closed: bool) -> Result<Roster, Error> {
        Roster::new(
            group(),
            self.revision() + 1,
            *self.view.digest(),
            self.authority.clone(),
            POLICY_VERSION_V1,
            closed,
            sorted(members),
        )
    }

    /// Applies one step and reports whether every part accepted it.
    fn apply(&mut self, step: &Value) -> bool {
        let actor = member(&step["actor"]);
        match step["op"].as_str().expect("op") {
            "invite" => {
                // The book does not look at the roster; the coordinator refuses
                // an invitation in a closed group (decision 0141), as the model
                // does.
                if self.view.roster().closed {
                    return false;
                }
                let invitation = Invitation::new(
                    InvitationId::new([number(step, "id") as u8; 16]),
                    group(),
                    member(&step["target"]),
                    self.revision(),
                    *self.view.digest(),
                    POLICY_VERSION_V1,
                    number(step, "expires_at"),
                )
                .unwrap();
                let mut book = self.book.clone();
                let accepted = book
                    .create(
                        &actor,
                        &self.authority,
                        &self.view.roster().members,
                        invitation,
                        number(step, "now"),
                    )
                    .is_ok();
                if accepted {
                    self.book = book;
                }
                accepted
            }
            "accept" => {
                let observed = number(step, "observed_revision");
                let mut book = self.book.clone();
                let accepted = book
                    .accept(
                        InvitationId::new([number(step, "id") as u8; 16]),
                        &actor,
                        observed,
                        &digest_for(observed),
                        number(step, "now"),
                    )
                    .is_ok();
                if accepted {
                    self.book = book;
                }
                accepted
            }
            "admit" => {
                let id = InvitationId::new([number(step, "id") as u8; 16]);
                let Some(target) = self
                    .book
                    .records()
                    .iter()
                    .find(|record| record.id == id)
                    .map(|record| record.target.clone())
                else {
                    return false;
                };
                let mut members = self.view.roster().members.clone();
                members.push(target);
                let Ok(successor) = self.successor(members) else {
                    return false;
                };
                let revision = successor.revision;
                let mut view = self.view.clone();
                if view.accept_successor(&actor, successor, digest_for(revision))
                    != RosterDisposition::Accepted
                {
                    return false;
                }
                let mut book = self.book.clone();
                if book
                    .admit(id, &actor, &self.authority, revision, number(step, "now"))
                    .is_err()
                {
                    return false;
                }
                self.view = view;
                self.book = book;
                true
            }
            "revoke" => {
                let mut book = self.book.clone();
                let accepted = book
                    .revoke(
                        InvitationId::new([number(step, "id") as u8; 16]),
                        &actor,
                        &self.authority,
                        0,
                    )
                    .is_ok();
                if accepted {
                    self.book = book;
                }
                accepted
            }
            "remove" => {
                let target = member(&step["target"]);
                let members: Vec<Member> = self
                    .view
                    .roster()
                    .members
                    .iter()
                    .filter(|known| **known != target)
                    .cloned()
                    .collect();
                let Ok(successor) = self.successor(members) else {
                    return false;
                };
                let revision = successor.revision;
                self.view
                    .accept_successor(&actor, successor, digest_for(revision))
                    == RosterDisposition::Accepted
            }
            "close" => {
                let Ok(successor) = self.successor_with(self.view.roster().members.clone(), true)
                else {
                    return false;
                };
                let revision = successor.revision;
                self.view
                    .accept_successor(&actor, successor, digest_for(revision))
                    == RosterDisposition::Accepted
            }
            other => panic!("unknown op in vectors: {other}"),
        }
    }

    fn assert_matches(&self, expected: &Value, context: &str) {
        assert_eq!(
            self.revision(),
            number(expected, "revision"),
            "{context}: revision"
        );
        let roster: Vec<Member> = expected["roster"]
            .as_array()
            .expect("roster")
            .iter()
            .map(member)
            .collect();
        assert_eq!(
            self.view.roster().members,
            sorted(roster),
            "{context}: roster"
        );
        let invitations = expected["invitations"].as_array().expect("invitations");
        assert_eq!(
            self.book.records().len(),
            invitations.len(),
            "{context}: invitation count"
        );
        for expected in invitations {
            let id = InvitationId::new([number(expected, "id") as u8; 16]);
            let record = self
                .book
                .records()
                .iter()
                .find(|record| record.id == id)
                .unwrap_or_else(|| panic!("{context}: invitation {id:?} missing"));
            assert_eq!(record.target, member(&expected["target"]), "{context}");
            assert_eq!(
                record.source_revision,
                number(expected, "source_revision"),
                "{context}: source revision"
            );
            let status = &expected["status"];
            let want = match status["state"].as_str().expect("state") {
                "pending" => InvitationStatus::Pending,
                "accepted_pending_admission" => InvitationStatus::AcceptedPendingAdmission,
                "admitted" => InvitationStatus::Admitted {
                    revision: number(status, "revision"),
                },
                "revoked" => InvitationStatus::Revoked,
                other => panic!("unknown status in vectors: {other}"),
            };
            assert_eq!(record.status, want, "{context}: invitation status");
        }
    }
}

#[test]
fn the_rust_group_types_replay_the_lean_model_traces() {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors: invalid JSON");
    assert_eq!(doc["format"], "group-v1");
    assert_eq!(number(&doc, "max_members"), 8);
    let traces = doc["traces"].as_array().expect("traces");
    assert_eq!(traces.len(), 10, "the committed vector set changed shape");

    let mut steps_replayed = 0;
    let mut refusals_replayed = 0;
    for trace in traces {
        let name = trace["name"].as_str().expect("name");
        let mut world = World::new(member(&trace["authority"]));
        for (index, step) in trace["steps"].as_array().expect("steps").iter().enumerate() {
            let context = format!("{name} step {index} ({})", step["op"].as_str().unwrap());
            let expected = step["accepted"].as_bool().expect("accepted");
            assert_eq!(world.apply(step), expected, "{context}: accepted");
            world.assert_matches(&step["state"], &context);
            steps_replayed += 1;
            refusals_replayed += usize::from(!expected);
        }
    }
    // The vectors must exercise both outcomes, or the comparison proves little.
    assert_eq!(steps_replayed, 104);
    assert_eq!(refusals_replayed, 31);
}

#[test]
fn the_model_numbering_is_the_code_numbering() {
    // The point of decision 0137, restated without the vector file: invite at
    // revision 0, admit at revision 1, and a second invitee admitted at 2.
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors: invalid JSON");
    let trace = doc["traces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|trace| trace["name"] == "admission-numbering")
        .expect("admission-numbering");
    let revisions: Vec<u64> = trace["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| number(&step["state"], "revision"))
        .collect();
    assert_eq!(revisions, vec![0, 0, 0, 1, 1, 1, 2]);
}
