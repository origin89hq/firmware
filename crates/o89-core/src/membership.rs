//! Who is enrolled, changed from a session: `Invite 0x15`, `Approve 0x16`
//! and `Remove 0x17`, each a signed write that opened (P-080's first step).
//!
//! **Each rule's steps run in the rule's order**, and a refusal is the first
//! step that fails; nothing is drawn, spent, stored or freed before every
//! check ahead of it has passed. The sessions seal what these answer.
//!
//! **An approval is two halves.** Its proof is an HMAC under P-238's
//! admission key, which is a Diffie–Hellman with the controller key, and
//! that key is the worker's (P-243). So [`approve`] takes P-255's steps up
//! to the proof and hands back what the worker has to verify, and
//! [`approved`] takes the rest once it has: the invite is looked up again,
//! and its inviter checked again, because either can have gone while the
//! worker ran.
//!
//! **A sender is a slot's current enrolment.** A session whose slot was
//! re-keyed or freed since it bound is refused as unauthorised: it speaks
//! for an enrolment that is gone (P-239).
//!
//! cites: P-251, P-252, P-254, P-255, P-256, P-257

use km43::{
    ApproveAck, ApproveOperation, ClientCapability, ClientId, Commitment, Decision, Enrolled,
    ErrorCode, Generation, Invitation, InviteAck, InviteError, InviteNonce, InviteOperation,
    PublicKey, RemoveOperation, Reveal, Role, Verified,
};

use crate::clients::{ClientLabel, Clients, Enrolment, Occupant};
use crate::fram::Fram;
use crate::invites::Pending;
use crate::session::{Keys, SessionNote};
use crate::tick::Tick;

/// A proof's and a confirmation's bytes (P-257).
const TAG: usize = 16;

/// The enrolment a session speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sender {
    pub(crate) client: ClientId,
    pub(crate) generation: Generation,
}

/// What to answer, and what to tell the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an answer nobody seals is a client waiting on a timeout"]
pub(crate) struct Answer<T> {
    /// The ack, or a sealed error.
    pub(crate) reply: Result<T, ErrorCode>,
    pub(crate) note: Option<SessionNote>,
}

impl<T> Answer<T> {
    pub(crate) const fn ack(ack: T) -> Self {
        Self {
            reply: Ok(ack),
            note: None,
        }
    }

    const fn error(code: ErrorCode, note: Option<SessionNote>) -> Self {
        Self {
            reply: Err(code),
            note,
        }
    }

    const fn with(mut self, note: SessionNote) -> Self {
        self.note = Some(note);
        self
    }
}

/// The capability a role's proposal needs (P-251): bit 6 `invite` to
/// propose an admin, bit 7 `approve` for an owner or a viewer.
const fn proposing(role: Role) -> ClientCapability {
    match role {
        Role::Admin => ClientCapability::INVITE,
        Role::Owner | Role::Viewer => ClientCapability::APPROVE,
    }
}

/// Whether an enrolment's mask holds every bit of `required` (P-251).
const fn may(occupant: &Occupant, required: ClientCapability) -> bool {
    occupant.mask().0 & required.0 == required.0
}

/// Whether an enrolment's mask lets it propose `role`.
const fn may_propose(occupant: &Occupant, role: Role) -> bool {
    may(occupant, proposing(role))
}

/// Whether any occupied slot holds `key` (P-252 step 2, P-255 step 6).
fn holds(clients: &Clients, epoch: km43::Epoch, key: &PublicKey) -> bool {
    clients
        .occupied(epoch)
        .any(|(_, occupant)| occupant.client() == *key)
}

/// The sender's current enrolment, or `None` for one that is gone.
fn current(keys: &Keys, sender: Sender) -> Option<(km43::Epoch, &Occupant)> {
    let epoch = keys.epoch?;
    keys.clients
        .occupant(sender.client, epoch)
        .filter(|occupant| occupant.generation() == sender.generation)
        .map(|occupant| (epoch, occupant))
}

/// Whether the slot that proposed `pending` still holds the enrolment that
/// did, with a role that may still propose it (P-255 step 4).
fn inviter_holds(keys: &Keys, pending: &Pending) -> bool {
    let Some(epoch) = keys.epoch else {
        return false;
    };
    keys.clients
        .occupant(pending.inviter, epoch)
        .is_some_and(|occupant| {
            occupant.generation() == pending.inviter_generation
                && may_propose(occupant, pending.role)
        })
}

fn refused(outcome: km43::Invite) -> Answer<InviteAck> {
    match InviteAck::refused(outcome) {
        Ok(ack) => Answer::ack(ack),
        Err(_) => Answer::error(ErrorCode::MalformedFrame, None),
    }
}

/// `Invite 0x15`, in P-252's order. The spend is on the part before the
/// invite is stored (P-254), and the invite is stored before it is
/// answered.
pub(crate) async fn propose<F: Fram>(
    keys: &mut Keys,
    sender: Sender,
    operation: &InviteOperation<'_>,
    now: Tick,
    fram: &mut F,
) -> Answer<InviteAck> {
    let Some((epoch, occupant)) = current(keys, sender) else {
        return refused(km43::Invite::Unauthorised);
    };
    let (role, suite) = (occupant.role(), occupant.suite());
    // Step 1.
    if !may_propose(occupant, operation.role) {
        return refused(km43::Invite::Unauthorised);
    }
    // Step 2.
    if holds(&keys.clients, epoch, &operation.invitee) {
        return refused(km43::Invite::KnownKey);
    }
    // Step 3: only an admin has a budget.
    let spends = match role {
        Role::Admin => true,
        Role::Owner | Role::Viewer => false,
    };
    if spends && keys.budgets.left(sender.client, epoch, sender.generation) == 0 {
        return refused(km43::Invite::NoBudget);
    }
    // Step 4.
    if keys.clients.free_for(operation.role, epoch).is_none() {
        return refused(km43::Invite::TableFull);
    }
    // Step 5, after the rows past their hour have gone.
    let _expired = keys.invites.expire(now);
    if keys.invites.room(sender.client, role).is_err() {
        return refused(km43::Invite::InvitesFull);
    }
    let Ok(label) = ClientLabel::new(operation.label) else {
        return Answer::error(ErrorCode::MalformedFrame, None);
    };
    let Ok(drawn) = keys.generator.challenge(fram).await else {
        return Answer::error(ErrorCode::BusyRetry, Some(SessionNote::EntropyUnavailable));
    };
    let nonce = InviteNonce(drawn);
    if spends {
        match keys
            .budgets
            .spend(sender.client, epoch, sender.generation, fram)
            .await
        {
            Ok(_) => {}
            Err(crate::Unspent::Exhausted) => return refused(km43::Invite::NoBudget),
            Err(crate::Unspent::NoSuchSlot | crate::Unspent::Write(_)) => {
                return Answer::error(ErrorCode::BusyRetry, Some(SessionNote::MembershipNotStored));
            }
        }
    }
    let pending = Pending {
        nonce,
        role: operation.role,
        invitee: operation.invitee,
        commitment: operation.commitment,
        inviter: sender.client,
        inviter_generation: sender.generation,
        kind: operation.client_kind,
        label,
        suite,
        proposed: now,
    };
    if keys.invites.propose(pending, role).is_err() {
        // `room` said yes above and nothing ran between.
        return refused(km43::Invite::InvitesFull);
    }
    Answer::ack(InviteAck::proposed(nonce)).with(SessionNote::Proposed(sender.client))
}

/// What the worker verifies for an approval: P-257's check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Check {
    pub(crate) invitation: Invitation,
    pub(crate) commitment: Commitment,
    pub(crate) proof: [u8; TAG],
}

/// Where an `Approve` stands after its first half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a check nobody queues is an approval nobody answers"]
pub(crate) enum Approval {
    /// Answered without the worker: a refusal, or a decline.
    Answered(Answer<ApproveAck>),
    /// Steps 1 to 4 passed; step 5 is the worker's.
    Verify(Check),
}

fn decided(outcome: km43::Approve) -> Answer<ApproveAck> {
    match ApproveAck::other(outcome) {
        Ok(ack) => Answer::ack(ack),
        Err(_) => Answer::error(ErrorCode::MalformedFrame, None),
    }
}

/// `Approve 0x16`, P-255's steps 1 to 4, and the check for step 5.
pub(crate) fn approve(
    keys: &mut Keys,
    sender: Sender,
    operation: &ApproveOperation,
    now: Tick,
) -> Approval {
    // Step 1.
    let Some(pending) = keys.invites.find(&operation.nonce, now).cloned() else {
        return Approval::Answered(decided(km43::Approve::UnknownInvite));
    };
    // Step 2: an owner decides; the inviter may withdraw its own.
    let owner = current(keys, sender).is_some_and(|(_, occupant)| match occupant.role() {
        Role::Owner => true,
        Role::Admin | Role::Viewer => false,
    });
    let inviter =
        pending.inviter == sender.client && pending.inviter_generation == sender.generation;
    let reveal_proof = match operation.decision {
        Decision::Decline if owner || inviter => {
            // Step 3.
            let _withdrawn = keys.invites.withdraw(&operation.nonce);
            return Approval::Answered(decided(km43::Approve::Declined));
        }
        Decision::Approve { reveal, proof } if owner => (reveal, proof),
        Decision::Decline | Decision::Approve { .. } => {
            return Approval::Answered(decided(km43::Approve::Unauthorised));
        }
    };
    // Step 4.
    if !inviter_holds(keys, &pending) {
        let _withdrawn = keys.invites.withdraw(&operation.nonce);
        return Approval::Answered(decided(km43::Approve::InviterGone));
    }
    let (Some(epoch), Some(secret), Some(controller)) = (keys.epoch, keys.secret, keys.controller)
    else {
        // A unit with no epoch, secret or controller key binds no session,
        // so no approval reaches here from one.
        return Approval::Answered(Answer::error(ErrorCode::BusyRetry, None));
    };
    let (reveal, proof): (Reveal, [u8; TAG]) = reveal_proof;
    Approval::Verify(Check {
        invitation: Invitation {
            device_id: secret.device_id(),
            controller,
            epoch,
            suite: pending.suite,
            role: pending.role,
            inviter: pending.inviter,
            inviter_generation: pending.inviter_generation,
            invitee: pending.invitee,
            nonce: pending.nonce,
            reveal,
        },
        commitment: pending.commitment,
        proof,
    })
}

/// `Approve 0x16`, P-255's steps 5 to 8 once the worker has checked the
/// proof. The invite is looked up and its inviter checked again: the worker
/// took a second, and a removal, a reset or the deadline may have come in
/// it. `unbind` ends every session on the slot before it is written
/// (P-240).
pub(crate) async fn approved<F: Fram>(
    keys: &mut Keys,
    sender: Sender,
    nonce: &InviteNonce,
    checked: Result<Verified, InviteError>,
    now: Tick,
    unbind: impl FnOnce(ClientId),
    fram: &mut F,
) -> Answer<ApproveAck> {
    let Some(pending) = keys.invites.find(nonce, now).cloned() else {
        return decided(km43::Approve::UnknownInvite);
    };
    let still_owner = current(keys, sender).is_some_and(|(_, occupant)| match occupant.role() {
        Role::Owner => true,
        Role::Admin | Role::Viewer => false,
    });
    if !still_owner {
        return decided(km43::Approve::Unauthorised);
    }
    if !inviter_holds(keys, &pending) {
        let _withdrawn = keys.invites.withdraw(nonce);
        return decided(km43::Approve::InviterGone);
    }
    let Some(epoch) = keys.epoch else {
        return decided(km43::Approve::Unauthorised);
    };
    // Step 5.
    let Ok(verified) = checked else {
        let _withdrawn = keys.invites.withdraw(nonce);
        return decided(km43::Approve::Refused);
    };
    // Step 6.
    if holds(&keys.clients, epoch, &pending.invitee) {
        let _withdrawn = keys.invites.withdraw(nonce);
        return decided(km43::Approve::KnownKey);
    }
    // Step 7: the lowest free slot, never one reclaimed by label.
    let Some(id) = keys.clients.free_for(pending.role, epoch) else {
        return decided(km43::Approve::TableFull);
    };
    // Step 8.
    unbind(id);
    let enrolment = Enrolment {
        client: pending.invitee,
        admit: *verified.admit_key().to_stored(),
        suite: pending.suite,
        role: pending.role,
        kind: pending.kind,
        label: pending.label,
    };
    let Ok(generation) = keys.clients.enrol(id, enrolment, epoch, fram).await else {
        return decided(km43::Approve::NotStored).with(SessionNote::MembershipNotStored);
    };
    let _withdrawn = keys.invites.withdraw(nonce);
    let budget_restored = keys
        .budgets
        .restore(pending.inviter, epoch, pending.inviter_generation, fram)
        .await
        .is_ok();
    let confirm = *verified.confirm(id, generation).as_bytes();
    Answer::ack(ApproveAck::enrolled(Enrolled {
        client_id: id,
        generation,
        confirm,
    }))
    .with(SessionNote::Approved {
        client: id,
        budget_restored,
    })
}

/// A removal that passed P-256's steps 1 to 3: the slot to free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a removal decided and not carried out removes nobody"]
pub(crate) enum Removal {
    /// Refused, nothing changed.
    Refused(km43::Remove),
    /// Free this slot: step 4 next.
    Free(ClientId),
}

/// `Remove 0x17`, P-256's steps 1 to 3.
pub(crate) fn removal(keys: &Keys, sender: Sender, operation: RemoveOperation) -> Removal {
    // Step 1.
    let Some((epoch, occupant)) = current(keys, sender) else {
        return Removal::Refused(km43::Remove::Unauthorised);
    };
    if !may(occupant, ClientCapability::INVITE) {
        return Removal::Refused(km43::Remove::Unauthorised);
    }
    let owner = match occupant.role() {
        Role::Owner => true,
        Role::Admin | Role::Viewer => false,
    };
    // Step 2.
    let Some(target) = keys
        .clients
        .occupant(operation.client_id, epoch)
        .filter(|target| target.generation() == operation.generation)
    else {
        return Removal::Refused(km43::Remove::Gone);
    };
    // Step 3.
    match target.role() {
        Role::Owner => Removal::Refused(km43::Remove::Protected),
        Role::Viewer if !owner => Removal::Refused(km43::Remove::Protected),
        Role::Viewer | Role::Admin => Removal::Free(operation.client_id),
    }
}

/// P-256's step 4 and its answer, once the caller has unbound every other
/// session on the slot: the slot's invites withdrawn, then the slot freed,
/// which moves its generation and with it the budget (P-254) on.
pub(crate) async fn remove<F: Fram>(
    keys: &mut Keys,
    id: ClientId,
    fram: &mut F,
) -> (km43::Remove, Option<SessionNote>) {
    let _withdrawn = keys.invites.withdraw_inviter(id);
    let Some(epoch) = keys.epoch else {
        return (km43::Remove::Gone, None);
    };
    match keys.clients.remove(id, epoch, fram).await {
        Ok(_) => (km43::Remove::Removed, Some(SessionNote::Removed(id))),
        Err(_) => (
            km43::Remove::NotStored,
            Some(SessionNote::MembershipNotStored),
        ),
    }
}
