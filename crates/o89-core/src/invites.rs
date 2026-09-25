//! The pending invites, as P-253 keeps them: `MAX_INVITES` rows in RAM.
//!
//! **Full is a refusal, never an eviction** (P-003). A slot holds at most
//! `MAX_INVITES_PER_INVITER` rows, and the last free row is an owner's, so
//! two admins proposing twice each cannot shut out the one person who can
//! approve anything.
//!
//! **Nothing here survives a reboot**, by design: an invite that does not
//! outlive the next power cut cannot outlive the person who proposed it by
//! more than that. A factory reset and a freed or re-keyed inviter slot
//! withdraw rows too, and every row is withdrawn `INVITE_TTL` after it was
//! proposed, on the monotonic tick (P-004); a tick that reads earlier than a
//! row's proposal gives it no age to trust, and withdraws it.
//!
//! Rows are kept oldest first and without gaps, the order `Clients 0x98`
//! lists them in (P-251). Nothing here checks roles, keys or the client
//! table: the session takes P-252's and P-255's steps in their order and
//! asks this table only the questions that are its own.
//!
//! cites: P-252, P-253

use km43::{
    ClientId, ClientKind, Commitment, Generation, INVITE_TTL_MS, InviteNonce, InviteRow,
    MAX_INVITES, MAX_INVITES_PER_INVITER, PublicKey, Role, Suite,
};

use crate::clients::ClientLabel;
use crate::tick::{Millis, Tick};

/// How long a row stays pending after it was proposed (P-253).
pub const INVITE_TTL: Millis = Millis::from_millis(INVITE_TTL_MS);

/// One pending invite: what P-257's transcript and P-255's write need,
/// and the tick it was proposed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// `N_c`, the invite's name.
    pub nonce: InviteNonce,
    /// The role the invitee would enrol with.
    pub role: Role,
    /// `IS`, the key the invite is for.
    pub invitee: PublicKey,
    /// What the invitee committed to at proposal (P-257).
    pub commitment: Commitment,
    /// The slot that proposed it.
    pub inviter: ClientId,
    /// That slot's generation when it proposed.
    pub inviter_generation: Generation,
    /// What the invitee will say it is; shown, decides nothing (P-105).
    pub kind: ClientKind,
    /// What a person sees in the list.
    pub label: ClientLabel,
    /// The suite the slot will pin: the inviter's.
    pub suite: Suite,
    /// The tick it was proposed at, which its deadline counts from.
    pub proposed: Tick,
}

impl Pending {
    /// Whether P-253's deadline has passed at `now`, or the tick gives the
    /// row no age to trust.
    #[must_use]
    pub fn expired(&self, now: Tick) -> bool {
        now.since(self.proposed)
            .is_none_or(|age| age.as_millis() >= INVITE_TTL.as_millis())
    }

    /// Whole seconds left before the deadline at `now`, rounded up so a
    /// live row never reads zero, and at most an hour.
    #[must_use]
    pub fn expires_in(&self, now: Tick) -> u32 {
        let left = now.since(self.proposed).map_or(0, |age| {
            INVITE_TTL.as_millis().saturating_sub(age.as_millis())
        });
        u32::try_from(left.div_ceil(1000)).unwrap_or(u32::MAX)
    }

    /// The row `Clients 0x98` lists for this invite at `now`.
    #[must_use]
    pub fn row(&self, now: Tick) -> InviteRow<'_> {
        InviteRow {
            nonce: self.nonce,
            role: self.role,
            invitee: self.invitee,
            inviter: self.inviter,
            inviter_generation: self.inviter_generation,
            client_kind: self.kind,
            label: self.label.as_str(),
            expires_in: self.expires_in(now),
            suite: self.suite,
        }
    }
}

/// Why the table has no row for a proposal: `Invite` outcome 3
/// `invites_full` (P-253). Nothing was evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a refusal nobody answers leaves the proposer waiting"]
pub enum InvitesFull {
    /// Every row holds a pending invite.
    Table,
    /// The last free row is held for an owner, and the proposer is not one.
    OwnersRow,
    /// This slot already holds `MAX_INVITES_PER_INVITER` pending invites.
    Inviter,
}

/// The pending-invite table.
#[derive(Debug, Default)]
pub struct Invites {
    /// Oldest first, the occupied rows before every `None`.
    rows: [Option<Pending>; MAX_INVITES],
}

impl Invites {
    /// An empty table: what every boot starts with (P-253).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rows: [const { None }; MAX_INVITES],
        }
    }

    /// The pending invites, oldest first.
    pub fn pending(&self) -> impl Iterator<Item = &Pending> {
        self.rows.iter().map_while(Option::as_ref)
    }

    /// How many invites are pending.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending().count()
    }

    /// Whether no invite is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending().next().is_none()
    }

    /// Whether slot `inviter`, holding `role`, may take a row now (P-253),
    /// asked before a proposal draws its nonce or spends its budget.
    ///
    /// # Errors
    ///
    /// [`InvitesFull`] naming which of P-253's limits refused it.
    pub fn room(&self, inviter: ClientId, role: Role) -> Result<(), InvitesFull> {
        let held = self.pending().filter(|row| row.inviter == inviter).count();
        if held >= MAX_INVITES_PER_INVITER {
            return Err(InvitesFull::Inviter);
        }
        match MAX_INVITES.saturating_sub(self.len()) {
            0 => Err(InvitesFull::Table),
            1 => match role {
                Role::Owner => Ok(()),
                Role::Admin | Role::Viewer => Err(InvitesFull::OwnersRow),
            },
            _ => Ok(()),
        }
    }

    /// Store `pending`, proposed by a slot holding `role`, as the newest row.
    ///
    /// # Errors
    ///
    /// [`InvitesFull`] as [`Invites::room`] answers it; nothing is stored.
    pub fn propose(&mut self, pending: Pending, role: Role) -> Result<(), InvitesFull> {
        self.room(pending.inviter, role)?;
        let free = self
            .rows
            .iter_mut()
            .find(|row| row.is_none())
            .ok_or(InvitesFull::Table)?;
        *free = Some(pending);
        Ok(())
    }

    /// The live invite named `nonce` at `now`, after every row past its
    /// deadline has been withdrawn.
    pub fn find(&mut self, nonce: &InviteNonce, now: Tick) -> Option<&Pending> {
        self.expire(now);
        self.pending().find(|row| row.nonce == *nonce)
    }

    /// Withdraw the invite named `nonce`, handing it back.
    pub fn withdraw(&mut self, nonce: &InviteNonce) -> Option<Pending> {
        let at = self
            .rows
            .iter()
            .position(|row| row.as_ref().is_some_and(|row| row.nonce == *nonce))?;
        self.remove(at)
    }

    /// Withdraw every invite slot `inviter` proposed, when the slot is freed
    /// or re-keyed (P-253). Answers how many went.
    pub fn withdraw_inviter(&mut self, inviter: ClientId) -> usize {
        self.retain(|row| row.inviter != inviter)
    }

    /// Withdraw every invite past its deadline at `now`. Answers how many
    /// went.
    pub fn expire(&mut self, now: Tick) -> usize {
        self.retain(|row| !row.expired(now))
    }

    /// Withdraw every invite: a factory reset (P-085, P-253).
    pub fn clear(&mut self) {
        self.rows = [const { None }; MAX_INVITES];
    }

    /// Keep the rows `keep` accepts, in their order. Bounded by
    /// `MAX_INVITES` passes.
    fn retain(&mut self, keep: impl Fn(&Pending) -> bool) -> usize {
        let mut gone: usize = 0;
        let mut at = 0;
        while let Some(Some(row)) = self.rows.get(at) {
            if keep(row) {
                at = at.saturating_add(1);
            } else {
                // `remove` shifts the next row into `at`.
                let _withdrawn = self.remove(at);
                gone = gone.saturating_add(1);
            }
        }
        gone
    }

    /// Take row `at` out and close the gap, so the rows stay oldest first
    /// and contiguous.
    fn remove(&mut self, at: usize) -> Option<Pending> {
        let tail = self.rows.get_mut(at..)?;
        let taken = tail.first_mut()?.take();
        tail.rotate_left(1);
        taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> ClientId {
        ClientId::new(n).expect("a slot number")
    }

    fn pending(n: u8, inviter: u32, proposed: u64) -> Pending {
        Pending {
            nonce: InviteNonce([n; 16]),
            role: Role::Admin,
            invitee: PublicKey::from_bytes([n; 32]),
            commitment: Commitment([n; 32]),
            inviter: id(inviter),
            inviter_generation: Generation::new(1).expect("a generation"),
            kind: ClientKind::try_from(1).expect("a kind"),
            label: ClientLabel::new("cabin").expect("a label"),
            suite: Suite::try_from(1).expect("a suite"),
            proposed: Tick::from_millis(proposed),
        }
    }

    fn nonces(invites: &Invites) -> [Option<u8>; MAX_INVITES] {
        let mut out = [None; MAX_INVITES];
        for (slot, row) in out.iter_mut().zip(invites.pending()) {
            *slot = row.nonce.0.first().copied();
        }
        out
    }

    #[test]
    fn p_253_an_admin_takes_every_row_but_the_owners() {
        let mut invites = Invites::new();
        invites
            .propose(pending(1, 1, 0), Role::Admin)
            .expect("row 1");
        invites
            .propose(pending(2, 2, 0), Role::Admin)
            .expect("row 2");
        invites
            .propose(pending(3, 2, 0), Role::Admin)
            .expect("row 3");
        assert_eq!(
            invites.propose(pending(4, 1, 0), Role::Admin),
            Err(InvitesFull::OwnersRow)
        );
        assert_eq!(invites.len(), 3);
    }

    #[test]
    fn p_253_an_owner_takes_the_last_row_and_then_the_table_refuses_everyone() {
        let mut invites = Invites::new();
        for n in 1..=3 {
            invites
                .propose(pending(n, u32::from(n), 0), Role::Admin)
                .expect("an admin row");
        }
        invites
            .propose(pending(4, 4, 0), Role::Owner)
            .expect("the owner's row");
        assert_eq!(
            invites.propose(pending(5, 5, 0), Role::Owner),
            Err(InvitesFull::Table)
        );
        assert_eq!(nonces(&invites), [Some(1), Some(2), Some(3), Some(4)]);
    }

    #[test]
    fn p_253_a_slot_holds_at_most_two_rows_whatever_its_role() {
        let mut invites = Invites::new();
        invites
            .propose(pending(1, 1, 0), Role::Owner)
            .expect("first");
        invites
            .propose(pending(2, 1, 0), Role::Owner)
            .expect("second");
        assert_eq!(
            invites.propose(pending(3, 1, 0), Role::Owner),
            Err(InvitesFull::Inviter)
        );
        assert_eq!(invites.room(id(2), Role::Admin), Ok(()));
    }

    #[test]
    fn p_253_a_refusal_evicts_nothing() {
        let mut invites = Invites::new();
        for n in 1..=4 {
            invites
                .propose(pending(n, u32::from(n), 0), Role::Owner)
                .expect("a row");
        }
        let _ = invites.propose(pending(9, 5, 0), Role::Owner);
        assert_eq!(nonces(&invites), [Some(1), Some(2), Some(3), Some(4)]);
    }

    #[test]
    fn p_253_a_row_is_live_until_the_hour_and_withdrawn_at_it() {
        let mut invites = Invites::new();
        invites
            .propose(pending(1, 1, 1_000), Role::Admin)
            .expect("row");
        let nonce = InviteNonce([1; 16]);
        let last = Tick::from_millis(1_000 + INVITE_TTL_MS - 1);
        assert!(invites.find(&nonce, last).is_some());
        assert_eq!(
            invites.pending().next().map(|row| row.expires_in(last)),
            Some(1)
        );
        assert!(
            invites
                .find(&nonce, Tick::from_millis(1_000 + INVITE_TTL_MS))
                .is_none()
        );
        assert!(invites.is_empty());
    }

    #[test]
    fn p_253_a_tick_behind_the_proposal_withdraws_the_row() {
        let mut invites = Invites::new();
        invites
            .propose(pending(1, 1, 5_000), Role::Admin)
            .expect("row");
        assert!(
            invites
                .find(&InviteNonce([1; 16]), Tick::from_millis(4_999))
                .is_none()
        );
        assert!(invites.is_empty());
    }

    #[test]
    fn p_253_expires_in_counts_whole_seconds_from_the_hour_down() {
        let row = pending(1, 1, 0);
        assert_eq!(row.expires_in(Tick::from_millis(0)), 3_600);
        assert_eq!(row.expires_in(Tick::from_millis(1)), 3_600);
        assert_eq!(row.expires_in(Tick::from_millis(1_000)), 3_599);
        assert_eq!(row.expires_in(Tick::from_millis(INVITE_TTL_MS)), 0);
        assert_eq!(row.row(Tick::from_millis(0)).label, "cabin");
    }

    #[test]
    fn p_253_withdrawing_keeps_the_rest_oldest_first_and_frees_the_row() {
        let mut invites = Invites::new();
        for n in 1..=4 {
            invites
                .propose(pending(n, u32::from(n), 0), Role::Owner)
                .expect("a row");
        }
        let taken = invites.withdraw(&InviteNonce([2; 16])).expect("row 2");
        assert_eq!(taken.inviter, id(2));
        assert_eq!(nonces(&invites), [Some(1), Some(3), Some(4), None]);
        invites
            .propose(pending(5, 5, 0), Role::Owner)
            .expect("the freed row");
        assert_eq!(nonces(&invites), [Some(1), Some(3), Some(4), Some(5)]);
        assert!(invites.withdraw(&InviteNonce([2; 16])).is_none());
    }

    #[test]
    fn p_253_a_freed_inviter_takes_its_rows_with_it() {
        let mut invites = Invites::new();
        invites.propose(pending(1, 3, 0), Role::Admin).expect("a");
        invites.propose(pending(2, 1, 0), Role::Admin).expect("b");
        invites.propose(pending(3, 3, 0), Role::Admin).expect("c");
        assert_eq!(invites.withdraw_inviter(id(3)), 2);
        assert_eq!(nonces(&invites), [Some(2), None, None, None]);
        assert_eq!(invites.withdraw_inviter(id(3)), 0);
    }

    #[test]
    fn p_253_expiry_withdraws_only_the_rows_past_their_hour() {
        let mut invites = Invites::new();
        invites.propose(pending(1, 1, 0), Role::Admin).expect("old");
        invites
            .propose(pending(2, 2, 10_000), Role::Admin)
            .expect("young");
        invites.propose(pending(3, 3, 0), Role::Admin).expect("old");
        assert_eq!(invites.expire(Tick::from_millis(INVITE_TTL_MS)), 2);
        assert_eq!(nonces(&invites), [Some(2), None, None, None]);
    }

    #[test]
    fn p_253_a_factory_reset_withdraws_everything() {
        let mut invites = Invites::new();
        invites.propose(pending(1, 1, 0), Role::Admin).expect("a");
        invites.clear();
        assert!(invites.is_empty());
        assert!(
            invites
                .find(&InviteNonce([1; 16]), Tick::from_millis(0))
                .is_none()
        );
    }
}
