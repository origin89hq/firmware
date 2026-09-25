//! The controller's end of the UART: the link and the sessions it carries,
//! and the one place a frame is sent to one or the other.
//!
//! A frame whose opcode is link-local, or an error with neither a session
//! nor a request, is the other firmware's and goes to the [`Link`]; every
//! other frame is a client's, relayed with its connection's handle, and
//! goes to the [`Sessions`] (L-002, P-021). The two share the rows: the
//! link admits and frees them on the comms processor's word, the sessions
//! decide what each row holds, and a close either one wants goes out as
//! the link's request. Key agreement leaves through [`Endpoint::next_job`]
//! and comes back through [`Endpoint::completed`], so whoever computes it
//! does so off the executor that calls this (P-243). The adapter and the
//! simulator both drive this, so the composition is written once.
//!
//! cites: L-002, P-243

use km43::LinkEnvelope;

use crate::agreement::{Done, Job};
use crate::fram::Fram;
use crate::link::{Actions, Link};
use crate::session::{Facts, LogSpan, Reply, Sessions};
use crate::tick::Tick;
use o89_link::is_peer_refusal;

/// What the adapter knows that neither half holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local<'a> {
    /// `Discover` key 4.
    pub model: &'a str,
    /// The log's span, as the recorder last published it.
    pub log: LogSpan,
    /// Whether the controller holds a time.
    pub time_known: bool,
    /// Whether the pairing window is open, read as this frame is handled.
    pub pairing_open: bool,
}

/// What one frame asked for: the link's actions, and a client's answer,
/// which goes out first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a step nobody performs is a frame nobody answered"]
pub struct Step {
    /// The answer to a client's frame, at the head of the buffer.
    pub reply: Option<Reply>,
    /// Then these, in order.
    pub actions: Actions,
}

/// The link and the sessions over it.
pub struct Endpoint {
    /// The link-local state machine.
    pub link: Link,
    /// The rows and their sessions.
    pub sessions: Sessions,
}

impl Endpoint {
    /// A frame from the comms processor, whole and CRC-checked. A client's
    /// answer is written into `dst`.
    pub async fn frame<F: Fram>(
        &mut self,
        frame: &[u8],
        now: Tick,
        local: &Local<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Step {
        self.link
            .set_network(match self.sessions.keys().network.held() {
                crate::Held::Present(network) => (network.version() != 0).then_some(*network),
                crate::Held::Absent => Some(crate::Network::NONE),
                crate::Held::Corrupt | crate::Held::Malformed(_) => None,
            });
        // A frame that is not four elements is nobody's to route; the
        // sessions refuse it with error 1 (P-028).
        if let Ok(envelope) = LinkEnvelope::decode(frame)
            && is_for_the_link(&envelope)
        {
            let actions = self.link.received(envelope, now, &mut self.sessions);
            // A row admitted by that frame is given its challenge before the
            // next frame is read (L-070).
            self.sessions.settle(now, fram).await;
            return Step {
                reply: None,
                actions,
            };
        }
        let controller_fw = self.link.identity().fw;
        let peer = self.link.peer().copied();
        let facts = facts(&self.link, local, controller_fw.as_str(), peer.as_ref());
        let reply = self
            .sessions
            .frame(frame, now, (&facts, &mut self.link.wifi), fram, dst)
            .await;
        self.answered(reply, now)
    }

    /// The next key agreement to compute, if the worker is free and one
    /// waits (P-243).
    pub fn next_job(&mut self) -> Option<Job> {
        self.sessions.next_job()
    }

    /// A job the adapter could not hand to the worker, put back.
    pub fn unsent(&mut self, job: Job) {
        self.sessions.unsent(job);
    }

    /// A key agreement came back from the worker: its answer, if its
    /// handshake is still the one its connection is in.
    pub async fn completed<F: Fram>(
        &mut self,
        done: Done,
        now: Tick,
        local: &Local<'_>,
        fram: &mut F,
        dst: &mut [u8],
    ) -> Step {
        let controller_fw = self.link.identity().fw;
        let peer = self.link.peer().copied();
        let facts = facts(&self.link, local, controller_fw.as_str(), peer.as_ref());
        let reply = self.sessions.completed(done, now, &facts, fram, dst).await;
        self.answered(reply, now)
    }

    /// A client's answer, and the close it asked for as the link's request.
    fn answered(&mut self, reply: Reply, now: Tick) -> Step {
        let actions = match reply.close {
            Some(close) => self.link.close(close.conn, close.reason, now),
            None => Actions::NONE,
        };
        Step {
            reply: Some(reply),
            actions,
        }
    }

    /// Time passed: the link's own tick, then every session that has gone
    /// quiet for fifteen minutes closed (P-077). `install_in_flight` is
    /// L-113's; `pairing` is the panel's window deadline while it is open,
    /// read now, which the link reports when it changed (L-195).
    pub fn tick(&mut self, now: Tick, install_in_flight: bool, pairing: Option<Tick>) -> Actions {
        self.link
            .set_network(match self.sessions.keys().network.held() {
                crate::Held::Present(network) => (network.version() != 0).then_some(*network),
                crate::Held::Absent => Some(crate::Network::NONE),
                crate::Held::Corrupt | crate::Held::Malformed(_) => None,
            });
        self.link.pairing_window(pairing, now);
        let mut actions = self.link.tick(now, install_in_flight, &mut self.sessions);
        for close in self.sessions.tick(now).iter() {
            self.link
                .close_into(close.conn, close.reason, now, &mut actions);
        }
        actions
    }
}

/// What the sessions are told that neither half holds on its own.
fn facts<'a>(
    link: &Link,
    local: &Local<'a>,
    fw_controller: &'a str,
    peer: Option<&'a crate::link::Peer>,
) -> Facts<'a> {
    Facts {
        model: local.model,
        fw_controller,
        fw_comms: peer.map_or("", |peer| peer.fw.as_str()),
        log: local.log,
        time_known: local.time_known,
        pairing_open: local.pairing_open,
        link: link.compat(),
    }
}

/// Whether a frame is the other firmware's: a link-local opcode, or an
/// error about a frame of ours, which carries neither a session nor a
/// request (L-181). An error carrying either is a client's.
fn is_for_the_link(envelope: &LinkEnvelope<'_>) -> bool {
    let request = envelope.opcode() & 0x7F;
    (0x60..=0x7E).contains(&request) || is_peer_refusal(envelope)
}
