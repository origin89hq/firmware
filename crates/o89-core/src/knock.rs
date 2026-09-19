//! What the module's answer to a knock is (L-192).
//!
//! The controller knocks by repeating one `EnterDownload` under one
//! `req_id` until the module answers it or three seconds pass. Only an
//! `EnterDownloadAck` carrying that `req_id` answers it: an `entering`
//! under any other id was never this knock's to hear, and taking it would
//! open the bridge to a module that may still be running its image.
//!
//! cites: L-192

use km43::{
    DownloadVerdict, EnterDownload, Intake, LinkEnvelope, LinkMessageType, ReqId, Side, arriving,
};

/// What a frame from the module says to the knock under `ReqId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "an answer nobody reads is a knock that runs to its deadline"]
pub enum KnockAnswer {
    /// `entering`, under the knock's own id: the module is resetting into
    /// its ROM (L-190).
    Entering,
    /// `refused_outside_window`, under the knock's own id: the window had
    /// closed (L-191).
    Refused,
    /// Anything else: another message, an answer under another id, one in
    /// a client's session, or a verdict whose body does not read.
    NotOurs,
}

/// Read `envelope`, from the module, against the knock sent as `knock`.
pub fn knock_answer(envelope: LinkEnvelope<'_>, knock: ReqId) -> KnockAnswer {
    match arriving(envelope.opcode(), Side::Controller, envelope.session()) {
        Intake::Act(LinkMessageType::EnterDownloadAck) => {}
        Intake::Act(_) | Intake::Refuse(_) => return KnockAnswer::NotOurs,
    }
    if envelope.req_id() != knock {
        return KnockAnswer::NotOurs;
    }
    match DownloadVerdict::decode(envelope) {
        Ok(DownloadVerdict {
            outcome: EnterDownload::Entering,
        }) => KnockAnswer::Entering,
        Ok(DownloadVerdict {
            outcome: EnterDownload::RefusedOutsideWindow,
        }) => KnockAnswer::Refused,
        Err(_) => KnockAnswer::NotOurs,
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use km43::{Heartbeat, LinkHeader, SessionId};

    use super::*;

    const KNOCK: ReqId = ReqId(0x5A5A_0001);

    fn verdict(
        buf: &mut [u8; 64],
        outcome: EnterDownload,
        req_id: ReqId,
        session: SessionId,
    ) -> LinkEnvelope<'_> {
        let len = DownloadVerdict { outcome }
            .write(
                LinkHeader {
                    kind: LinkMessageType::EnterDownloadAck,
                    session,
                    req_id,
                },
                buf,
            )
            .expect("encodes");
        LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope")
    }

    #[test]
    fn l_192_entering_under_the_knocks_own_id_answers_it() {
        let mut buf = [0u8; 64];
        let answer = verdict(&mut buf, EnterDownload::Entering, KNOCK, SessionId::None);
        assert_eq!(knock_answer(answer, KNOCK), KnockAnswer::Entering);
    }

    #[test]
    fn l_192_a_refusal_under_the_knocks_own_id_is_a_refusal() {
        let mut buf = [0u8; 64];
        let answer = verdict(
            &mut buf,
            EnterDownload::RefusedOutsideWindow,
            KNOCK,
            SessionId::None,
        );
        assert_eq!(knock_answer(answer, KNOCK), KnockAnswer::Refused);
    }

    #[test]
    fn l_192_entering_under_another_id_is_not_an_answer() {
        let mut buf = [0u8; 64];
        let answer = verdict(
            &mut buf,
            EnterDownload::Entering,
            ReqId(KNOCK.0.wrapping_add(1)),
            SessionId::None,
        );
        assert_eq!(knock_answer(answer, KNOCK), KnockAnswer::NotOurs);
    }

    #[test]
    fn l_192_entering_in_a_clients_session_is_not_an_answer() {
        let mut buf = [0u8; 64];
        let session = SessionId::Assigned(NonZeroU16::new(3).expect("nonzero"));
        let answer = verdict(&mut buf, EnterDownload::Entering, KNOCK, session);
        assert_eq!(knock_answer(answer, KNOCK), KnockAnswer::NotOurs);
    }

    #[test]
    fn l_192_another_message_under_the_knocks_id_is_not_an_answer() {
        let mut buf = [0u8; 64];
        let len = Heartbeat {
            uptime_s: 1,
            conns: 0,
        }
        .write(
            LinkHeader {
                kind: LinkMessageType::HeartbeatAck,
                session: SessionId::None,
                req_id: KNOCK,
            },
            &mut buf,
        )
        .expect("encodes");
        let beat = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert_eq!(knock_answer(beat, KNOCK), KnockAnswer::NotOurs);
    }

    #[test]
    fn l_192_a_verdict_whose_body_does_not_read_is_not_an_answer() {
        let mut buf = [0u8; 64];
        let mut cbor = LinkHeader {
            kind: LinkMessageType::EnterDownloadAck,
            session: SessionId::None,
            req_id: KNOCK,
        }
        .write(1, &mut buf)
        .expect("the header encodes");
        cbor.key(1).expect("key");
        cbor.u64(99).expect("value");
        let len = cbor.finish().expect("finishes");
        let answer = LinkEnvelope::decode(buf.get(..len).expect("fits")).expect("an envelope");
        assert_eq!(knock_answer(answer, KNOCK), KnockAnswer::NotOurs);
    }
}
