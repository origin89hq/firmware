//! The station's DHCP client against `embassy-net`'s own stack.
//!
//! The comms core reports `no_ip` once the station has been associated for
//! `NO_IP` without an address (F-092). The DHCP client must resend a lost
//! DISCOVER inside that bound, or one dropped frame reads as a failed join
//! (firmware #143). The stack runs here on the mock clock with a link that
//! comes up after the stack's first poll, as association does on the part,
//! and never answers, so every DISCOVER is lost. The test reads when each
//! one leaves.

#[cfg(test)]
mod dhcp {
    use core::cell::{Cell, RefCell};
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use std::rc::Rc;

    use embassy_net::driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};
    use embassy_net::{Config, DhcpConfig, StackResources};
    use embassy_time::{Duration, Instant, MockDriver};
    use o89_comms_core::{DHCP_DISCOVER_RESEND, NO_IP};
    use o89_comms_net::station_dhcp;

    /// How far the mock clock moves between polls of the runner.
    const STEP: Duration = Duration::from_millis(10);
    /// How long each run lasts: past smoltcp's default 10 s resend.
    const HORIZON: Duration = Duration::from_secs(12);
    /// The station's socket budget is not under test here; the DHCP client and
    /// DNS are the only sockets this stack opens.
    const SOCKETS: usize = 2;

    /// When each DISCOVER left, in milliseconds on the mock clock.
    type Sent = Rc<RefCell<Vec<u64>>>;

    /// A link that sends nothing until `up`, and never answers.
    struct Silent {
        up: Rc<Cell<bool>>,
        sent: Sent,
    }

    struct Nothing;

    impl RxToken for Nothing {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
            f(&mut [])
        }
    }

    /// Records a frame's send time when it is a DHCP DISCOVER.
    struct Capture {
        sent: Sent,
    }

    impl TxToken for Capture {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut frame = vec![0u8; len];
            let result = f(&mut frame);
            if is_discover(&frame) {
                self.sent.borrow_mut().push(Instant::now().as_millis());
            }
            result
        }
    }

    impl Driver for Silent {
        type RxToken<'a> = Nothing;
        type TxToken<'a> = Capture;

        fn receive(&mut self, _cx: &mut Context) -> Option<(Nothing, Capture)> {
            None
        }

        fn transmit(&mut self, _cx: &mut Context) -> Option<Capture> {
            self.up.get().then(|| Capture {
                sent: Rc::clone(&self.sent),
            })
        }

        fn link_state(&mut self, _cx: &mut Context) -> LinkState {
            if self.up.get() {
                LinkState::Up
            } else {
                LinkState::Down
            }
        }

        fn capabilities(&self) -> Capabilities {
            let mut capabilities = Capabilities::default();
            capabilities.max_transmission_unit = 1_514;
            capabilities
        }

        fn hardware_address(&self) -> HardwareAddress {
            HardwareAddress::Ethernet([0x02, 0, 0, 0, 0, 0x01])
        }
    }

    /// An Ethernet frame carrying a DHCP message of type 1 (DISCOVER) to the
    /// server port.
    fn is_discover(frame: &[u8]) -> bool {
        const ETHERNET: usize = 14;
        /// The UDP header and BOOTP's fixed fields, before the magic cookie.
        const COOKIE_AT: usize = 8 + 236;
        const COOKIE: [u8; 4] = [99, 130, 83, 99];
        if frame.get(12..14) != Some(&[0x08, 0x00]) {
            return false;
        }
        let Some(ip) = frame.get(ETHERNET..) else {
            return false;
        };
        let (Some(&version_ihl), Some(&17)) = (ip.first(), ip.get(9)) else {
            return false;
        };
        let Some(udp) = ip.get(usize::from(version_ihl & 0x0f).saturating_mul(4)..) else {
            return false;
        };
        if udp.get(2..4) != Some(&[0, 67]) {
            return false;
        }
        let Some([c0, c1, c2, c3, options @ ..]) = udp.get(COOKIE_AT..) else {
            return false;
        };
        if [*c0, *c1, *c2, *c3] != COOKIE {
            return false;
        }
        // Each pass consumes at least one byte, so the frame bounds the walk.
        let mut rest = options;
        while let [code, tail @ ..] = rest {
            match code {
                0 => rest = tail,
                255 => return false,
                _ => {
                    let [len, value @ ..] = tail else {
                        return false;
                    };
                    if *code == 53 {
                        return value.first() == Some(&1);
                    }
                    rest = value.get(usize::from(*len)..).unwrap_or(&[]);
                }
            }
        }
        false
    }

    /// Runs the stack for `HORIZON` on the mock clock, the link coming up after
    /// the first poll, and returns when each DISCOVER left relative to the
    /// first.
    fn discovers(dhcp: DhcpConfig) -> Vec<u64> {
        MockDriver::get().reset();
        let up = Rc::new(Cell::new(false));
        let sent = Sent::default();
        let mut resources = StackResources::<SOCKETS>::new();
        let (_stack, mut runner) = embassy_net::new(
            Silent {
                up: Rc::clone(&up),
                sent: Rc::clone(&sent),
            },
            Config::dhcpv4(dhcp),
            &mut resources,
            1,
        );
        let mut run = pin!(runner.run());
        let mut cx = Context::from_waker(Waker::noop());
        // The mock clock moves `STEP` a pass, so `HORIZON` bounds the loop.
        while Instant::now().as_millis() <= HORIZON.as_millis() {
            assert!(matches!(run.as_mut().poll(&mut cx), Poll::Pending));
            up.set(true);
            MockDriver::get().advance(STEP);
        }
        let sent = sent.borrow();
        let first = *sent
            .first()
            .expect("the stack sends a DISCOVER once the link is up");
        sent.iter().map(|at| at.saturating_sub(first)).collect()
    }

    /// The longest wait between one DISCOVER and the next, and when the last
    /// one left. embassy-net sends one on the poll that sees the link up and
    /// another on the next, when it resets its DHCP client, so the first gap is
    /// one step; what binds a lost DISCOVER is the longest gap.
    fn longest_gap(sent: &[u64]) -> (u64, u64) {
        let longest = sent
            .windows(2)
            .map(|pair| pair[1].saturating_sub(pair[0]))
            .max()
            .expect("a lost DISCOVER is resent");
        (longest, *sent.last().expect("a DISCOVER was sent"))
    }

    /// Both runs share the one mock clock, so they run in sequence.
    #[test]
    fn f_092_a_lost_discover_is_resent_inside_the_no_ip_bound() {
        let resend = DHCP_DISCOVER_RESEND.as_millis();
        let (longest, last) =
            longest_gap(&discovers(station_dhcp("o89").expect("a short hostname")));
        assert!(
            longest < NO_IP.as_millis(),
            "a lost DISCOVER waited {longest} ms, past `no_ip` at {} ms",
            NO_IP.as_millis()
        );
        assert!(
            (resend..resend + STEP.as_millis()).contains(&longest),
            "resends {longest} ms apart, configured for {resend} ms"
        );
        // Resends continue for the whole run rather than stopping early,
        // which would also keep every gap short.
        assert!(
            last + resend + STEP.as_millis() > HORIZON.as_millis(),
            "the last DISCOVER left at {last} ms of {} ms",
            HORIZON.as_millis()
        );

        // smoltcp's default is what board A ran before #143: a lost DISCOVER
        // waits past the moment the core reports `no_ip`.
        let (stock, _) = longest_gap(&discovers(DhcpConfig::default()));
        assert!(
            stock >= NO_IP.as_millis(),
            "the default resent after {stock} ms, inside `no_ip`"
        );
    }
}
