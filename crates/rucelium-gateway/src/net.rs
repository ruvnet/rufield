//! The UDP front door (ADR-265 §4): one socket, one receive loop, every
//! datagram fed through [`crate::pipeline::process_datagram`] under the
//! state lock with the reception timestamp from the system clock.

use crate::pipeline::process_datagram;
use crate::state::{now_ns, GatewayState};
use tokio::net::UdpSocket;

/// Largest datagram the gateway will read (a v1 envelope is 151 bytes; the
/// headroom tolerates future envelope kinds without silent truncation).
const MAX_DATAGRAM: usize = 2048;

/// Run the UDP receive loop forever on an already-bound socket. Rejections
/// are counted in the shared state, not logged per-datagram (an attacker
/// must not be able to flood the log).
pub async fn run_udp(socket: UdpSocket, state: GatewayState) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _from)) => {
                let received_ns = now_ns();
                let mut inner = state.inner.lock().await;
                let _ = process_datagram(&mut inner, &buf[..len], received_ns);
            }
            Err(e) => {
                eprintln!("gateway: udp receive error: {e}");
            }
        }
    }
}
