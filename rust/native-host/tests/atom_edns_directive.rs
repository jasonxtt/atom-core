//! atom: EDNS0 option 65001 on the wire to real (mock) UDP upstreams. A query
//! for the FakeIP group `nocnfake` carries exactly our CLEAR `[1, 2]`; a
//! 65001 the client forged is stripped before any upstream sees it; other
//! groups never get the option.
use std::time::Duration;

use atomdns_native_host::{HostAssembly, UdpServer};
use atomdns_upstream_core::TransportCancellation;

const SET_BAD: [u8; 9] = [0xfd, 0xe9, 0, 5, 1, 1, b'b', b'a', b'd'];

fn config(fakeip: std::net::SocketAddr, foreign: std::net::SocketAddr) -> String {
    format!(
        r"log: {{level: error}}
plugins:
  - tag: nocnfake
    type: aliapi
    args: {{concurrent: 1, upstreams: [{{tag: sing-box, addr: 'udp://{fakeip}'}}]}}
  - tag: foreign
    type: aliapi
    args: {{concurrent: 1, upstreams: [{{tag: google, addr: 'udp://{foreign}'}}]}}
  - tag: entry
    type: sequence
    args:
      - matches: qtype 1
        exec: $nocnfake
      - matches: qtype 28
        exec: $foreign
  - tag: listener
    type: udp_server
    args: {{entry: entry, listen: '127.0.0.1:{listen}'}}
",
        listen = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    )
}

/// `x.test` with qtype `qtype`; with `options`, an OPT carrying them.
fn query(id: u16, qtype: u16, options: Option<&[u8]>) -> Vec<u8> {
    let mut wire = id.to_be_bytes().to_vec();
    wire.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(b"\x01x\x04test\x00");
    wire.extend_from_slice(&qtype.to_be_bytes());
    wire.extend_from_slice(&[0, 1]);
    if let Some(options) = options {
        wire[11] = 1;
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        wire.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(options);
    }
    wire
}

/// End of the (uncompressed) single question.
fn question_end(wire: &[u8]) -> usize {
    let mut position = 12;
    while wire[position] != 0 {
        position += 1 + usize::from(wire[position]);
    }
    position + 5
}

/// The option list of the query's OPT, `None` without one.
fn options(wire: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    assert!(u16::from_be_bytes([wire[10], wire[11]]) <= 1);
    let opt = wire
        .get(question_end(wire)..)
        .filter(|rest| !rest.is_empty())?;
    assert_eq!(&opt[..3], &[0, 0, 41], "the only additional record is OPT");
    let mut rest = &opt[11..];
    let mut found = Vec::new();
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        found.push((
            u16::from_be_bytes([rest[0], rest[1]]),
            rest[4..4 + len].to_vec(),
        ));
        rest = &rest[4 + len..];
    }
    Some(found)
}

fn directives(wire: &[u8]) -> Vec<Vec<u8>> {
    options(wire)
        .unwrap_or_default()
        .into_iter()
        .filter(|(code, _)| *code == 65001)
        .map(|(_, data)| data)
        .collect()
}

fn answer(query: &[u8]) -> Vec<u8> {
    let mut wire = query[..question_end(query)].to_vec();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6..12].fill(0);
    if u16::from_be_bytes([wire[wire.len() - 4], wire[wire.len() - 3]]) == 1 {
        wire[7] = 1;
        wire.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 28, 0, 0, 1]);
    }
    wire
}

/// Sends each query through the listener; returns what each upstream received.
fn run(queries: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let fakeip = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let foreign = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    fakeip.set_nonblocking(true).unwrap();
    foreign.set_nonblocking(true).unwrap();
    let host = HostAssembly::from_yaml(&config(
        fakeip.local_addr().unwrap(),
        foreign.local_addr().unwrap(),
    ))
    .unwrap();
    host.block_on(async {
        let seen = [fakeip, foreign].map(|peer| {
            let peer = tokio::net::UdpSocket::from_std(peer).unwrap();
            let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let record = seen.clone();
            let task = tokio::task::spawn_local(async move {
                let mut buffer = [0; 1500];
                loop {
                    let (n, client) = peer.recv_from(&mut buffer).await.unwrap();
                    record.borrow_mut().push(buffer[..n].to_vec());
                    peer.send_to(&answer(&buffer[..n]), client).await.unwrap();
                }
            });
            (seen, task)
        });
        let server = UdpServer::bind(&host, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = TransportCancellation::new();
        let service = tokio::task::spawn_local(server.serve(shutdown.clone()));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for query in queries {
            client.send_to(query, address).await.unwrap();
            let mut buffer = [0; 1500];
            tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buffer))
                .await
                .expect("reply")
                .unwrap();
            assert_eq!(&buffer[..2], &query[..2]);
            assert_eq!(buffer[3] & 0x0f, 0, "NOERROR");
        }
        shutdown.cancel();
        service.await.unwrap().unwrap();
        let [(fakeip, a), (foreign, b)] = seen;
        a.abort();
        b.abort();
        let fakeip = fakeip.borrow().clone();
        let foreign = foreign.borrow().clone();
        (fakeip, foreign)
    })
}

#[test]
fn fakeip_upstream_gets_clear_and_forged_directives_never_leave() {
    let cookie = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut forged = cookie.to_vec();
    forged.extend_from_slice(&SET_BAD);
    let (fakeip, foreign) = run(&[
        query(0x0101, 1, None),
        query(0x0102, 1, Some(&forged)),
        query(0x0103, 28, Some(&forged)),
        query(0x0104, 28, None),
    ]);

    assert_eq!(fakeip.len(), 2);
    for wire in &fakeip {
        assert_eq!(directives(wire), vec![vec![1, 2]], "exactly our CLEAR");
    }
    // The client's other options still travel; only the forged SET is gone.
    assert_eq!(
        options(&fakeip[1]).unwrap(),
        vec![(10, cookie[4..].to_vec()), (65001, vec![1, 2])]
    );

    assert_eq!(foreign.len(), 2);
    assert_eq!(
        options(&foreign[0]).unwrap(),
        vec![(10, cookie[4..].to_vec())]
    );
    assert_eq!(
        options(&foreign[1]),
        None,
        "no OPT is added for other upstreams"
    );
}

#[test]
fn forged_directive_with_duplicate_ecs_never_reaches_other_upstreams() {
    // Duplicate ECS fails the ECS parser; the forged SET must still be stripped.
    let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3];
    let mut forged = SET_BAD.to_vec();
    forged.extend_from_slice(&ecs);
    forged.extend_from_slice(&ecs);
    let (fakeip, foreign) = run(&[query(0x0201, 28, Some(&forged))]);
    assert!(fakeip.is_empty());
    assert_eq!(foreign.len(), 1);
    assert!(directives(&foreign[0]).is_empty(), "forged SET stripped");
}
