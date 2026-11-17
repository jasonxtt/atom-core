//! Linux packet info for wildcard UDP listeners, including dual-stack sockets.
#![allow(unsafe_code)]

use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};

use socket2::{SockAddr, Socket};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use super::ReplyTo;

pub(crate) fn enable(socket: &Socket, dual_stack: bool) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_option(fd, libc::IPPROTO_IP, libc::IP_PKTINFO)?;
    if dual_stack {
        set_option(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)?;
    }
    Ok(())
}

fn set_option(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: The borrowed socket is live and the option reads one C int.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const on).cast(),
            size_of_val(&on) as _,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum Source {
    V4(libc::in_addr),
    V6(libc::in6_pktinfo),
}

impl Source {
    pub(super) async fn send(
        self,
        socket: &UdpSocket,
        wire: &[u8],
        peer: SocketAddr,
    ) -> io::Result<usize> {
        let fd = socket.as_raw_fd();
        socket
            .async_io(Interest::WRITABLE, || match self {
                Self::V4(address) => sendmsg(
                    fd,
                    wire,
                    peer,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    libc::in_pktinfo {
                        // Keep route selection independent of the ingress interface.
                        ipi_ifindex: 0,
                        ipi_spec_dst: address,
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    },
                ),
                Self::V6(info) => {
                    sendmsg(fd, wire, peer, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, info)
                }
            })
            .await
    }
}

pub(super) async fn recv(
    socket: &UdpSocket,
    wire: &mut [u8],
) -> io::Result<Option<(usize, ReplyTo)>> {
    socket
        .async_io(Interest::READABLE, || recvmsg(socket.as_raw_fd(), wire))
        .await
}

// A dual-stack socket can receive both IPv4 and IPv6 control messages for
// one datagram. CMSG headers require native alignment.
const CONTROL_SIZE: usize = unsafe {
    (libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as _)
        + libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _)) as usize
};

#[repr(C)]
struct Control {
    _alignment: [libc::cmsghdr; 0],
    bytes: [u8; CONTROL_SIZE],
}

impl Control {
    fn new() -> Self {
        Self {
            _alignment: [],
            bytes: [0; CONTROL_SIZE],
        }
    }
}

fn recvmsg(fd: RawFd, wire: &mut [u8]) -> io::Result<Option<(usize, ReplyTo)>> {
    let mut control = Control::new();
    let mut iov = libc::iovec {
        iov_base: wire.as_mut_ptr().cast(),
        iov_len: wire.len(),
    };
    // SAFETY: All pointers refer to live writable buffers of the given sizes.
    // On success recvmsg initializes the peer address and sets its length.
    let ((length, source), peer) = unsafe {
        SockAddr::try_init(|address, length| {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = address.cast();
            msg.msg_namelen = *length;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.bytes.as_mut_ptr().cast();
            msg.msg_controllen = control.bytes.len() as _;
            let received = libc::recvmsg(fd, &mut msg, 0);
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            *length = msg.msg_namelen;
            Ok((received as usize, source_from(&msg)))
        })
    }?;
    // A datagram missing its packet info must not get a reply with an
    // unspecified source. Discard it without closing the listener.
    Ok(peer.as_socket().zip(source).map(|(peer, source)| {
        (
            length,
            ReplyTo {
                peer,
                source: Some(source),
            },
        )
    }))
}

/// Reads the control buffer returned by a successful Linux recvmsg.
unsafe fn source_from(msg: &libc::msghdr) -> Option<Source> {
    if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return None;
    }
    // SAFETY: recvmsg supplied the headers and their lengths in the aligned
    // buffer. Check the payload size before reading either packet-info type.
    unsafe {
        let mut v6 = None;
        let mut header = libc::CMSG_FIRSTHDR(msg);
        while let Some(cmsg) = header.as_ref() {
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_PKTINFO)
                    if cmsg.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as _) as _ =>
                {
                    let info = libc::CMSG_DATA(header)
                        .cast::<libc::in_pktinfo>()
                        .read_unaligned();
                    // Prefer IPv4 packet info over IPv6 info for a mapped peer.
                    // The local destination of unicast traffic is exact.
                    // For broadcasts this is a usable local unicast address.
                    return Some(Source::V4(info.ipi_spec_dst));
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)
                    if cmsg.cmsg_len
                        >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as _ =>
                {
                    let mut info = libc::CMSG_DATA(header)
                        .cast::<libc::in6_pktinfo>()
                        .read_unaligned();
                    let ip = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                    if !ip.is_unicast_link_local() {
                        info.ipi6_ifindex = 0;
                    }
                    if ip.is_multicast() {
                        // The kernel selects a unicast source for multicast queries.
                        info.ipi6_addr.s6_addr = Ipv6Addr::UNSPECIFIED.octets();
                    }
                    v6 = Some(Source::V6(info));
                }
                _ => {}
            }
            header = libc::CMSG_NXTHDR(msg, header);
        }
        v6
    }
}

fn sendmsg<T: Copy>(
    fd: RawFd,
    wire: &[u8],
    peer: SocketAddr,
    level: libc::c_int,
    kind: libc::c_int,
    info: T,
) -> io::Result<usize> {
    assert!(size_of::<T>() <= size_of::<libc::in6_pktinfo>());
    let peer = SockAddr::from(peer);
    let mut iov = libc::iovec {
        iov_base: wire.as_ptr().cast_mut().cast(),
        iov_len: wire.len(),
    };
    let mut control = Control::new();
    // SAFETY: The aligned buffer fits either packet-info type and its
    // header. sendmsg only reads the address, iovec, payload and control data.
    let sent = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = peer.as_ptr().cast_mut().cast();
        msg.msg_namelen = peer.len();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.bytes.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(size_of::<T>() as _) as _;
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<T>() as _) as _;
        (*header).cmsg_level = level;
        (*header).cmsg_type = kind;
        libc::CMSG_DATA(header).cast::<T>().write_unaligned(info);
        libc::sendmsg(fd, &msg, 0)
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sent as usize)
}
