//! Reading a request frame together with at most one file descriptor the
//! client passed with `SCM_RIGHTS` (F19 §4.6 `RegisterFile`).
//!
//! The frame is read with `recvmsg` so the ancillary data that rides with its
//! bytes is received rather than discarded. Through `rustix`'s safe API every
//! received descriptor arrives as an `OwnedFd`, so it is closed whenever it is
//! not used. More than one descriptor, or a truncated control message, makes
//! the frame invalid (the connection is dropped like any malformed frame).

use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;

use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
use tokio::io::Interest;
use tokio::net::UnixStream;

use crate::helper::proto::{FrameError, MAX_FRAME_LEN};

/// Read one length-delimited frame body and the descriptor passed with it.
pub(super) async fn read_frame_with_fd(
    stream: &UnixStream,
) -> Result<(Vec<u8>, Option<OwnedFd>), FrameError> {
    let mut fd = None;
    let mut prefix = [0u8; 4];
    read_exact(stream, &mut prefix, &mut fd).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    read_exact(stream, &mut body, &mut fd).await?;
    Ok((body, fd))
}

async fn read_exact(
    stream: &UnixStream,
    buf: &mut [u8],
    fd: &mut Option<OwnedFd>,
) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || {
            recv_some(stream, &mut buf[filled..], fd)
        }) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn recv_flags() -> RecvFlags {
    #[cfg(target_os = "linux")]
    {
        RecvFlags::CMSG_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        RecvFlags::empty()
    }
}

/// One `recvmsg` into `buf`, keeping at most one passed descriptor.
fn recv_some(stream: &UnixStream, buf: &mut [u8], fd: &mut Option<OwnedFd>) -> io::Result<usize> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        stream,
        &mut [IoSliceMut::new(buf)],
        &mut control,
        recv_flags(),
    )?;
    if msg.flags.contains(ReturnFlags::CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated control message",
        ));
    }
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = message {
            for passed in fds {
                if fd.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "more than one descriptor",
                    ));
                }
                *fd = Some(passed);
            }
        }
    }
    Ok(msg.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::io::IoSlice;
    use std::os::fd::AsFd as _;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn send_with(sock: &std::os::unix::net::UnixStream, bytes: &[u8], fds: &[&std::fs::File]) {
        let borrowed: Vec<_> = fds.iter().map(|f| f.as_fd()).collect();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !borrowed.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(&borrowed)));
        }
        rustix::net::sendmsg(
            sock,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();
    }

    fn pair() -> (std::os::unix::net::UnixStream, UnixStream) {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        (a, UnixStream::from_std(b).unwrap())
    }

    #[tokio::test]
    async fn a_frame_and_its_descriptor_arrive_together() {
        let (client, server) = pair();
        let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        send_with(&client, &frame(b"hello"), &[&file]);
        let (body, fd) = read_frame_with_fd(&server).await.unwrap();
        assert_eq!(body, b"hello");
        let passed = std::fs::File::from(fd.expect("a descriptor"));
        assert_eq!(
            passed.metadata().unwrap().len(),
            file.metadata().unwrap().len()
        );
        // Without a descriptor the frame still reads.
        send_with(&client, &frame(b"plain"), &[]);
        let (body, fd) = read_frame_with_fd(&server).await.unwrap();
        assert_eq!(body, b"plain");
        assert!(fd.is_none());
    }

    #[tokio::test]
    async fn two_descriptors_or_an_oversized_frame_are_refused() {
        let (client, server) = pair();
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        send_with(&client, &frame(b"x"), &[&f, &f]);
        assert!(read_frame_with_fd(&server).await.is_err());

        let (client, server) = pair();
        let huge = (u32::try_from(MAX_FRAME_LEN).unwrap() + 1).to_be_bytes();
        send_with(&client, &huge, &[]);
        assert!(matches!(
            read_frame_with_fd(&server).await,
            Err(FrameError::TooLarge(_))
        ));
    }
}
