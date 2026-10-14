//! Helper-API wire protocol: CBOR request/response and length-delimited framing.
//!
//! The transport is request/response, one exchange per connection (see
//! `docs/helper-api.md`). Each message is a single CBOR value preceded by a
//! 4-byte big-endian length. The length is bounded by [`MAX_FRAME_LEN`] so a
//! hostile or buggy client cannot make the MIA allocate without limit.
//!
//! The message types — the v1 token request and the v2 envelope with the F19
//! registration operations — live in the `mia-helper-proto` crate and are
//! re-exported here; this module adds the async (tokio) framing the daemon
//! uses.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// The wire types are shared with the Rust SDK's helper client through the
// tiny `mia-helper-proto` crate, so an application never depends on the
// daemon crate. They are re-exported here unchanged.
pub use mia_helper_proto::{
    decode_request, format_id, parse_id, ChildToken, ErrorCode, HelperFrame, HelperOp, HelperReq,
    HelperResp, LocalRequestStatus, LocalState, ProtoError, RegErrorCode, RegistrationResp,
    Request, UserSel, ID_LEN, MAX_FRAME_LEN, PROTOCOL_V2,
};

/// Framing / codec failures.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The declared frame length exceeded [`MAX_FRAME_LEN`].
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    /// CBOR encoding failed.
    #[error("cbor encode: {0}")]
    Encode(String),
    /// CBOR decoding failed.
    #[error("cbor decode: {0}")]
    Decode(String),
}

/// Serialize `value` to CBOR and write it as a length-delimited frame.
pub async fn write_frame<W, T>(w: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let mut body = Vec::with_capacity(256);
    ciborium::into_writer(value, &mut body).map_err(|e| FrameError::Encode(e.to_string()))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-delimited frame and decode it from CBOR.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let body = read_frame_bytes(r).await?;
    ciborium::from_reader(&body[..]).map_err(|e| FrameError::Decode(e.to_string()))
}

/// Read one length-delimited frame body without decoding it (the server
/// decodes it with [`decode_request`], which tells v1 from v2).
pub async fn read_frame_bytes<R>(r: &mut R) -> Result<Vec<u8>, FrameError>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn req_frame_roundtrips() {
        let req = HelperReq {
            audience: "https://api.example.com".into(),
            dpop_jkt: "abc123".into(),
            ttl_secs: 300,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).await.unwrap();
        let back: HelperReq = read_frame(&mut &buf[..]).await.unwrap();
        assert_eq!(req, back);
    }

    #[tokio::test]
    async fn resp_error_roundtrips() {
        let resp = HelperResp::Error {
            code: ErrorCode::PermissionDenied,
            retry_after: None,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &resp).await.unwrap();
        let back: HelperResp = read_frame(&mut &buf[..]).await.unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn the_shared_default_endpoint_is_the_daemon_default() {
        assert_eq!(
            std::path::Path::new(mia_helper_proto::DEFAULT_ENDPOINT),
            crate::config::default_helper_socket(None)
        );
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected_without_allocating_body() {
        // A 4-byte prefix claiming more than MAX_FRAME_LEN, with no body.
        let huge = (u32::try_from(MAX_FRAME_LEN).unwrap() + 1).to_be_bytes();
        let err = read_frame::<_, HelperReq>(&mut &huge[..])
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }
}
