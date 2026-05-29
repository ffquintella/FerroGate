//! Helper-API wire protocol: CBOR request/response and length-delimited framing.
//!
//! The transport is request/response, one exchange per connection (see
//! `docs/helper-api.md`). Each message is a single CBOR value preceded by a
//! 4-byte big-endian length. The length is bounded by [`MAX_FRAME_LEN`] so a
//! hostile or buggy client cannot make the MIA allocate without limit.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest frame the server will read or write, in bytes. Requests are tiny;
/// a minted child token is a few KiB of composite signature, so 64 KiB is
/// generous while still bounding per-connection memory.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// A token request from a local caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperReq {
    /// Target audience the token is minted for, e.g. `https://api.example.com`.
    pub audience: String,
    /// Base64url SHA-256 thumbprint of the caller's DPoP public JWK.
    pub dpop_jkt: String,
    /// Requested lifetime in seconds; clamped server-side to
    /// [`crate::helper::token::MAX_CHILD_TTL_SECS`].
    pub ttl_secs: u32,
}

/// A minted child token plus the metadata a caller needs to schedule renewal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildToken {
    /// The compact JWS child token.
    pub jws: String,
    /// Expiry, Unix seconds.
    pub exp: i64,
}

/// Stable refusal opcodes. These are a closed set — never caller input — so
/// the channel exposes no oracle surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Caller failed authentication or is not on the allowlist.
    PermissionDenied,
    /// The MIA holds no valid host SVID, so it cannot mint.
    NoHostSvid,
    /// The request was malformed (bad fields).
    MalformedRequest,
    /// The server is shedding load; retry later.
    RateLimited,
    /// An unexpected internal error.
    Internal,
}

/// The server's reply to a [`HelperReq`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperResp {
    /// A successfully minted token.
    Token(ChildToken),
    /// A refusal, optionally with a retry hint (seconds).
    Error {
        /// The refusal opcode.
        code: ErrorCode,
        /// Suggested seconds to wait before retrying, if applicable.
        retry_after: Option<u32>,
    },
}

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
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    ciborium::from_reader(&body[..]).map_err(|e| FrameError::Decode(e.to_string()))
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
