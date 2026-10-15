//! Bounded random access to an untrusted file, and checked integer reads.
//!
//! Every parser reads through a [`Source`]: each read is bounds-checked
//! against the file length, charged to the metadata byte budget, and checked
//! against the wall-clock deadline. Integer fields are read with
//! [`Fields`], which returns [`ParseError::Truncated`] instead of indexing
//! out of bounds, so hostile offsets and lengths can only produce errors.

use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use crate::limits::Limits;

/// Why metadata parsing stopped. Identification treats every variant the
/// same way: the source contributes no version.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// A structure extends past the data that holds it.
    #[error("truncated")]
    Truncated,
    /// A structure is inconsistent; names the structure.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// The metadata byte budget is exhausted.
    #[error("metadata read limit exceeded")]
    TooMuchData,
    /// Nesting is deeper than the limit.
    #[error("nesting deeper than the limit")]
    TooDeep,
    /// The wall-clock budget is exhausted.
    #[error("time budget exceeded")]
    Deadline,
    /// Reading the file failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl ParseError {
    /// A short stable name of the failure, for diagnostics.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::Malformed(_) => "malformed",
            Self::TooMuchData => "too_much_data",
            Self::TooDeep => "too_deep",
            Self::Deadline => "deadline",
            Self::Io(_) => "io",
        }
    }
}

/// The metadata budget of one identification: bytes and time.
#[derive(Debug)]
pub(crate) struct Budget {
    deadline: Instant,
    remaining: u64,
    pub(crate) max_depth: usize,
}

impl Budget {
    pub(crate) fn new(limits: &Limits) -> Self {
        Self {
            deadline: Instant::now() + limits.time_budget,
            remaining: limits.max_metadata_bytes,
            max_depth: limits.max_depth,
        }
    }

    /// Fail once the deadline has passed.
    pub(crate) fn check_time(&self) -> Result<(), ParseError> {
        if Instant::now() >= self.deadline {
            return Err(ParseError::Deadline);
        }
        Ok(())
    }

    /// Charge `n` bytes to the budget.
    pub(crate) fn take(&mut self, n: u64) -> Result<(), ParseError> {
        self.check_time()?;
        self.remaining = self
            .remaining
            .checked_sub(n)
            .ok_or(ParseError::TooMuchData)?;
        Ok(())
    }
}

/// Bounded random access to the file being identified.
pub(crate) struct Source<'a, R: Read + Seek> {
    inner: &'a mut R,
    len: u64,
    pub(crate) budget: &'a mut Budget,
}

impl<'a, R: Read + Seek> Source<'a, R> {
    /// A source over the first `len` bytes of `inner`.
    pub(crate) fn new(inner: &'a mut R, len: u64, budget: &'a mut Budget) -> Self {
        Self { inner, len, budget }
    }

    /// Read exactly `len` bytes at `offset`.
    pub(crate) fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, ParseError> {
        let len64 = u64::try_from(len).map_err(|_| ParseError::TooMuchData)?;
        let end = offset.checked_add(len64).ok_or(ParseError::Truncated)?;
        if end > self.len {
            return Err(ParseError::Truncated);
        }
        self.budget.take(len64)?;
        self.inner.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read up to `max` bytes at `offset` (fewer at the end of the data).
    pub(crate) fn read_prefix(&mut self, offset: u64, max: usize) -> Result<Vec<u8>, ParseError> {
        let available = self.len.saturating_sub(offset);
        let len = usize::try_from(available.min(max as u64)).unwrap_or(max);
        self.read_at(offset, len)
    }
}

/// Checked fixed-width reads from a byte slice, in one byte order.
#[derive(Clone, Copy)]
pub(crate) struct Fields<'b> {
    pub(crate) buf: &'b [u8],
    pub(crate) little_endian: bool,
}

impl<'b> Fields<'b> {
    pub(crate) fn le(buf: &'b [u8]) -> Self {
        Self {
            buf,
            little_endian: true,
        }
    }

    pub(crate) fn new(buf: &'b [u8], little_endian: bool) -> Self {
        Self { buf, little_endian }
    }

    fn array<const N: usize>(&self, off: usize) -> Result<[u8; N], ParseError> {
        let end = off.checked_add(N).ok_or(ParseError::Truncated)?;
        self.buf
            .get(off..end)
            .and_then(|s| s.try_into().ok())
            .ok_or(ParseError::Truncated)
    }

    pub(crate) fn u16(&self, off: usize) -> Result<u16, ParseError> {
        let a = self.array::<2>(off)?;
        Ok(if self.little_endian {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }

    pub(crate) fn u32(&self, off: usize) -> Result<u32, ParseError> {
        let a = self.array::<4>(off)?;
        Ok(if self.little_endian {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    pub(crate) fn u64(&self, off: usize) -> Result<u64, ParseError> {
        let a = self.array::<8>(off)?;
        Ok(if self.little_endian {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }

    pub(crate) fn slice(&self, off: usize, len: usize) -> Result<&'b [u8], ParseError> {
        let end = off.checked_add(len).ok_or(ParseError::Truncated)?;
        self.buf.get(off..end).ok_or(ParseError::Truncated)
    }
}

/// `n` rounded up to a multiple of `align` (a power of two), checked.
pub(crate) fn align_up(n: usize, align: usize) -> Result<usize, ParseError> {
    let mask = align - 1;
    n.checked_add(mask)
        .map(|v| v & !mask)
        .ok_or(ParseError::Truncated)
}

/// Convert a 64-bit file quantity to `usize`, refusing what cannot be held.
pub(crate) fn to_usize(v: u64) -> Result<usize, ParseError> {
    usize::try_from(v).map_err(|_| ParseError::TooMuchData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounds_checked() {
        let f = Fields::le(&[1, 0, 0, 0, 2]);
        assert_eq!(f.u32(0).unwrap(), 1);
        assert!(matches!(f.u32(2), Err(ParseError::Truncated)));
        assert!(matches!(f.u64(usize::MAX - 2), Err(ParseError::Truncated)));
        assert!(matches!(f.slice(4, 2), Err(ParseError::Truncated)));
        assert_eq!(Fields::new(&[0, 1], false).u16(0).unwrap(), 1);
    }

    #[test]
    fn the_byte_budget_is_enforced() {
        let limits = Limits {
            max_metadata_bytes: 8,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits);
        let mut data = std::io::Cursor::new(vec![0u8; 64]);
        let mut src = Source::new(&mut data, 64, &mut budget);
        assert_eq!(src.read_at(0, 8).unwrap().len(), 8);
        assert!(matches!(src.read_at(8, 1), Err(ParseError::TooMuchData)));
        assert!(matches!(src.read_at(60, 8), Err(ParseError::Truncated)));
        assert!(matches!(
            src.read_at(u64::MAX, 2),
            Err(ParseError::Truncated)
        ));
    }

    #[test]
    fn alignment_is_checked() {
        assert_eq!(align_up(5, 4).unwrap(), 8);
        assert_eq!(align_up(8, 8).unwrap(), 8);
        assert!(align_up(usize::MAX, 4).is_err());
    }
}
