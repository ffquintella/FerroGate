//! Serde helpers for fixed-size byte arrays as CBOR byte strings.
//!
//! `serde` encodes `[u8; N]` as an array of N integers by default; the signed
//! documents use a single CBOR byte string instead (compact, and one canonical
//! form). Only the byte-string form is accepted on decode, and the length must
//! match exactly.

use std::fmt;

use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};

struct FixedVisitor<const N: usize>;

impl<const N: usize> Visitor<'_> for FixedVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a byte string of length {N}")
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
    }

    fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&v)
    }
}

/// `[u8; N]` as one byte string.
pub(crate) mod fixed {
    use super::{Deserializer, FixedVisitor, Serializer};

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        v: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        d.deserialize_bytes(FixedVisitor::<N>)
    }
}

/// `Option<[u8; N]>` as a byte string or CBOR `null`.
pub(crate) mod opt_fixed {
    use std::fmt;

    use serde::de::Visitor;

    use super::{Deserializer, FixedVisitor, Serializer};

    // `serde(with)` fixes this signature.
    #[allow(clippy::ref_option)]
    pub(crate) fn serialize<S: Serializer, const N: usize>(
        v: &Option<[u8; N]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&Bytes(b)),
            None => s.serialize_none(),
        }
    }

    struct Bytes<'a, const N: usize>(&'a [u8; N]);
    impl<const N: usize> serde::Serialize for Bytes<'_, N> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.0)
        }
    }

    struct OptVisitor<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for OptVisitor<N> {
        type Value = Option<[u8; N]>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "null or a byte string of length {N}")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_bytes(FixedVisitor::<N>).map(Some)
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        d.deserialize_option(OptVisitor::<N>)
    }
}

/// `Vec<[u8; N]>` as an array of byte strings.
pub(crate) mod vec_fixed {
    use super::{fmt, Deserializer, FixedVisitor, SeqAccess, SerializeSeq, Serializer, Visitor};

    struct Item<const N: usize>([u8; N]);
    impl<'de, const N: usize> serde::Deserialize<'de> for Item<N> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_bytes(FixedVisitor::<N>).map(Item)
        }
    }

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        v: &[[u8; N]],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        struct Bytes<'a, const N: usize>(&'a [u8; N]);
        impl<const N: usize> serde::Serialize for Bytes<'_, N> {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0)
            }
        }
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&Bytes(item))?;
        }
        seq.end()
    }

    struct SeqVisitor<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for SeqVisitor<N> {
        type Value = Vec<[u8; N]>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "an array of byte strings of length {N}")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            // The caller bounds the encoded size; do not trust a size hint.
            let mut out = Vec::new();
            while let Some(Item(b)) = seq.next_element::<Item<N>>()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Vec<[u8; N]>, D::Error> {
        d.deserialize_seq(SeqVisitor::<N>)
    }
}
