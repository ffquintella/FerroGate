//! Fixed-size byte-array newtypes with CBOR/JSON byte-string serde impls.
//!
//! `serde`'s built-in `[u8; N]` `Deserialize` only covers small `N`; the audit
//! event schema uses 48- and 16-byte fields. We wrap them in newtypes whose
//! `Serialize` emits a single byte string (rather than an array of small
//! integers) so the on-wire CBOR is compact and unambiguous, and whose
//! `Deserialize` accepts both byte-string and `[u8]` array forms — the
//! conservative reader stance.

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

macro_rules! byte_array_newtype {
    ($name:ident, $len:expr) => {
        /// Wrapper exposing a fixed-size byte array with byte-string serde.
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(b: $name) -> Self {
                b.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = [u8; $len];

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a byte string or array of length {}", $len)
                    }

                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                        if v.len() != $len {
                            return Err(E::invalid_length(v.len(), &self));
                        }
                        let mut out = [0u8; $len];
                        out.copy_from_slice(v);
                        Ok(out)
                    }

                    fn visit_borrowed_bytes<E: serde::de::Error>(
                        self,
                        v: &'de [u8],
                    ) -> Result<Self::Value, E> {
                        self.visit_bytes(v)
                    }

                    fn visit_byte_buf<E: serde::de::Error>(
                        self,
                        v: Vec<u8>,
                    ) -> Result<Self::Value, E> {
                        self.visit_bytes(&v)
                    }

                    fn visit_seq<A: SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<Self::Value, A::Error> {
                        let mut out = [0u8; $len];
                        for (i, slot) in out.iter_mut().enumerate() {
                            *slot = seq
                                .next_element::<u8>()?
                                .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                        }
                        if seq.next_element::<u8>()?.is_some() {
                            return Err(A::Error::invalid_length($len + 1, &self));
                        }
                        Ok(out)
                    }
                }
                d.deserialize_bytes(V).map($name)
            }
        }
    };
}

byte_array_newtype!(Hash384, 48);
byte_array_newtype!(Bytes16, 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_roundtrip_via_byte_string() {
        let h = Hash384([0xAB; 48]);
        let mut buf = Vec::new();
        ciborium::into_writer(&h, &mut buf).unwrap();
        // First byte should be a CBOR byte string of length 48 (major type 2, length 0x18 0x30).
        assert_eq!(
            buf[0] & 0xE0,
            0x40,
            "first byte indicates major type 2 (bytes)"
        );
        let back: Hash384 = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, h);
    }
}
