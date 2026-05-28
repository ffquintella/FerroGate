//! Enclave measurements and the per-cluster allowlist.
//!
//! A *measurement* is the hash of the launched CMIS image as reported by the
//! TEE (SEV-SNP `MEASUREMENT` / TDX `MRTD`). We carry it as a fixed 48-byte
//! SHA3-384 digest on the wire so the same type works for both vendors —
//! lengths are normalised by the per-vendor report parser.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

/// Length of a measurement digest in bytes (SHA3-384 / matches MRTD width).
pub const MEASUREMENT_LEN: usize = 48;

/// A TEE-launch measurement.
#[derive(Clone, Copy)]
pub struct Measurement(pub [u8; MEASUREMENT_LEN]);

impl Measurement {
    /// Build a measurement from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MEASUREMENT_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 48 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MEASUREMENT_LEN] {
        &self.0
    }

    /// Lowercase hex (96 chars), useful for tracing and audit events.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for Measurement {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Measurement {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Measurement;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("48-byte enclave measurement")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Measurement, E> {
                if v.len() != MEASUREMENT_LEN {
                    return Err(E::custom("measurement must be 48 bytes"));
                }
                let mut b = [0u8; MEASUREMENT_LEN];
                b.copy_from_slice(v);
                Ok(Measurement(b))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Measurement, E> {
                self.visit_bytes(&v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Measurement, A::Error> {
                let mut buf = Vec::with_capacity(MEASUREMENT_LEN);
                while let Some(b) = seq.next_element::<u8>()? {
                    buf.push(b);
                }
                self.visit_bytes(&buf)
            }
        }
        d.deserialize_bytes(V)
    }
}

impl PartialEq for Measurement {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Measurement {}

impl std::hash::Hash for Measurement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::fmt::Debug for Measurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't dump 96 hex chars into traces by default — show a short tag.
        write!(f, "Measurement({}…)", &self.to_hex()[..16])
    }
}

/// Approved CMIS image set. Membership is a constant-time scan to avoid a
/// timing oracle on measurement validity.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    entries: Vec<Measurement>,
}

impl Allowlist {
    /// Build an allowlist from an iterator of measurements.
    pub fn new<I: IntoIterator<Item = Measurement>>(it: I) -> Self {
        Self {
            entries: it.into_iter().collect(),
        }
    }

    /// Approve an additional measurement.
    pub fn push(&mut self, m: Measurement) {
        self.entries.push(m);
    }

    /// Number of approved measurements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the allowlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Constant-time membership check.
    #[must_use]
    pub fn contains(&self, m: &Measurement) -> bool {
        let mut acc: u8 = 0;
        for entry in &self.entries {
            let eq: u8 = entry.0.ct_eq(&m.0).unwrap_u8();
            acc |= eq;
        }
        acc != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_contains_is_membership() {
        let m1 = Measurement([1u8; 48]);
        let m2 = Measurement([2u8; 48]);
        let other = Measurement([9u8; 48]);
        let al = Allowlist::new([m1, m2]);
        assert!(al.contains(&m1));
        assert!(al.contains(&m2));
        assert!(!al.contains(&other));
    }

    #[test]
    fn measurement_debug_does_not_dump_full_hex() {
        let m = Measurement([0xab; 48]);
        let s = format!("{m:?}");
        assert!(s.contains("…"));
        assert!(!s.contains(&"ab".repeat(48)));
    }

    #[test]
    fn measurement_cbor_round_trips() {
        let m = Measurement([7u8; 48]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&m, &mut buf).unwrap();
        let m2: Measurement = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(m, m2);
    }
}
