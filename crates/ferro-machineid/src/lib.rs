//! `ferro-machineid` — stable hardware fingerprint for the TPM-less `host-key`
//! attestation profile (feature F15).
//!
//! A machine with no TPM cannot present an EK certificate. Instead, `mia`
//! anchors its identity in a fingerprint derived from stable, burned-in
//! hardware identifiers:
//!
//! ```text
//! H = SHA-384( board_serial ‖ 0x1f ‖ platform_uuid ‖ 0x1f ‖ disk_serial )
//! ```
//!
//! `H` is the direct analogue of the EK-certificate hash in the F13 fleet
//! manifest: it is the host's *enrolled identity*. It is **not** key material —
//! the signing key is a separate, non-exportable Secure-Enclave key (see the
//! `ferro-sep` crate). Deriving a key *from* these identifiers would be
//! pointless: anyone who can read the serials could reproduce it.
//!
//! All inputs are **public** hardware identifiers, so this crate stays
//! `#![forbid(unsafe_code)]`. On macOS the values are read from
//! `/usr/sbin/ioreg` (an absolute path, so `PATH` cannot be hijacked); on Linux
//! from sysfs / DMI; on Windows from the SMBIOS / storage identifiers exposed by
//! CIM, queried via an absolute-path PowerShell (same `PATH`-safety rationale as
//! `ioreg`). A native IOKit / SMBIOS backend confined to an `unsafe`-isolated
//! crate is a possible future refinement.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha384};

/// Domain-separation byte between fingerprint components (ASCII unit separator),
/// so `("AB","C")` and `("A","BC")` never hash alike.
const SEP: u8 = 0x1f;

/// The raw, normalised hardware identifiers a machine fingerprint is built from.
///
/// These are sent on the wire (in `MachineFacts`) so the verifier can recompute
/// the fingerprint and confirm the presenter observed this exact hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFacts {
    /// Board / machine serial number. On Apple Silicon this is
    /// `IOPlatformSerialNumber` (there is no per-core "CPU serial"); on Linux,
    /// the DMI product/board serial.
    pub board_serial: String,
    /// Stable platform hardware UUID (`IOPlatformUUID` / DMI `product_uuid`).
    pub platform_uuid: String,
    /// Boot-disk hardware serial (the NVMe/SATA device serial — tied to the
    /// physical drive, survives a reformat).
    pub disk_serial: String,
}

impl MachineFacts {
    /// Normalise (trim + uppercase) the identifiers into canonical form. Applied
    /// on both collection and verification so trivial formatting differences
    /// never change the fingerprint.
    #[must_use]
    pub fn normalised(&self) -> Self {
        let norm = |s: &str| s.trim().to_ascii_uppercase();
        Self {
            board_serial: norm(&self.board_serial),
            platform_uuid: norm(&self.platform_uuid),
            disk_serial: norm(&self.disk_serial),
        }
    }

    /// Compute the fingerprint `H` over the canonicalised identifiers.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        let n = self.normalised();
        let mut h = Sha384::new();
        h.update(n.board_serial.as_bytes());
        h.update([SEP]);
        h.update(n.platform_uuid.as_bytes());
        h.update([SEP]);
        h.update(n.disk_serial.as_bytes());
        let mut out = [0u8; 48];
        out.copy_from_slice(&h.finalize());
        Fingerprint(out)
    }

    /// True iff the machine is sufficiently identified after trimming.
    ///
    /// The board serial and the SMBIOS `product_uuid` are required — both stable
    /// and unique per machine. The disk serial is **best-effort**: many
    /// virtualised hosts (e.g. VMware SCSI disks) expose none, and a fingerprint
    /// built from board serial + UUID is still unique, so a blank disk serial no
    /// longer rejects the machine. Hosts that *do* report a disk serial still
    /// fold it into the fingerprint, so their identity is unchanged.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let n = self.normalised();
        !n.board_serial.is_empty() && !n.platform_uuid.is_empty()
    }
}

/// A 48-byte SHA-384 machine fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 48]);

impl Fingerprint {
    /// The 48 raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Lowercase-hex encoding (96 chars) — the form the fleet manifest enrolls.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Why hardware-fact collection failed.
#[derive(Debug, thiserror::Error)]
pub enum MachineIdError {
    /// A required identifier could not be read or was empty.
    #[error("could not read hardware identifier: {0}")]
    Unavailable(String),
    /// Running the platform query tool failed.
    #[error("hardware query failed: {0}")]
    Query(String),
    /// This platform has no fingerprint backend yet.
    #[error("machine fingerprinting is not supported on this platform")]
    Unsupported,
}

/// Collect this machine's hardware facts using the platform backend.
///
/// # Errors
/// Returns [`MachineIdError`] if any required identifier is missing or the
/// platform is unsupported.
pub fn collect_facts() -> Result<MachineFacts, MachineIdError> {
    let facts = imp::collect()?;
    if !facts.is_complete() {
        return Err(MachineIdError::Unavailable(
            "one or more hardware identifiers were empty".to_string(),
        ));
    }
    Ok(facts.normalised())
}

/// Collect facts and return the fingerprint in one step.
///
/// # Errors
/// Propagates [`collect_facts`] errors.
pub fn fingerprint() -> Result<Fingerprint, MachineIdError> {
    Ok(collect_facts()?.fingerprint())
}

// ---- macOS backend ------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use super::{MachineFacts, MachineIdError};
    use std::process::Command;

    const IOREG: &str = "/usr/sbin/ioreg";

    /// Run `ioreg -rd1 -c <class>` and return its stdout.
    fn ioreg(class: &str) -> Result<String, MachineIdError> {
        let out = Command::new(IOREG)
            .args(["-rd1", "-c", class])
            .output()
            .map_err(|e| MachineIdError::Query(format!("{IOREG} {class}: {e}")))?;
        if !out.status.success() {
            return Err(MachineIdError::Query(format!(
                "{IOREG} {class} exited with {}",
                out.status
            )));
        }
        String::from_utf8(out.stdout)
            .map_err(|e| MachineIdError::Query(format!("{IOREG} {class}: non-utf8 output: {e}")))
    }

    /// Extract the value of an `ioreg` line of the form `"key" = "value"`.
    fn prop(text: &str, key: &str) -> Option<String> {
        let needle = format!("\"{key}\"");
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix(&needle) {
                // rest looks like ` = "value"`
                if let Some(eq) = rest.find('=') {
                    let v = rest[eq + 1..].trim();
                    let v = v.trim_matches('"');
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        None
    }

    pub(super) fn collect() -> Result<MachineFacts, MachineIdError> {
        let platform = ioreg("IOPlatformExpertDevice")?;
        let board_serial = prop(&platform, "IOPlatformSerialNumber")
            .ok_or_else(|| MachineIdError::Unavailable("IOPlatformSerialNumber".to_string()))?;
        let platform_uuid = prop(&platform, "IOPlatformUUID")
            .ok_or_else(|| MachineIdError::Unavailable("IOPlatformUUID".to_string()))?;

        let nvme = ioreg("IONVMeController")?;
        let disk_serial = prop(&nvme, "Serial Number")
            .ok_or_else(|| MachineIdError::Unavailable("NVMe Serial Number".to_string()))?;

        Ok(MachineFacts {
            board_serial,
            platform_uuid,
            disk_serial,
        })
    }
}

// ---- Linux backend ------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::{MachineFacts, MachineIdError};
    use std::fs;
    use std::path::Path;

    fn read_trim(path: &str) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// First non-removable block device's hardware serial under `/sys/block`.
    fn disk_serial() -> Option<String> {
        let entries = fs::read_dir("/sys/block").ok()?;
        let mut candidates: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            // skip virtual / removable devices
            .filter(|n| !n.starts_with("loop") && !n.starts_with("ram") && !n.starts_with("dm-"))
            .collect();
        candidates.sort();
        for dev in candidates {
            let base = format!("/sys/block/{dev}/device");
            if Path::new(&format!("/sys/block/{dev}/removable"))
                .canonicalize()
                .is_ok()
            {
                if let Some("1") = read_trim(&format!("/sys/block/{dev}/removable")).as_deref() {
                    continue;
                }
            }
            if let Some(s) = read_trim(&format!("{base}/serial")) {
                return Some(s);
            }
            // NVMe namespaces expose the controller serial one level up.
            if let Some(s) = read_trim(&format!("{base}/../serial")) {
                return Some(s);
            }
        }
        None
    }

    pub(super) fn collect() -> Result<MachineFacts, MachineIdError> {
        // DMI is the strong hardware anchor; board serial falls back to the
        // product serial when the board serial is restricted.
        let board_serial = read_trim("/sys/class/dmi/id/board_serial")
            .or_else(|| read_trim("/sys/class/dmi/id/product_serial"))
            .ok_or_else(|| {
                MachineIdError::Unavailable("DMI board/product serial (needs root?)".to_string())
            })?;
        let platform_uuid = read_trim("/sys/class/dmi/id/product_uuid").ok_or_else(|| {
            MachineIdError::Unavailable("DMI product_uuid (needs root?)".to_string())
        })?;
        // Best-effort: absent on many virtualised hosts (VMware SCSI disks
        // expose no serial / wwid / VPD page). The fingerprint stays
        // well-defined without it (board serial + product UUID); see
        // [`MachineFacts::is_complete`].
        let disk_serial = disk_serial().unwrap_or_default();

        Ok(MachineFacts {
            board_serial,
            platform_uuid,
            disk_serial,
        })
    }
}

// ---- Windows backend ----------------------------------------------------

#[cfg(target_os = "windows")]
mod imp {
    use super::{MachineFacts, MachineIdError};
    use std::process::Command;

    /// Absolute path to Windows PowerShell, so `PATH` cannot be hijacked
    /// (mirrors the macOS `ioreg` approach). `%SystemRoot%` is `C:\Windows` on a
    /// default install; PowerShell 5.1 ships in-box on every supported Windows.
    fn powershell() -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe")
    }

    /// Query the burned-in SMBIOS / storage identifiers via CIM in one process,
    /// emitting `key=value` lines we parse below. These are the Windows
    /// analogues of the macOS `ioreg` / Linux DMI values: the SMBIOS system UUID
    /// and baseboard serial (`Win32_ComputerSystemProduct` / `Win32_BaseBoard`)
    /// and the lowest-index physical disk's serial (`Win32_DiskDrive`).
    fn query() -> Result<String, MachineIdError> {
        const SCRIPT: &str = "$ErrorActionPreference='SilentlyContinue';\
            $p=Get-CimInstance Win32_ComputerSystemProduct;\
            $b=Get-CimInstance Win32_BaseBoard;\
            $d=Get-CimInstance Win32_DiskDrive | Sort-Object Index | Select-Object -First 1;\
            Write-Output \"uuid=$($p.UUID)\";\
            Write-Output \"board=$($b.SerialNumber)\";\
            Write-Output \"product=$($p.IdentifyingNumber)\";\
            Write-Output \"disk=$($d.SerialNumber)\"";
        let out = Command::new(powershell())
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .output()
            .map_err(|e| MachineIdError::Query(format!("powershell: {e}")))?;
        if !out.status.success() {
            return Err(MachineIdError::Query(format!(
                "powershell exited with {}",
                out.status
            )));
        }
        String::from_utf8(out.stdout)
            .map_err(|e| MachineIdError::Query(format!("non-utf8 output: {e}")))
    }

    /// Common SMBIOS placeholder strings that are not real identifiers — treated
    /// as absent so a board that ships "To Be Filled By O.E.M." falls back.
    fn is_placeholder(v: &str) -> bool {
        matches!(
            v.trim().to_ascii_uppercase().as_str(),
            "" | "TO BE FILLED BY O.E.M."
                | "DEFAULT STRING"
                | "SYSTEM SERIAL NUMBER"
                | "NONE"
                | "NOT SPECIFIED"
                | "NOT APPLICABLE"
                | "0"
                | "00000000-0000-0000-0000-000000000000"
                | "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
        )
    }

    /// Value of the `key=value` line for `key`, rejecting placeholder junk.
    fn val(text: &str, key: &str) -> Option<String> {
        let prefix = format!("{key}=");
        text.lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
            .map(str::trim)
            .filter(|v| !is_placeholder(v))
            .map(ToString::to_string)
    }

    pub(super) fn collect() -> Result<MachineFacts, MachineIdError> {
        let text = query()?;
        // The SMBIOS system UUID is the strong, stable anchor (the analogue of
        // DMI `product_uuid`).
        let platform_uuid = val(&text, "uuid").ok_or_else(|| {
            MachineIdError::Unavailable(
                "SMBIOS system UUID (Win32_ComputerSystemProduct.UUID)".to_string(),
            )
        })?;
        // Baseboard serial is often blank on consumer hardware; fall back to the
        // product identifying number (both are burned-in SMBIOS fields).
        let board_serial = val(&text, "board")
            .or_else(|| val(&text, "product"))
            .ok_or_else(|| {
                MachineIdError::Unavailable("baseboard / product serial".to_string())
            })?;
        let disk_serial = val(&text, "disk").ok_or_else(|| {
            MachineIdError::Unavailable("boot disk serial (Win32_DiskDrive.SerialNumber)".to_string())
        })?;

        Ok(MachineFacts {
            board_serial,
            platform_uuid,
            disk_serial,
        })
    }
}

// ---- Unsupported platforms ----------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::{MachineFacts, MachineIdError};

    pub(super) fn collect() -> Result<MachineFacts, MachineIdError> {
        Err(MachineIdError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(a: &str, b: &str, c: &str) -> MachineFacts {
        MachineFacts {
            board_serial: a.to_string(),
            platform_uuid: b.to_string(),
            disk_serial: c.to_string(),
        }
    }

    #[test]
    fn fingerprint_is_stable_and_normalised() {
        let lower = facts("wt3qf2j3yl", " 38d33b14 ", "0ba02061");
        let upper = facts("WT3QF2J3YL", "38D33B14", "0BA02061");
        assert_eq!(lower.fingerprint(), upper.fingerprint());
    }

    #[test]
    fn distinct_hardware_distinct_fingerprint() {
        assert_ne!(
            facts("A", "B", "C").fingerprint(),
            facts("A", "B", "D").fingerprint()
        );
    }

    #[test]
    fn component_boundaries_are_unambiguous() {
        // Without a separator, ("AB","C","D") and ("A","BC","D") would collide.
        assert_ne!(
            facts("AB", "C", "D").fingerprint(),
            facts("A", "BC", "D").fingerprint()
        );
    }

    #[test]
    fn hex_is_96_chars() {
        assert_eq!(facts("A", "B", "C").fingerprint().to_hex().len(), 96);
    }

    #[test]
    fn completeness_rejects_blank_fields() {
        assert!(!facts("A", "", "C").is_complete());
        assert!(facts("A", "B", "C").is_complete());
    }

    // On this developer Mac the real backend should yield a complete set.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_collects_real_facts() {
        let f = collect_facts().expect("collect on macOS");
        assert!(f.is_complete());
        assert_eq!(f.fingerprint().to_hex().len(), 96);
    }
}
