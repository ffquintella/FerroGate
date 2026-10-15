//! Risk flags (F19 §4.5): a bitmask shown to the approver and used by the
//! auto-update policy. MIA sets the file-system bits, `ferro-appid` the
//! interpreter and signature bits, CMIS the history bits; CMIS masks any
//! bit a host is not entitled to set ([`RiskFlags::HOST_SETTABLE`]).

use crate::format::BinaryFormat;
use crate::platform::Platform;
use crate::signer::SignerSummary;

/// The F19 §4.5 risk-flag bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RiskFlags(pub u32);

impl RiskFlags {
    /// Bit 0 (MIA): the file and every ancestor are writable only by
    /// administrators.
    pub const PATH_PROTECTED: u32 = 1 << 0;
    /// Bit 1 (MIA): a non-admin principal can replace the file.
    pub const USER_WRITABLE_PATH: u32 = 1 << 1;
    /// Bit 2 (MIA): the file or an ancestor is world-writable.
    pub const WORLD_WRITABLE: u32 = 1 << 2;
    /// Bit 3 (MIA): the path is under a temporary or download directory.
    pub const TEMP_DIR: u32 = 1 << 3;
    /// Bit 4 (MIA): UNC, NFS, SMB or FUSE mount.
    pub const NETWORK_PATH: u32 = 1 << 4;
    /// Bit 5 (appid): an interpreter; approving it permits any script.
    pub const INTERPRETER: u32 = 1 << 5;
    /// Bit 6 (appid): a Windows or macOS binary without a valid signature.
    pub const UNSIGNED: u32 = 1 << 6;
    /// Bit 7 (CMIS): the signer differs from the newest approved revision.
    pub const SIGNER_CHANGED: u32 = 1 << 7;
    /// Bit 8 (CMIS): the declared version exists with another hash.
    pub const VERSION_COLLISION: u32 = 1 << 8;
    /// Bit 9 (CMIS): the declared version is lower than the parent's.
    pub const VERSION_DOWNGRADE: u32 = 1 << 9;
    /// Bit 10 (CMIS): the hash was revoked in this lineage before.
    pub const HASH_PREVIOUSLY_REVOKED: u32 = 1 << 10;
    /// Bit 11 (CMIS): the hash was denied in this lineage before.
    pub const HASH_PREVIOUSLY_DENIED: u32 = 1 << 11;
    /// Bit 12 (MIA): the running image was replaced on disk.
    pub const DELETED_ON_DISK: u32 = 1 << 12;
    /// Bit 13 (MIA): the Linux caller hash was not cross-checked with IMA.
    pub const IMA_UNVERIFIED: u32 = 1 << 13;
    /// Bit 14 (CMIS): the host attested with the software host-key tier.
    pub const HOST_TIER_B: u32 = 1 << 14;

    /// Bits a host (MIA and `ferro-appid` on the host) may set; CMIS masks
    /// the rest of a submitted bitmask.
    pub const HOST_SETTABLE: u32 = Self::PATH_PROTECTED
        | Self::USER_WRITABLE_PATH
        | Self::WORLD_WRITABLE
        | Self::TEMP_DIR
        | Self::NETWORK_PATH
        | Self::INTERPRETER
        | Self::UNSIGNED
        | Self::DELETED_ON_DISK
        | Self::IMA_UNVERIFIED;

    /// Bits only CMIS sets.
    pub const CMIS_ONLY: u32 = Self::SIGNER_CHANGED
        | Self::VERSION_COLLISION
        | Self::VERSION_DOWNGRADE
        | Self::HASH_PREVIOUSLY_REVOKED
        | Self::HASH_PREVIOUSLY_DENIED
        | Self::HOST_TIER_B;

    /// Whether every bit of `mask` is set.
    #[must_use]
    pub const fn contains(self, mask: u32) -> bool {
        self.0 & mask == mask
    }

    /// The flags `ferro-appid` decides for a binary: `interpreter` from the
    /// file name, `unsigned` for a PE or Mach-O binary without a valid
    /// signature (no verifier result counts as not valid).
    #[must_use]
    pub fn from_binary(
        platform: Platform,
        canonical_path: &str,
        format: BinaryFormat,
        signer: Option<&SignerSummary>,
    ) -> Self {
        let mut bits = 0;
        if is_interpreter(basename(platform, canonical_path)) {
            bits |= Self::INTERPRETER;
        }
        if matches!(format, BinaryFormat::Pe | BinaryFormat::MachO)
            && !signer.is_some_and(|s| s.valid)
        {
            bits |= Self::UNSIGNED;
        }
        Self(bits)
    }
}

/// Interpreter names (F19 §4.5, plus `nodejs` and the common shells `dash`,
/// `ksh`, `csh`, `tcsh` and `fish`: flagging more only adds a warning). A
/// name also matches with a version suffix made of digits, dots and dashes
/// (`python3.12`, `ruby3.2`, `node20`), and `python` matches any suffix
/// (`pythonw`).
const INTERPRETERS: &[&str] = &[
    "node",
    "nodejs",
    "java",
    "javaw",
    "ruby",
    "perl",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
    "osascript",
    "wscript",
    "cscript",
    "php",
    "lua",
];

/// The file name of `path` on `platform`.
#[must_use]
pub fn basename(platform: Platform, path: &str) -> &str {
    let separators: &[char] = match platform {
        Platform::Windows => &['\\', '/'],
        Platform::Linux | Platform::MacOs => &['/'],
    };
    path.rsplit(separators).next().unwrap_or(path)
}

/// Whether a file name names a script interpreter (case-insensitive, an
/// `.exe` extension ignored).
#[must_use]
pub fn is_interpreter(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    let name = lower.strip_suffix(".exe").unwrap_or(&lower);
    if name.starts_with("python") {
        return true;
    }
    INTERPRETERS.iter().any(|base| {
        name.strip_prefix(base).is_some_and(|rest| {
            rest.chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SignerKind;

    #[test]
    fn interpreters_are_detected() {
        for name in [
            "python",
            "python3",
            "python3.12",
            "pythonw.exe",
            "node",
            "node20",
            "java",
            "javaw.exe",
            "ruby3.2",
            "perl5.36",
            "bash",
            "sh",
            "zsh",
            "pwsh.exe",
            "PowerShell.exe",
            "cmd.exe",
            "osascript",
            "wscript.exe",
            "cscript.exe",
            "php8.2",
            "lua5.4",
        ] {
            assert!(is_interpreter(name), "{name}");
        }
        for name in [
            "shutdown",
            "nodejs-helper",
            "javac",
            "luac",
            "tool",
            "bashful",
            "cmdx",
        ] {
            assert!(!is_interpreter(name), "{name}");
        }
    }

    #[test]
    fn appid_flags_follow_format_and_signer() {
        let valid = SignerSummary {
            kind: SignerKind::Authenticode,
            id: "ab".into(),
            subject: None,
            valid: true,
        };
        let invalid = SignerSummary {
            valid: false,
            ..valid.clone()
        };
        let pe =
            |s| RiskFlags::from_binary(Platform::Windows, r"C:\App\app.exe", BinaryFormat::Pe, s);
        assert_eq!(pe(Some(&valid)), RiskFlags(0));
        assert!(pe(Some(&invalid)).contains(RiskFlags::UNSIGNED));
        assert!(pe(None).contains(RiskFlags::UNSIGNED));
        let elf =
            RiskFlags::from_binary(Platform::Linux, "/usr/bin/python3", BinaryFormat::Elf, None);
        assert_eq!(elf, RiskFlags(RiskFlags::INTERPRETER));
        let win = RiskFlags::from_binary(
            Platform::Windows,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            BinaryFormat::Pe,
            Some(&valid),
        );
        assert_eq!(win, RiskFlags(RiskFlags::INTERPRETER));
    }

    #[test]
    fn bit_groups_partition_the_table() {
        assert_eq!(RiskFlags::HOST_SETTABLE & RiskFlags::CMIS_ONLY, 0);
        assert_eq!(
            RiskFlags::HOST_SETTABLE | RiskFlags::CMIS_ONLY,
            (1 << 15) - 1
        );
    }
}
