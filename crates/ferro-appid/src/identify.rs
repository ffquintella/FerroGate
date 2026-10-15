//! Identify one binary from one open file (F19 §4.1).
//!
//! The caller opens the file once — for `RegisterSelf` the running image,
//! for `RegisterFile` the descriptor the client passed — and hands the open
//! file to [`identify`], which hashes it and reads its metadata through the
//! same handle, so the hash and the metadata describe the same file. The
//! file is only read; nothing is executed.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha384};

use crate::bytes::{Budget, ParseError, Source};
use crate::dpkg::DpkgDb;
use crate::flags::RiskFlags;
use crate::format::{detect_in, BinaryFormat};
use crate::limits::Limits;
use crate::platform::Platform;
use crate::signer::SignerSummary;
use crate::version::{
    clean, VersionInfo, VersionSource, MAX_BUNDLE_ID_CHARS, MAX_NAME_CHARS, MAX_VERSION_CHARS,
};
use crate::{elf, macho, pe, plist_bundle};

/// Which version sources to consult (`registration.version_sources`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one switch per F19 §4.3 source.
pub struct VersionSources {
    /// PE `VS_VERSIONINFO` (`"pe"`).
    pub pe: bool,
    /// Bundle `Info.plist` (`"plist"`).
    pub plist: bool,
    /// ELF `.note.package` (`"elf-note"`).
    pub elf_note: bool,
    /// dpkg database (`"dpkg"`).
    pub dpkg: bool,
}

impl Default for VersionSources {
    fn default() -> Self {
        Self {
            pe: true,
            plist: true,
            elf_note: true,
            dpkg: true,
        }
    }
}

/// How to identify a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyOptions {
    /// Platform the binary lives on (selects the external version sources).
    pub platform: Platform,
    /// Size, read, depth and time bounds.
    pub limits: Limits,
    /// Version sources to consult.
    pub sources: VersionSources,
    /// Root of the dpkg database.
    pub dpkg_root: PathBuf,
    /// Owner uid of the executable; a bundle `Info.plist` must be owned by
    /// it or by root.
    pub exe_owner: Option<u32>,
}

impl Default for IdentifyOptions {
    fn default() -> Self {
        Self {
            platform: Platform::current(),
            limits: Limits::default(),
            sources: VersionSources::default(),
            dpkg_root: PathBuf::from("/var/lib/dpkg"),
            exe_owner: None,
        }
    }
}

/// What identification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identification {
    /// SHA-384 of the file's bytes.
    pub sha384: [u8; 48],
    /// Bytes hashed.
    pub size: u64,
    /// Executable format.
    pub format: BinaryFormat,
    /// Declared version and display names (untrusted).
    pub version: VersionInfo,
    /// A signature is embedded (PE certificate table, Mach-O
    /// `LC_CODE_SIGNATURE` in every slice). Validity is the verifier's call.
    pub embedded_signature: bool,
    /// The flags `ferro-appid` decides (`interpreter`, `unsigned`).
    pub flags: RiskFlags,
    /// Why a metadata source failed, if one did ([`ParseError::kind`]).
    pub metadata_error: Option<&'static str>,
}

impl Identification {
    /// The hash as 96 lowercase hex characters (the ledger's `bin_sha`).
    #[must_use]
    pub fn sha384_hex(&self) -> String {
        hex::encode(self.sha384)
    }
}

/// Why identification failed outright. Metadata failures never fail it.
#[derive(Debug, thiserror::Error)]
pub enum IdentifyError {
    /// The file exceeds `max_file_size` (`file_too_large`).
    #[error("file_too_large")]
    FileTooLarge,
    /// Reading the file failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Hash `file` and read its metadata, from the same handle.
///
/// `canonical_path` is the path the OS resolved for the handle (§4.2); it
/// selects the bundle and dpkg lookups and the interpreter flag. `signer`
/// is the platform verifier's result, when there is one; a PE or Mach-O
/// binary without a valid signature is flagged `unsigned`.
pub fn identify<R: Read + Seek>(
    file: &mut R,
    canonical_path: &str,
    signer: Option<&SignerSummary>,
    opts: &IdentifyOptions,
) -> Result<Identification, IdentifyError> {
    let (sha384, size) = hash(file, opts.limits.max_file_size)?;
    let mut budget = Budget::new(&opts.limits);
    let mut src = Source::new(file, size, &mut budget);
    let mut meta = Metadata::default();
    let format = meta
        .note(detect_in(&mut src))
        .unwrap_or(BinaryFormat::Other);
    meta.collect(&mut src, format, canonical_path, opts);
    Ok(Identification {
        sha384,
        size,
        format,
        version: meta.version,
        embedded_signature: meta.embedded_signature,
        flags: RiskFlags::from_binary(opts.platform, canonical_path, format, signer),
        metadata_error: meta.error,
    })
}

/// Stream the file through SHA-384, refusing more than `max` bytes.
fn hash<R: Read + Seek>(file: &mut R, max: u64) -> Result<([u8; 48], u64), IdentifyError> {
    let len = file.seek(SeekFrom::End(0))?;
    if len > max {
        return Err(IdentifyError::FileTooLarge);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha384::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > max {
            return Err(IdentifyError::FileTooLarge);
        }
        hasher.update(&buf[..n]);
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&hasher.finalize());
    Ok((out, size))
}

/// Metadata gathered from the sources, first hit wins.
#[derive(Default)]
struct Metadata {
    version: VersionInfo,
    embedded_signature: bool,
    error: Option<&'static str>,
}

impl Metadata {
    fn note<T>(&mut self, r: Result<T, ParseError>) -> Option<T> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                self.error.get_or_insert(e.kind());
                None
            }
        }
    }

    fn set_version(&mut self, raw: Option<&str>, source: VersionSource) {
        if self.version.declared_version.is_some() {
            return;
        }
        if let Some(v) = raw.and_then(|v| clean(v, MAX_VERSION_CHARS)) {
            self.version.declared_version = Some(v);
            self.version.source = source;
        }
    }

    fn set_name(slot: &mut Option<String>, raw: Option<&str>, max: usize) {
        if slot.is_none() {
            *slot = raw.and_then(|v| clean(v, max));
        }
    }

    /// Consult the sources in the F19 §4.3 order. A failing source
    /// contributes nothing; the next one is still tried.
    fn collect<R: Read + Seek>(
        &mut self,
        src: &mut Source<'_, R>,
        format: BinaryFormat,
        canonical_path: &str,
        opts: &IdentifyOptions,
    ) {
        match format {
            BinaryFormat::Pe => {
                if let Some(facts) = self.note(pe::facts(src)) {
                    self.embedded_signature = facts.has_certificate_table;
                    if let (true, Some(v)) = (opts.sources.pe, facts.version) {
                        let string = v.product_version.as_deref().or(v.file_version.as_deref());
                        self.set_version(string, VersionSource::PeString);
                        self.set_version(
                            v.fixed_product_version.as_deref(),
                            VersionSource::PeFixed,
                        );
                        Self::set_name(
                            &mut self.version.product_name,
                            v.product_name.as_deref(),
                            MAX_NAME_CHARS,
                        );
                        Self::set_name(
                            &mut self.version.company_name,
                            v.company_name.as_deref(),
                            MAX_NAME_CHARS,
                        );
                    }
                }
            }
            BinaryFormat::MachO => {
                if let Some(signed) = self.note(macho::has_code_signature(src)) {
                    self.embedded_signature = signed;
                }
            }
            BinaryFormat::Elf | BinaryFormat::Other => {}
        }
        if opts.sources.plist && opts.platform == Platform::MacOs {
            let r = plist_bundle::read_within(
                Path::new(canonical_path),
                src.budget,
                opts.limits.max_metadata_bytes,
                opts.exe_owner,
            );
            if let Some(Some(b)) = self.note(r) {
                self.set_version(b.short_version.as_deref(), VersionSource::PlistShort);
                self.set_version(b.bundle_version.as_deref(), VersionSource::PlistBundle);
                Self::set_name(
                    &mut self.version.product_name,
                    b.name.as_deref(),
                    MAX_NAME_CHARS,
                );
                Self::set_name(
                    &mut self.version.bundle_id,
                    b.identifier.as_deref(),
                    MAX_BUNDLE_ID_CHARS,
                );
            }
        }
        if opts.sources.elf_note && format == BinaryFormat::Elf {
            if let Some(Some(note)) = self.note(elf::package_note(src)) {
                self.set_version(note.version.as_deref(), VersionSource::ElfNotePackage);
                Self::set_name(
                    &mut self.version.package_name,
                    note.name.as_deref(),
                    MAX_NAME_CHARS,
                );
            }
        }
        if opts.sources.dpkg
            && opts.platform == Platform::Linux
            && self.version.declared_version.is_none()
        {
            let db = DpkgDb::new(&opts.dpkg_root);
            if let Some(Some(pkg)) = self.note(db.package_within(canonical_path, src.budget)) {
                self.set_version(Some(&pkg.version), VersionSource::Dpkg);
                Self::set_name(
                    &mut self.version.package_name,
                    Some(&pkg.name),
                    MAX_NAME_CHARS,
                );
            }
        }
    }
}
