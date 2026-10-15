//! dpkg package version (F19 §4.3, version source 6).
//!
//! The owning package is found in `/var/lib/dpkg/info/*.list` (one installed
//! path per line), and its version in `/var/lib/dpkg/status`. Both are read
//! as files, line by line and bounded in size and time; `dpkg-query` is
//! never spawned. On merged-`/usr` systems a package may list `/bin/x` for
//! the canonical `/usr/bin/x`, so that alias is tried as well.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::bytes::{Budget, ParseError};
use crate::limits::Limits;

/// Most `.list` files examined.
const MAX_LIST_FILES: usize = 50_000;
/// Largest `.list` file read.
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
/// Largest `status` file read (streamed, never held in memory).
const MAX_STATUS_BYTES: u64 = 256 * 1024 * 1024;
/// Longest line accepted in either file.
const MAX_LINE: usize = 64 * 1024;

/// A dpkg database rooted at a directory (normally `/var/lib/dpkg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpkgDb {
    root: PathBuf,
}

/// The package that owns a path, and its installed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpkgPackage {
    /// Package name (without architecture qualifier).
    pub name: String,
    /// Installed version.
    pub version: String,
}

impl Default for DpkgDb {
    fn default() -> Self {
        Self::new("/var/lib/dpkg")
    }
}

impl DpkgDb {
    /// A database rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The installed package owning `path`, if any.
    pub fn package_of(
        &self,
        path: &str,
        limits: &Limits,
    ) -> Result<Option<DpkgPackage>, ParseError> {
        self.package_within(path, &Budget::new(limits))
    }

    pub(crate) fn package_within(
        &self,
        path: &str,
        budget: &Budget,
    ) -> Result<Option<DpkgPackage>, ParseError> {
        let Some((name, arch)) = self.owner(path, budget)? else {
            return Ok(None);
        };
        let version = self.installed_version(&name, arch.as_deref(), budget)?;
        Ok(version.map(|version| DpkgPackage { name, version }))
    }

    /// Find the `.list` file naming `path`; returns `(package, arch)`.
    fn owner(
        &self,
        path: &str,
        budget: &Budget,
    ) -> Result<Option<(String, Option<String>)>, ParseError> {
        let candidates = candidates(path);
        let dir = match std::fs::read_dir(self.root.join("info")) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        for (n, entry) in dir.enumerate() {
            if n >= MAX_LIST_FILES {
                return Err(ParseError::TooMuchData);
            }
            budget.check_time()?;
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(stem) = file_name.to_str().and_then(|f| f.strip_suffix(".list")) else {
                continue;
            };
            if lists_path(&entry.path(), &candidates, budget)? {
                let (name, arch) = match stem.split_once(':') {
                    Some((name, arch)) => (name.to_string(), Some(arch.to_string())),
                    None => (stem.to_string(), None),
                };
                return Ok(Some((name, arch)));
            }
        }
        Ok(None)
    }

    /// The `Version:` of the installed stanza of `name` (and `arch`).
    fn installed_version(
        &self,
        name: &str,
        arch: Option<&str>,
        budget: &Budget,
    ) -> Result<Option<String>, ParseError> {
        let file = match File::open(self.root.join("status")) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut reader = BufReader::new(file.take(MAX_STATUS_BYTES));
        let mut stanza = Stanza::default();
        let mut line = Vec::new();
        let mut lines = 0usize;
        loop {
            if !read_line(&mut reader, &mut line)? {
                return Ok(stanza.matching(name, arch));
            }
            lines += 1;
            if lines.is_multiple_of(4096) {
                budget.check_time()?;
            }
            if line.is_empty() {
                if let Some(v) = stanza.matching(name, arch) {
                    return Ok(Some(v));
                }
                stanza = Stanza::default();
                continue;
            }
            let text = String::from_utf8_lossy(&line);
            if let Some((field, value)) = text.split_once(':') {
                let value = value.trim().to_string();
                match field {
                    "Package" => stanza.package = Some(value),
                    "Architecture" => stanza.arch = Some(value),
                    "Status" => stanza.status = Some(value),
                    "Version" => stanza.version = Some(value),
                    _ => {}
                }
            }
        }
    }
}

#[derive(Default)]
struct Stanza {
    package: Option<String>,
    arch: Option<String>,
    status: Option<String>,
    version: Option<String>,
}

impl Stanza {
    fn matching(&self, name: &str, arch: Option<&str>) -> Option<String> {
        let installed = self
            .status
            .as_deref()
            .is_some_and(|s| s.ends_with(" installed"));
        let arch_ok = arch.is_none_or(|a| self.arch.as_deref() == Some(a));
        (self.package.as_deref() == Some(name) && installed && arch_ok)
            .then(|| self.version.clone())
            .flatten()
    }
}

/// `path` and, on merged-`/usr` systems, its `/bin`, `/sbin`, `/lib*` alias.
fn candidates(path: &str) -> Vec<Vec<u8>> {
    let mut out = vec![path.as_bytes().to_vec()];
    if let Some(rest) = path.strip_prefix("/usr") {
        if ["/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"]
            .iter()
            .any(|d| rest.starts_with(d))
        {
            out.push(rest.as_bytes().to_vec());
        }
    }
    out
}

/// Whether the `.list` file at `list` contains one of `candidates` as a line.
fn lists_path(list: &Path, candidates: &[Vec<u8>], budget: &Budget) -> Result<bool, ParseError> {
    let file = File::open(list)?;
    if file.metadata()?.len() > MAX_LIST_BYTES {
        return Ok(false);
    }
    let mut reader = BufReader::new(file.take(MAX_LIST_BYTES));
    let mut line = Vec::new();
    let mut lines = 0usize;
    while read_line(&mut reader, &mut line)? {
        lines += 1;
        if lines.is_multiple_of(4096) {
            budget.check_time()?;
        }
        if candidates.contains(&line) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read one line (without its newline) into `line`; `false` at the end.
fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Result<bool, ParseError> {
    line.clear();
    let n = reader
        .by_ref()
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', line)?;
    if n == 0 {
        return Ok(false);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > MAX_LINE {
        return Err(ParseError::Malformed("dpkg line too long"));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_usr_aliases_are_tried() {
        assert_eq!(
            candidates("/usr/bin/tool"),
            vec![b"/usr/bin/tool".to_vec(), b"/bin/tool".to_vec()]
        );
        assert_eq!(candidates("/opt/tool"), vec![b"/opt/tool".to_vec()]);
        assert_eq!(candidates("/usr/share/x").len(), 1);
    }

    #[test]
    fn overlong_lines_are_refused() {
        let data = vec![b'a'; MAX_LINE + 10];
        let mut r = std::io::Cursor::new(data);
        let mut line = Vec::new();
        assert!(read_line(&mut r, &mut line).is_err());
    }
}
