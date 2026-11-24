//! macOS verifier: the Apple code signature of a running caller, checked by
//! the kernel-tracked code identity of its PID (ADR-0006 §4).

//! `SecCodeCheckValidity` validates the *running* code (dynamic validity) as
//! well as its on-disk signature, under the requirement
//! `anchor apple generic` (an Apple-rooted chain: Developer ID, App Store or
//! Apple). The chain and the timestamp then come from
//! `SecCodeCopySigningInformation`, the one call `security-framework` does
//! not wrap, declared below.

#![allow(unsafe_code)] // source: ADR-0006 §4 (one Security.framework call)

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::CFURL;
use security_framework::certificate::SecCertificate;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};

use crate::model::SignatureKind;
use crate::verifier::{
    same_image, CallerTarget, SignatureVerifier, VerifiedSignature, VerifyError,
};

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoCertificates: CFStringRef;
    static kSecCodeInfoTimestamp: CFStringRef;
}

/// `kSecCSSigningInformation`: include the certificate chain.
const SIGNING_INFORMATION: u32 = 1 << 1;
/// Apple-rooted chains only; the rule's CA pin narrows further.
const REQUIREMENT: &str = "anchor apple generic";

/// `errSecCSUnsigned`.
const UNSIGNED: i32 = -67062;
/// `errSecCSNoSuchCode` (the process is gone).
const NO_SUCH_CODE: i32 = -67065;
/// `errSecCSStaticCodeNotFound`.
const STATIC_CODE_NOT_FOUND: i32 = -67068;
/// `errSecCSStaticCodeChanged`.
const STATIC_CODE_CHANGED: i32 = -67034;
/// `errSecCertificateRevoked`.
const CERT_REVOKED: i32 = -67820;
/// `errSecCertificateExpired`.
const CERT_EXPIRED: i32 = -67818;

fn map_status(status: i32) -> VerifyError {
    match status {
        UNSIGNED => VerifyError::Unsigned,
        NO_SUCH_CODE | STATIC_CODE_NOT_FOUND => VerifyError::Unreadable,
        STATIC_CODE_CHANGED => VerifyError::ImageChanged,
        CERT_REVOKED => VerifyError::Revoked,
        CERT_EXPIRED => VerifyError::Expired,
        _ => VerifyError::Untrusted,
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // used as `map_err(|e| map_err(&e))`
fn map_err(e: &security_framework::base::Error) -> VerifyError {
    map_status(e.code())
}

/// The production macOS verifier.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MacVerifier;

impl SignatureVerifier for MacVerifier {
    fn verify_caller(&self, target: &CallerTarget<'_>) -> Result<VerifiedSignature, VerifyError> {
        let exe = target.exe_path.ok_or(VerifyError::Unreadable)?;
        let pid = i32::try_from(target.pid).map_err(|_| VerifyError::Unreadable)?;
        let requirement: SecRequirement = REQUIREMENT.parse().map_err(|e| map_err(&e))?;

        let mut attrs = GuestAttributes::new();
        attrs.set_pid(pid);
        let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
            .map_err(|e| map_err(&e))?;
        code.check_validity(Flags::NONE, &requirement)
            .map_err(|e| map_err(&e))?;

        // The validated code must be the image the caller was identified by:
        // its path is the executable or the bundle holding it, and the bytes
        // at the executable path still hash to `bin_sha`.
        let code_path = code
            .path(Flags::NONE)
            .ok()
            .and_then(|u| u.to_path())
            .ok_or(VerifyError::Unreadable)?;
        if !same_or_inside(&canonical(&code_path), &canonical(Path::new(exe))) {
            return Err(VerifyError::ImageChanged);
        }
        let mut file = std::fs::File::open(exe).map_err(|_| VerifyError::Unreadable)?;
        same_image(&mut file, target.bin_sha)?;

        signing_information(code.as_concrete_TypeRef().cast::<c_void>())
    }

    fn verify_file(&self, path: &Path) -> Result<VerifiedSignature, VerifyError> {
        let requirement: SecRequirement = REQUIREMENT.parse().map_err(|e| map_err(&e))?;
        let url = CFURL::from_path(path, false).ok_or(VerifyError::Unreadable)?;
        let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(|e| map_err(&e))?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::CHECK_ALL_ARCHITECTURES,
            &requirement,
        )
        .map_err(|e| map_err(&e))?;
        signing_information(code.as_concrete_TypeRef().cast::<c_void>())
    }
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// `exe` is `code` itself or a file inside the bundle directory `code`.
fn same_or_inside(code: &Path, exe: &Path) -> bool {
    exe == code || exe.starts_with(code)
}

/// The certificate chain and timestamp of a validated code object.
fn signing_information(code: *const c_void) -> Result<VerifiedSignature, VerifyError> {
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `code` is a live SecCodeRef or SecStaticCodeRef owned by the
    // caller for the duration of this call; `info` is a valid out-pointer.
    let status = unsafe {
        SecCodeCopySigningInformation(code, SIGNING_INFORMATION, std::ptr::from_mut(&mut info))
    };
    if status != 0 || info.is_null() {
        return Err(map_status(status));
    }
    // SAFETY: on success the call returned a +1 CFDictionary we now own.
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    // SAFETY: framework constants, valid for the life of the process.
    let (certs_key, ts_key) = unsafe {
        (
            CFString::wrap_under_get_rule(kSecCodeInfoCertificates),
            CFString::wrap_under_get_rule(kSecCodeInfoTimestamp),
        )
    };
    let timestamped = info.find(&ts_key).is_some();
    let certs = info
        .find(&certs_key)
        .and_then(|v| v.downcast::<CFArray>())
        .ok_or(VerifyError::Unsigned)?;
    let mut chain_der = Vec::with_capacity(usize::try_from(certs.len()).unwrap_or(0));
    for item in certs.iter() {
        // SAFETY: the array is retained by `certs`; the item is a borrowed
        // CF object we retain through `wrap_under_get_rule`.
        let any = unsafe { CFType::wrap_under_get_rule(*item) };
        let cert = any
            .downcast::<SecCertificate>()
            .ok_or(VerifyError::Untrusted)?;
        chain_der.push(cert.to_der());
    }
    if chain_der.is_empty() {
        return Err(VerifyError::Unsigned);
    }
    Ok(VerifiedSignature {
        kind: SignatureKind::Apple,
        chain_der,
        timestamped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::SignerFacts;

    #[test]
    fn statuses_map_to_fail_closed_reasons() {
        assert_eq!(map_status(UNSIGNED), VerifyError::Unsigned);
        assert_eq!(map_status(CERT_REVOKED), VerifyError::Revoked);
        assert_eq!(map_status(-67050), VerifyError::Untrusted);
        assert!(same_or_inside(
            Path::new("/Applications/A.app"),
            Path::new("/Applications/A.app/Contents/MacOS/A")
        ));
        assert!(!same_or_inside(
            Path::new("/usr/bin/a"),
            Path::new("/usr/bin/ab")
        ));
    }

    /// A real Apple-signed platform binary, verified by the PID of a running
    /// copy: the chain is Apple-rooted and parses.
    #[test]
    fn a_running_platform_binary_verifies_with_its_chain() {
        use sha2::{Digest as _, Sha384};
        let exe = "/bin/sleep";
        let mut child = std::process::Command::new(exe).arg("5").spawn().unwrap();
        let sha: [u8; 48] = Sha384::digest(std::fs::read(exe).unwrap()).into();
        let canonical_exe = canonical(Path::new(exe));
        let target = CallerTarget {
            pid: child.id(),
            exe_path: canonical_exe.to_str(),
            bin_sha: &sha,
        };
        let got = MacVerifier.verify_caller(&target);
        let _ = child.kill();
        let _ = child.wait();
        let sig = got.unwrap();
        assert_eq!(sig.kind, SignatureKind::Apple);
        let facts = SignerFacts::of(&sig).unwrap();
        assert!(
            !facts.issuers.is_empty(),
            "Apple-rooted chain above the leaf"
        );

        let wrong = [0u8; 48];
        let mut child = std::process::Command::new(exe).arg("5").spawn().unwrap();
        let swapped = CallerTarget {
            pid: child.id(),
            exe_path: canonical_exe.to_str(),
            bin_sha: &wrong,
        };
        let got = MacVerifier.verify_caller(&swapped);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(got, Err(VerifyError::ImageChanged));
    }

    #[test]
    fn an_unsigned_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("ferro-codesign-mac-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not-code");
        std::fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
        let got = MacVerifier.verify_file(&path);
        let _ = std::fs::remove_dir_all(dir);
        assert!(
            matches!(got, Err(VerifyError::Unsigned | VerifyError::Untrusted)),
            "{got:?}"
        );
    }
}
