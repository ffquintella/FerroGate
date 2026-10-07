//! Consent for installing the allowlist trust anchor, resolved **before** any
//! network traffic so a run that cannot consent never dials CMIS.
//!
//! In order of precedence:
//!
//! 1. `--expect-fingerprint <hex>` — the fetched key must have this
//!    fingerprint ([`Consent::Flag`]);
//! 2. `--yes` — accept the key fetched over the pinned channel without a
//!    comparison ([`Consent::Unverified`]; kept for `mia refresh-key` and the
//!    `mia-tray` action, not recommended);
//! 3. on a terminal, a prompt for the enrollment-key fingerprint — what
//!    `ferrogate enrollment-key` prints on CMIS — validated as it is typed
//!    ([`Consent::Prompted`]); the fetched key is then verified against it
//!    exactly as against the flag;
//! 4. otherwise the run fails closed: nothing is fetched or written. There is
//!    no trust-on-first-use path.

use inquire::validator::Validation;

/// The refusal for a non-interactive run with neither `--expect-fingerprint`
/// nor `--yes`.
pub const NO_CONSENT: &str = "no enrollment-key fingerprint to verify the fetched key against, \
     and no terminal to ask for one: pass --expect-fingerprint <hex> — the value `ferrogate \
     enrollment-key` prints on CMIS. Nothing was fetched or written";

/// How the operator agreed to install the fetched enrollment key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consent {
    /// `--expect-fingerprint`: install only a key with this normalised
    /// fingerprint.
    Flag(String),
    /// Typed at the prompt: install only a key with this normalised
    /// fingerprint.
    Prompted(String),
    /// `--yes`: install the key fetched over the pinned channel without a
    /// fingerprint comparison.
    Unverified,
}

impl Consent {
    /// The fingerprint the fetched key must have, if any.
    #[must_use]
    pub fn expected(&self) -> Option<&str> {
        match self {
            Self::Flag(fp) | Self::Prompted(fp) => Some(fp),
            Self::Unverified => None,
        }
    }

    /// Where the expected fingerprint came from, for the success line.
    #[must_use]
    pub fn source(&self) -> &'static str {
        match self {
            Self::Flag(_) => "--expect-fingerprint",
            Self::Prompted(_) => "the fingerprint you entered",
            Self::Unverified => "nothing (--yes)",
        }
    }
}

/// Decide how the install is consented to. `expect` is the already validated
/// `--expect-fingerprint`; `interactive` says whether a prompt can be shown;
/// `prompt` asks for the fingerprint and is called only when needed. The
/// prompt's answer is validated again here, whatever it came from.
///
/// # Errors
///
/// [`NO_CONSENT`] for a non-interactive run without `expect` or `yes`; the
/// prompt's error (an aborted prompt included); a malformed answer.
pub fn resolve(
    expect: Option<&str>,
    yes: bool,
    interactive: bool,
    prompt: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<Consent> {
    if let Some(fp) = expect {
        return Ok(Consent::Flag(fp.to_owned()));
    }
    if yes {
        return Ok(Consent::Unverified);
    }
    anyhow::ensure!(interactive, NO_CONSENT);
    let answer = prompt()?;
    let fp = super::normalize_fingerprint(&answer).map_err(|problem| {
        anyhow::anyhow!("the fingerprint {problem}; nothing was fetched or written")
    })?;
    Ok(Consent::Prompted(fp))
}

/// Whether standard input is a terminal a prompt can read from.
#[must_use]
pub fn stdin_is_terminal() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// Ask for the enrollment-key fingerprint on the terminal, re-asking until
/// the answer is a full hex SHA-384 fingerprint ([`validate`]).
///
/// # Errors
///
/// Esc / Ctrl-C (nothing is fetched or written), or a terminal error.
pub fn prompt_fingerprint() -> anyhow::Result<String> {
    println!(
        "\nThe enrollment key is verified against its fingerprint before it is installed.\n\
         Run `ferrogate enrollment-key` against CMIS and enter the value it prints."
    );
    let answer = inquire::Text::new("Enrollment-key fingerprint (SHA-384, 96 hex digits):")
        .with_help_message("Esc aborts — nothing is fetched or written")
        .with_validator(validate)
        .prompt();
    match answer {
        Ok(fp) => Ok(fp),
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => anyhow::bail!("no fingerprint entered; nothing was fetched or written"),
        Err(e) => Err(e.into()),
    }
}

/// The prompt's validator: valid only for a full hex SHA-384 fingerprint
/// (either case, surrounding whitespace ignored). The message never echoes
/// the input.
///
/// # Errors
///
/// Never; a bad answer is [`Validation::Invalid`].
pub fn validate(input: &str) -> Result<Validation, inquire::CustomUserError> {
    Ok(match super::normalize_fingerprint(input) {
        Ok(_) => Validation::Valid,
        Err(problem) => Validation::Invalid(format!("The fingerprint {problem}").into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use inquire::validator::ErrorMessage;

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef\
                      0123456789abcdef0123456789abcdef0123456789abcdef";

    fn no_prompt() -> anyhow::Result<String> {
        panic!("the prompt must not be shown")
    }

    #[test]
    fn the_flag_wins_and_yes_skips_the_prompt() {
        assert_eq!(
            resolve(Some(FP), true, true, no_prompt).unwrap(),
            Consent::Flag(FP.to_owned())
        );
        let yes = resolve(None, true, false, no_prompt).unwrap();
        assert_eq!(yes, Consent::Unverified);
        assert_eq!(yes.expected(), None);
    }

    #[test]
    fn a_non_interactive_run_without_the_flag_fails_closed_before_any_prompt() {
        let err = resolve(None, false, false, no_prompt).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--expect-fingerprint <hex>"), "{msg}");
        assert!(msg.contains("ferrogate enrollment-key"), "{msg}");
        assert!(msg.contains("Nothing was fetched or written"), "{msg}");
    }

    #[test]
    fn an_interactive_run_prompts_and_normalises_the_answer() {
        let got = resolve(None, false, true, || {
            Ok(format!("  {}\n", FP.to_ascii_uppercase()))
        })
        .unwrap();
        assert_eq!(got, Consent::Prompted(FP.to_owned()));
        assert_eq!(got.expected(), Some(FP));
    }

    #[test]
    fn a_malformed_or_aborted_prompt_answer_is_refused() {
        for bad in [
            "",
            "abc",
            &FP[..12],
            &format!("{}zz", &FP[..94]),
            &"a".repeat(500),
        ] {
            let bad = bad.to_owned();
            let err = resolve(None, false, true, || Ok(bad.clone())).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("nothing was fetched or written"), "{msg}");
            if !bad.is_empty() {
                assert!(!msg.contains(&bad), "never echoes the input: {msg}");
            }
        }
        let err = resolve(None, false, true, || anyhow::bail!("aborted")).unwrap_err();
        assert_eq!(err.to_string(), "aborted");
    }

    #[test]
    fn the_prompt_validator_rejects_malformed_fingerprints() {
        assert!(matches!(validate(FP).unwrap(), Validation::Valid));
        assert!(matches!(
            validate(&FP.to_ascii_uppercase()).unwrap(),
            Validation::Valid
        ));
        for bad in [
            "",
            "not-a-fingerprint",
            &FP[..95],
            &format!("{FP}0"),
            &format!("{}g", &FP[..95]),
            &format!("--expect-fingerprint {FP}"),
        ] {
            match validate(bad).unwrap() {
                Validation::Invalid(ErrorMessage::Custom(msg)) => {
                    assert!(msg.contains("96"), "{msg}");
                    assert!(bad.is_empty() || !msg.contains(bad), "no echo: {msg}");
                }
                other => panic!("accepted {bad:?}: {other:?}"),
            }
        }
    }
}
