//! The trusted-publisher decision (ADR-0006 §3): pure, deterministic and
//! fail-closed. The OS verifier has already checked the signature, the chain
//! to a trusted root, revocation and the timestamp; this adds the
//! administrator's pins and the leaf validity window.

use crate::facts::SignerFacts;
use crate::model::PublisherRule;

/// Why no rule admitted a signer. Stable opcodes ([`Refusal::reason`]) for
/// the local log; the audit trail records the denial as `not-allowlisted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No trusted publisher is configured.
    NoRules,
    /// The leaf is outside its validity window and the signature carries no
    /// trusted timestamp.
    LeafExpired,
    /// No rule pins this signer.
    NoMatchingPublisher,
    /// A rule pins this signer, but its CA is not in the verified chain.
    WrongChain,
    /// A rule pins this signer and its chain, but requires a timestamp the
    /// signature does not carry.
    TimestampRequired,
    /// The only rules that pin this signer have expired.
    RuleExpired,
}

impl Refusal {
    /// Stable opcode.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoRules => "publisher-none-configured",
            Self::LeafExpired => "publisher-leaf-expired",
            Self::NoMatchingPublisher => "publisher-no-match",
            Self::WrongChain => "publisher-wrong-chain",
            Self::TimestampRequired => "publisher-timestamp-required",
            Self::RuleExpired => "publisher-rule-expired",
        }
    }
}

/// The first rule (in `rules` order) that admits `facts` at `now`.
///
/// A rule admits when it is unexpired, its kind is the signature's, its pin
/// equals the leaf's digest of that kind, its CA is in the chain above the
/// leaf, and its timestamp requirement holds. An expired leaf admits only
/// with a timestamp (the OS checked validity at signing time).
pub fn match_publisher<'a>(
    rules: &'a [PublisherRule],
    facts: &SignerFacts,
    now: i64,
) -> Result<&'a PublisherRule, Refusal> {
    if rules.is_empty() {
        return Err(Refusal::NoRules);
    }
    let in_window = facts.leaf.not_before <= now && now <= facts.leaf.not_after;
    if !in_window && !facts.timestamped {
        return Err(Refusal::LeafExpired);
    }
    let mut refusal = Refusal::NoMatchingPublisher;
    for rule in rules {
        if rule.kind != facts.kind || rule.pin != facts.leaf.pin(rule.pin_kind) {
            continue;
        }
        // From here the rule names this signer: keep the most specific
        // reason it did not admit.
        if rule.expires_at.is_some_and(|t| now >= t) {
            refusal = Refusal::RuleExpired;
            continue;
        }
        if !facts.chain_contains(&rule.anchor_sha256) {
            refusal = Refusal::WrongChain;
            continue;
        }
        if rule.require_timestamp && !facts.timestamped {
            refusal = Refusal::TimestampRequired;
            continue;
        }
        return Ok(rule);
    }
    Err(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::cert_facts;
    use crate::model::{PinKind, SignatureKind};
    use crate::testing::TestChain;

    /// 2026-01-01, inside the test chain's window.
    const NOW: i64 = 1_767_225_600;

    fn facts(chain: &TestChain, kind: SignatureKind, timestamped: bool) -> SignerFacts {
        SignerFacts::of(&chain.signature(kind, timestamped)).unwrap()
    }

    #[test]
    fn each_pin_kind_matches_its_own_signer() {
        let chain = TestChain::new("ACME Corp");
        let f = facts(&chain, SignatureKind::Authenticode, false);
        for pin in [
            PinKind::LeafCertSha256,
            PinKind::LeafSpkiSha256,
            PinKind::SubjectSha256,
        ] {
            let rules = [chain.rule(1, SignatureKind::Authenticode, pin)];
            assert_eq!(match_publisher(&rules, &f, NOW), Ok(&rules[0]), "{pin:?}");
        }
    }

    #[test]
    fn another_publisher_does_not_match() {
        let acme = TestChain::new("ACME Corp");
        let evil = TestChain::new("Evil Corp");
        let rules = [acme.rule(1, SignatureKind::Authenticode, PinKind::LeafSpkiSha256)];
        let f = facts(&evil, SignatureKind::Authenticode, false);
        assert_eq!(
            match_publisher(&rules, &f, NOW),
            Err(Refusal::NoMatchingPublisher)
        );
    }

    #[test]
    fn the_kind_must_match() {
        let chain = TestChain::new("ACME Corp");
        let rules = [chain.rule(1, SignatureKind::Apple, PinKind::LeafCertSha256)];
        let f = facts(&chain, SignatureKind::Authenticode, false);
        assert_eq!(
            match_publisher(&rules, &f, NOW),
            Err(Refusal::NoMatchingPublisher)
        );
    }

    /// Same leaf subject, but issued by a CA the rule does not pin: a
    /// look-alike certificate from another CA never matches.
    #[test]
    fn a_pinned_subject_under_the_wrong_chain_is_refused() {
        let real = TestChain::new("ACME Corp");
        let lookalike = TestChain::new("ACME Corp");
        let rules = [real.rule(1, SignatureKind::Authenticode, PinKind::SubjectSha256)];
        let f = facts(&lookalike, SignatureKind::Authenticode, true);
        assert_eq!(f.leaf.subject_sha256, rules[0].pin, "same subject DER");
        assert_eq!(match_publisher(&rules, &f, NOW), Err(Refusal::WrongChain));
    }

    #[test]
    fn an_expired_leaf_needs_a_timestamp() {
        let chain = TestChain::expired("ACME Corp");
        let rules = [chain.rule(1, SignatureKind::Apple, PinKind::LeafCertSha256)];
        let untimed = facts(&chain, SignatureKind::Apple, false);
        assert_eq!(
            match_publisher(&rules, &untimed, NOW),
            Err(Refusal::LeafExpired)
        );
        let timed = facts(&chain, SignatureKind::Apple, true);
        assert_eq!(match_publisher(&rules, &timed, NOW), Ok(&rules[0]));
        let leaf = cert_facts(&chain.leaf_der).unwrap();
        assert_eq!(
            match_publisher(&rules, &untimed, leaf.not_before - 1),
            Err(Refusal::LeafExpired),
            "not yet valid is outside the window too"
        );
    }

    #[test]
    fn a_rule_can_require_a_timestamp() {
        let chain = TestChain::new("ACME Corp");
        let mut rule = chain.rule(1, SignatureKind::Authenticode, PinKind::LeafSpkiSha256);
        rule.require_timestamp = true;
        let rules = [rule];
        let untimed = facts(&chain, SignatureKind::Authenticode, false);
        assert_eq!(
            match_publisher(&rules, &untimed, NOW),
            Err(Refusal::TimestampRequired)
        );
        let timed = facts(&chain, SignatureKind::Authenticode, true);
        assert_eq!(match_publisher(&rules, &timed, NOW), Ok(&rules[0]));
    }

    #[test]
    fn an_expired_rule_admits_nobody() {
        let chain = TestChain::new("ACME Corp");
        let mut rule = chain.rule(1, SignatureKind::Apple, PinKind::SubjectSha256);
        rule.expires_at = Some(NOW);
        let rules = [rule];
        let f = facts(&chain, SignatureKind::Apple, false);
        assert_eq!(match_publisher(&rules, &f, NOW), Err(Refusal::RuleExpired));
        assert_eq!(match_publisher(&rules, &f, NOW - 1), Ok(&rules[0]));
    }

    #[test]
    fn no_rules_is_the_old_behaviour() {
        let chain = TestChain::new("ACME Corp");
        let f = facts(&chain, SignatureKind::Apple, true);
        assert_eq!(match_publisher(&[], &f, NOW), Err(Refusal::NoRules));
    }

    #[test]
    fn the_first_admitting_rule_wins() {
        let chain = TestChain::new("ACME Corp");
        let mut expired = chain.rule(1, SignatureKind::Apple, PinKind::LeafCertSha256);
        expired.expires_at = Some(0);
        let good = chain.rule(2, SignatureKind::Apple, PinKind::SubjectSha256);
        let rules = [expired, good];
        let f = facts(&chain, SignatureKind::Apple, false);
        assert_eq!(
            match_publisher(&rules, &f, NOW).unwrap().publisher_id,
            [2; 16]
        );
    }
}
