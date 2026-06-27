//! Non-secret Daylight Equation model helpers.
//!
//! This crate intentionally avoids cryptographic operations. It models only
//! public constants and arithmetic from the corrected Daylight equation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Research,
    Proof,
    Open,
    Release,
    Install,
    RootRotate,
    AuditAccept,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Mode {
    Compact,
    Hybrid,
    PqStrict,
}

impl Mode {
    pub const fn order(self) -> u8 {
        match self {
            Mode::Compact => 0,
            Mode::Hybrid => 1,
            Mode::PqStrict => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim {
    Research,
    Proof,
    OpenEvidence,
    ReleaseCandidate,
    InstallEvidence,
    HybridEvidence,
    RootCeremony,
    AuditEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthPrimitive {
    Q,
    H,
    F,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    D2Hybrid,
    D3Root,
    D2HybridFrost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdProfile {
    pub signer_count: u8,
    pub signer_threshold: u8,
    pub domain_threshold: u8,
    pub pq_signer_count: u8,
    pub pq_signer_threshold: u8,
    pub pq_domain_threshold: u8,
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityStrengthVector {
    pub pq_kem_category: u8,
    pub pq_sig_category: u8,
    pub classical_dh_bits_max: u16,
    pub aead_conf_bits_approx: u16,
    pub aead_int_bits_max: u16,
    pub min_scalar_bits: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModeState {
    pub release_level: u8,
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DowngradePolicy {
    pub candidate: ModeState,
    pub minimum: ModeState,
    pub previous: Option<ModeState>,
    pub action: Action,
    pub suite_id_matches_hash: bool,
    pub suite_allowed: bool,
    pub suite_revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    UnsupportedReleaseLevel,
    InvalidThreshold,
    InvalidMode,
}

pub const RELEASE_LEVEL_MIN: u8 = 0;
pub const RELEASE_LEVEL_MAX: u8 = 3;

pub const DAYLIGHT_SECURITY_STRENGTH: SecurityStrengthVector = SecurityStrengthVector {
    pq_kem_category: 5,
    pq_sig_category: 5,
    classical_dh_bits_max: 192,
    aead_conf_bits_approx: 256,
    aead_int_bits_max: 128,
    min_scalar_bits: 128,
};

pub fn actions_for_release_level(release_level: u8) -> Result<&'static [Action], ModelError> {
    match release_level {
        0 => Ok(&[Action::Research, Action::Proof]),
        1 => Ok(&[Action::Research, Action::Proof, Action::Open]),
        2 => Ok(&[
            Action::Research,
            Action::Proof,
            Action::Open,
            Action::Release,
            Action::Install,
        ]),
        3 => Ok(&[
            Action::Research,
            Action::Proof,
            Action::Open,
            Action::Release,
            Action::Install,
            Action::RootRotate,
            Action::AuditAccept,
        ]),
        _ => Err(ModelError::UnsupportedReleaseLevel),
    }
}

pub fn action_allowed(release_level: u8, action: Action) -> Result<bool, ModelError> {
    Ok(actions_for_release_level(release_level)?.contains(&action))
}

pub fn threshold_profile(release_level: u8) -> Result<ThresholdProfile, ModelError> {
    match release_level {
        0 => Ok(ThresholdProfile {
            signer_count: 3,
            signer_threshold: 2,
            domain_threshold: 2,
            pq_signer_count: 3,
            pq_signer_threshold: 2,
            pq_domain_threshold: 2,
            mode: Mode::Compact,
        }),
        1 | 2 => Ok(ThresholdProfile {
            signer_count: 5,
            signer_threshold: 3,
            domain_threshold: 3,
            pq_signer_count: 5,
            pq_signer_threshold: 3,
            pq_domain_threshold: 3,
            mode: Mode::Hybrid,
        }),
        3 => Ok(ThresholdProfile {
            signer_count: 5,
            signer_threshold: 4,
            domain_threshold: 4,
            pq_signer_count: 5,
            pq_signer_threshold: 4,
            pq_domain_threshold: 4,
            mode: Mode::PqStrict,
        }),
        _ => Err(ModelError::UnsupportedReleaseLevel),
    }
}

pub fn claims_for_release_level(release_level: u8) -> Result<&'static [Claim], ModelError> {
    match release_level {
        0 => Ok(&[Claim::Research, Claim::Proof]),
        1 => Ok(&[Claim::Research, Claim::Proof, Claim::OpenEvidence]),
        2 => Ok(&[
            Claim::Research,
            Claim::Proof,
            Claim::OpenEvidence,
            Claim::ReleaseCandidate,
            Claim::InstallEvidence,
            Claim::HybridEvidence,
        ]),
        3 => Ok(&[
            Claim::Research,
            Claim::Proof,
            Claim::OpenEvidence,
            Claim::ReleaseCandidate,
            Claim::InstallEvidence,
            Claim::HybridEvidence,
            Claim::RootCeremony,
            Claim::AuditEvidence,
        ]),
        _ => Err(ModelError::UnsupportedReleaseLevel),
    }
}

pub fn claim_allowed(release_level: u8, claim: Claim) -> Result<bool, ModelError> {
    Ok(claims_for_release_level(release_level)?.contains(&claim))
}

pub fn required_auth_primitives(
    profile: Profile,
    release_level: u8,
    mode: Mode,
    _action: Action,
) -> Result<&'static [AuthPrimitive], ModelError> {
    ensure_release_level(release_level)?;
    match profile {
        Profile::D2Hybrid => match (release_level, mode) {
            (_, Mode::Compact) => Err(ModelError::InvalidMode),
            (0..=2, Mode::Hybrid) => Ok(&[AuthPrimitive::Q]),
            (0..=2, Mode::PqStrict) => Ok(&[AuthPrimitive::Q, AuthPrimitive::H]),
            (3, Mode::Hybrid | Mode::PqStrict) => Ok(&[AuthPrimitive::Q, AuthPrimitive::H]),
            _ => Err(ModelError::InvalidMode),
        },
        Profile::D3Root => match mode {
            Mode::Compact => Err(ModelError::InvalidMode),
            Mode::Hybrid | Mode::PqStrict => Ok(&[AuthPrimitive::Q, AuthPrimitive::H]),
        },
        Profile::D2HybridFrost => match (release_level, mode) {
            (_, Mode::Compact) => Err(ModelError::InvalidMode),
            (0..=2, Mode::Hybrid) => Ok(&[AuthPrimitive::Q, AuthPrimitive::F]),
            (3, Mode::Hybrid | Mode::PqStrict) => {
                Ok(&[AuthPrimitive::Q, AuthPrimitive::H, AuthPrimitive::F])
            }
            _ => Err(ModelError::InvalidMode),
        },
    }
}

pub fn mode_ok(
    profile: Profile,
    release_level: u8,
    mode: Mode,
    action: Action,
) -> Result<bool, ModelError> {
    Ok(
        required_auth_primitives(profile, release_level, mode, action).is_ok()
            && action_allowed(release_level, action)?,
    )
}

pub fn no_downgrade(policy: DowngradePolicy) -> Result<bool, ModelError> {
    ensure_release_level(policy.candidate.release_level)?;
    ensure_release_level(policy.minimum.release_level)?;
    if let Some(previous) = policy.previous {
        ensure_release_level(previous.release_level)?;
    }

    if !policy.suite_id_matches_hash || !policy.suite_allowed || policy.suite_revoked {
        return Ok(false);
    }
    if policy.candidate.release_level < policy.minimum.release_level {
        return Ok(false);
    }
    if policy.candidate.mode.order() < policy.minimum.mode.order() {
        return Ok(false);
    }

    if let Some(previous) = policy.previous {
        if policy.action == Action::RootRotate {
            return Ok(true);
        }
        if policy.candidate.release_level < previous.release_level {
            return Ok(false);
        }
        if policy.candidate.mode.order() < previous.mode.order() {
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn at_least_threshold_probability(
    n: u8,
    t: u8,
    per_member_probability: f64,
) -> Result<f64, ModelError> {
    if t == 0 || t > n {
        return Err(ModelError::InvalidThreshold);
    }
    if !(0.0..=1.0).contains(&per_member_probability) {
        return Err(ModelError::InvalidThreshold);
    }

    let p = per_member_probability;
    let mut total = 0.0;
    for i in t..=n {
        total += binomial(n, i) as f64 * p.powi(i as i32) * (1.0 - p).powi((n - i) as i32);
    }
    Ok(total)
}

pub fn authorization_probability(
    n: u8,
    t: u8,
    signer_availability: f64,
) -> Result<f64, ModelError> {
    at_least_threshold_probability(n, t, signer_availability)
}

pub fn compromise_probability(n: u8, t: u8, signer_compromise: f64) -> Result<f64, ModelError> {
    at_least_threshold_probability(n, t, signer_compromise)
}

pub fn correlated_break_upper_bound(
    iid_break_probability: f64,
    correlated_break_allowance: f64,
) -> Result<f64, ModelError> {
    if !(0.0..=1.0).contains(&iid_break_probability)
        || !(0.0..=1.0).contains(&correlated_break_allowance)
        || correlated_break_allowance > 1.0 - iid_break_probability
    {
        return Err(ModelError::InvalidThreshold);
    }
    Ok(iid_break_probability + correlated_break_allowance)
}

fn ensure_release_level(release_level: u8) -> Result<(), ModelError> {
    if (RELEASE_LEVEL_MIN..=RELEASE_LEVEL_MAX).contains(&release_level) {
        Ok(())
    } else {
        Err(ModelError::UnsupportedReleaseLevel)
    }
}

fn binomial(n: u8, k: u8) -> u64 {
    if k > n {
        return 0;
    }

    let k = k.min(n - k);
    let mut result = 1u64;
    for i in 1..=k {
        result = result * u64::from(n + 1 - i) / u64::from(i);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 0.000000000001;

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= EPSILON,
            "actual={actual}, expected={expected}"
        );
    }

    #[test]
    fn release_level_action_sets_match_v04_spec() {
        assert!(action_allowed(0, Action::Research).unwrap());
        assert!(action_allowed(0, Action::Proof).unwrap());
        assert!(!action_allowed(0, Action::Open).unwrap());
        assert!(!action_allowed(0, Action::Install).unwrap());

        assert!(action_allowed(1, Action::Open).unwrap());
        assert!(!action_allowed(1, Action::Install).unwrap());
        assert!(action_allowed(2, Action::Install).unwrap());
        assert!(!action_allowed(2, Action::RootRotate).unwrap());

        assert!(action_allowed(3, Action::RootRotate).unwrap());
        assert!(action_allowed(3, Action::AuditAccept).unwrap());
        assert_eq!(
            action_allowed(4, Action::Open),
            Err(ModelError::UnsupportedReleaseLevel)
        );
    }

    #[test]
    fn threshold_profiles_use_separate_signer_and_domain_thresholds() {
        assert_eq!(
            threshold_profile(0).unwrap(),
            ThresholdProfile {
                signer_count: 3,
                signer_threshold: 2,
                domain_threshold: 2,
                pq_signer_count: 3,
                pq_signer_threshold: 2,
                pq_domain_threshold: 2,
                mode: Mode::Compact,
            }
        );
        assert_eq!(
            threshold_profile(2).unwrap(),
            ThresholdProfile {
                signer_count: 5,
                signer_threshold: 3,
                domain_threshold: 3,
                pq_signer_count: 5,
                pq_signer_threshold: 3,
                pq_domain_threshold: 3,
                mode: Mode::Hybrid,
            }
        );
        assert_eq!(
            threshold_profile(3).unwrap(),
            ThresholdProfile {
                signer_count: 5,
                signer_threshold: 4,
                domain_threshold: 4,
                pq_signer_count: 5,
                pq_signer_threshold: 4,
                pq_domain_threshold: 4,
                mode: Mode::PqStrict,
            }
        );
    }

    #[test]
    fn claims_are_monotonic_by_release_level() {
        assert!(claim_allowed(0, Claim::Research).unwrap());
        assert!(claim_allowed(0, Claim::Proof).unwrap());
        assert!(!claim_allowed(0, Claim::ReleaseCandidate).unwrap());

        assert!(claim_allowed(1, Claim::OpenEvidence).unwrap());
        assert!(!claim_allowed(1, Claim::ReleaseCandidate).unwrap());
        assert!(!claim_allowed(1, Claim::HybridEvidence).unwrap());

        assert!(claim_allowed(2, Claim::ReleaseCandidate).unwrap());
        assert!(claim_allowed(2, Claim::InstallEvidence).unwrap());
        assert!(claim_allowed(2, Claim::HybridEvidence).unwrap());
        assert!(!claim_allowed(2, Claim::RootCeremony).unwrap());

        assert!(claim_allowed(3, Claim::RootCeremony).unwrap());
        assert!(claim_allowed(3, Claim::AuditEvidence).unwrap());
    }

    #[test]
    fn profile_requirement_sets_follow_v04_core() {
        assert_eq!(
            required_auth_primitives(Profile::D2Hybrid, 2, Mode::Hybrid, Action::Release).unwrap(),
            &[AuthPrimitive::Q]
        );
        assert_eq!(
            required_auth_primitives(Profile::D2Hybrid, 2, Mode::PqStrict, Action::Release)
                .unwrap(),
            &[AuthPrimitive::Q, AuthPrimitive::H]
        );
        assert_eq!(
            required_auth_primitives(Profile::D3Root, 3, Mode::Hybrid, Action::RootRotate).unwrap(),
            &[AuthPrimitive::Q, AuthPrimitive::H]
        );
        assert_eq!(
            required_auth_primitives(
                Profile::D2HybridFrost,
                3,
                Mode::PqStrict,
                Action::RootRotate
            )
            .unwrap(),
            &[AuthPrimitive::Q, AuthPrimitive::H, AuthPrimitive::F]
        );
        assert_eq!(
            required_auth_primitives(Profile::D2Hybrid, 2, Mode::Compact, Action::Release),
            Err(ModelError::InvalidMode)
        );
        assert_eq!(
            required_auth_primitives(Profile::D2HybridFrost, 2, Mode::PqStrict, Action::Release),
            Err(ModelError::InvalidMode)
        );
        assert!(!mode_ok(Profile::D2Hybrid, 2, Mode::Compact, Action::Release).unwrap());
        assert!(mode_ok(Profile::D2Hybrid, 2, Mode::Hybrid, Action::Release).unwrap());
    }

    #[test]
    fn security_strength_vector_does_not_claim_global_256_bits() {
        assert_eq!(DAYLIGHT_SECURITY_STRENGTH.pq_kem_category, 5);
        assert_eq!(DAYLIGHT_SECURITY_STRENGTH.pq_sig_category, 5);
        assert_eq!(DAYLIGHT_SECURITY_STRENGTH.classical_dh_bits_max, 192);
        assert_eq!(DAYLIGHT_SECURITY_STRENGTH.aead_conf_bits_approx, 256);
        assert_eq!(DAYLIGHT_SECURITY_STRENGTH.aead_int_bits_max, 128);
        assert_eq!(DAYLIGHT_SECURITY_STRENGTH.min_scalar_bits, 128);
    }

    #[test]
    fn no_downgrade_checks_policy_and_ledger_monotonicity() {
        let base = DowngradePolicy {
            candidate: ModeState {
                release_level: 2,
                mode: Mode::Hybrid,
            },
            minimum: ModeState {
                release_level: 1,
                mode: Mode::Hybrid,
            },
            previous: Some(ModeState {
                release_level: 2,
                mode: Mode::Hybrid,
            }),
            action: Action::Release,
            suite_id_matches_hash: true,
            suite_allowed: true,
            suite_revoked: false,
        };
        assert!(no_downgrade(base).unwrap());

        let mut downgraded = base;
        downgraded.candidate.mode = Mode::Compact;
        assert!(!no_downgrade(downgraded).unwrap());

        let mut revoked = base;
        revoked.suite_revoked = true;
        assert!(!no_downgrade(revoked).unwrap());

        let mut root_rotate = base;
        root_rotate.action = Action::RootRotate;
        root_rotate.candidate.release_level = 1;
        root_rotate.candidate.mode = Mode::Compact;
        root_rotate.minimum = ModeState {
            release_level: 1,
            mode: Mode::Compact,
        };
        assert!(no_downgrade(root_rotate).unwrap());
    }

    #[test]
    fn poster_probability_values_match_under_iid_assumption() {
        assert_close(authorization_probability(3, 2, 0.95).unwrap(), 0.99275);
        assert_close(compromise_probability(3, 2, 0.01).unwrap(), 0.000298);

        assert_close(authorization_probability(5, 3, 0.95).unwrap(), 0.998841875);
        assert_close(compromise_probability(5, 3, 0.01).unwrap(), 0.0000098506);

        assert_close(authorization_probability(5, 4, 0.95).unwrap(), 0.9774075);
        assert_close(compromise_probability(5, 4, 0.01).unwrap(), 0.0000000496);
    }

    #[test]
    fn correlated_break_bound_is_explicit() {
        let iid = compromise_probability(5, 3, 0.01).unwrap();
        assert_close(
            correlated_break_upper_bound(iid, 0.001).unwrap(),
            iid + 0.001,
        );
        assert_eq!(
            correlated_break_upper_bound(0.75, 0.26),
            Err(ModelError::InvalidThreshold)
        );
    }

    #[test]
    fn invalid_thresholds_reject() {
        assert_eq!(
            authorization_probability(3, 0, 0.95),
            Err(ModelError::InvalidThreshold)
        );
        assert_eq!(
            authorization_probability(3, 4, 0.95),
            Err(ModelError::InvalidThreshold)
        );
        assert_eq!(
            authorization_probability(3, 2, -0.1),
            Err(ModelError::InvalidThreshold)
        );
        assert_eq!(
            authorization_probability(3, 2, 1.1),
            Err(ModelError::InvalidThreshold)
        );
    }
}
