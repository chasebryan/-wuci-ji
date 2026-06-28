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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaylightV06PublicPredicate {
    ParseOk,
    SuiteOk,
    AuxHashOk,
    KemBlockOk,
    ModeOk,
    PolicyOk,
    ClaimOk,
    GateOk,
    ProvenanceOk,
    ContentReviewPreOk,
    VAuth,
    NoDowngradeFinal,
    LogOk,
    InstallOk,
    WitnessOk,
}

impl DaylightV06PublicPredicate {
    pub const fn name(self) -> &'static str {
        match self {
            DaylightV06PublicPredicate::ParseOk => "ParseOK",
            DaylightV06PublicPredicate::SuiteOk => "SuiteOK",
            DaylightV06PublicPredicate::AuxHashOk => "AuxHashOK",
            DaylightV06PublicPredicate::KemBlockOk => "KEMBlockOK",
            DaylightV06PublicPredicate::ModeOk => "ModeOK",
            DaylightV06PublicPredicate::PolicyOk => "PolicyOK",
            DaylightV06PublicPredicate::ClaimOk => "ClaimOK",
            DaylightV06PublicPredicate::GateOk => "GateOK",
            DaylightV06PublicPredicate::ProvenanceOk => "ProvenanceOK",
            DaylightV06PublicPredicate::ContentReviewPreOk => "ContentReviewPreOK",
            DaylightV06PublicPredicate::VAuth => "V_Auth",
            DaylightV06PublicPredicate::NoDowngradeFinal => "NoDowngradeFinal",
            DaylightV06PublicPredicate::LogOk => "LogOK",
            DaylightV06PublicPredicate::InstallOk => "InstallOK",
            DaylightV06PublicPredicate::WitnessOk => "WitnessOK",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaylightV06PrivatePredicate {
    DeriveOk,
    AeadDec,
    PayloadOk,
    CommitOk,
    LeakOk,
}

impl DaylightV06PrivatePredicate {
    pub const fn name(self) -> &'static str {
        match self {
            DaylightV06PrivatePredicate::DeriveOk => "DeriveOK",
            DaylightV06PrivatePredicate::AeadDec => "AEAD.Dec",
            DaylightV06PrivatePredicate::PayloadOk => "PayloadOK",
            DaylightV06PrivatePredicate::CommitOk => "CommitOK",
            DaylightV06PrivatePredicate::LeakOk => "LeakOK",
        }
    }
}

pub const DAYLIGHT_V06_PUBLIC_PREDICATES: [DaylightV06PublicPredicate; 15] = [
    DaylightV06PublicPredicate::ParseOk,
    DaylightV06PublicPredicate::SuiteOk,
    DaylightV06PublicPredicate::AuxHashOk,
    DaylightV06PublicPredicate::KemBlockOk,
    DaylightV06PublicPredicate::ModeOk,
    DaylightV06PublicPredicate::PolicyOk,
    DaylightV06PublicPredicate::ClaimOk,
    DaylightV06PublicPredicate::GateOk,
    DaylightV06PublicPredicate::ProvenanceOk,
    DaylightV06PublicPredicate::ContentReviewPreOk,
    DaylightV06PublicPredicate::VAuth,
    DaylightV06PublicPredicate::NoDowngradeFinal,
    DaylightV06PublicPredicate::LogOk,
    DaylightV06PublicPredicate::InstallOk,
    DaylightV06PublicPredicate::WitnessOk,
];

pub const DAYLIGHT_V06_PRIVATE_PREDICATES: [DaylightV06PrivatePredicate; 5] = [
    DaylightV06PrivatePredicate::DeriveOk,
    DaylightV06PrivatePredicate::AeadDec,
    DaylightV06PrivatePredicate::PayloadOk,
    DaylightV06PrivatePredicate::CommitOk,
    DaylightV06PrivatePredicate::LeakOk,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaylightV06PublicPredicates {
    pub parse_ok: bool,
    pub suite_ok: bool,
    pub aux_hash_ok: bool,
    pub kem_block_ok: bool,
    pub mode_ok: bool,
    pub policy_ok: bool,
    pub claim_ok: bool,
    pub gate_ok: bool,
    pub provenance_ok: bool,
    pub content_review_pre_ok: bool,
    pub v_auth: bool,
    pub no_downgrade_final: bool,
    pub log_ok: bool,
    pub install_ok: bool,
    pub witness_ok: bool,
}

impl DaylightV06PublicPredicates {
    pub const fn all_passed() -> Self {
        Self {
            parse_ok: true,
            suite_ok: true,
            aux_hash_ok: true,
            kem_block_ok: true,
            mode_ok: true,
            policy_ok: true,
            claim_ok: true,
            gate_ok: true,
            provenance_ok: true,
            content_review_pre_ok: true,
            v_auth: true,
            no_downgrade_final: true,
            log_ok: true,
            install_ok: true,
            witness_ok: true,
        }
    }

    pub const fn all_failed() -> Self {
        Self {
            parse_ok: false,
            suite_ok: false,
            aux_hash_ok: false,
            kem_block_ok: false,
            mode_ok: false,
            policy_ok: false,
            claim_ok: false,
            gate_ok: false,
            provenance_ok: false,
            content_review_pre_ok: false,
            v_auth: false,
            no_downgrade_final: false,
            log_ok: false,
            install_ok: false,
            witness_ok: false,
        }
    }

    pub const fn get(&self, predicate: DaylightV06PublicPredicate) -> bool {
        match predicate {
            DaylightV06PublicPredicate::ParseOk => self.parse_ok,
            DaylightV06PublicPredicate::SuiteOk => self.suite_ok,
            DaylightV06PublicPredicate::AuxHashOk => self.aux_hash_ok,
            DaylightV06PublicPredicate::KemBlockOk => self.kem_block_ok,
            DaylightV06PublicPredicate::ModeOk => self.mode_ok,
            DaylightV06PublicPredicate::PolicyOk => self.policy_ok,
            DaylightV06PublicPredicate::ClaimOk => self.claim_ok,
            DaylightV06PublicPredicate::GateOk => self.gate_ok,
            DaylightV06PublicPredicate::ProvenanceOk => self.provenance_ok,
            DaylightV06PublicPredicate::ContentReviewPreOk => self.content_review_pre_ok,
            DaylightV06PublicPredicate::VAuth => self.v_auth,
            DaylightV06PublicPredicate::NoDowngradeFinal => self.no_downgrade_final,
            DaylightV06PublicPredicate::LogOk => self.log_ok,
            DaylightV06PublicPredicate::InstallOk => self.install_ok,
            DaylightV06PublicPredicate::WitnessOk => self.witness_ok,
        }
    }

    pub fn with(mut self, predicate: DaylightV06PublicPredicate, value: bool) -> Self {
        match predicate {
            DaylightV06PublicPredicate::ParseOk => self.parse_ok = value,
            DaylightV06PublicPredicate::SuiteOk => self.suite_ok = value,
            DaylightV06PublicPredicate::AuxHashOk => self.aux_hash_ok = value,
            DaylightV06PublicPredicate::KemBlockOk => self.kem_block_ok = value,
            DaylightV06PublicPredicate::ModeOk => self.mode_ok = value,
            DaylightV06PublicPredicate::PolicyOk => self.policy_ok = value,
            DaylightV06PublicPredicate::ClaimOk => self.claim_ok = value,
            DaylightV06PublicPredicate::GateOk => self.gate_ok = value,
            DaylightV06PublicPredicate::ProvenanceOk => self.provenance_ok = value,
            DaylightV06PublicPredicate::ContentReviewPreOk => {
                self.content_review_pre_ok = value;
            }
            DaylightV06PublicPredicate::VAuth => self.v_auth = value,
            DaylightV06PublicPredicate::NoDowngradeFinal => self.no_downgrade_final = value,
            DaylightV06PublicPredicate::LogOk => self.log_ok = value,
            DaylightV06PublicPredicate::InstallOk => self.install_ok = value,
            DaylightV06PublicPredicate::WitnessOk => self.witness_ok = value,
        }
        self
    }

    pub fn all_hold(&self) -> bool {
        DAYLIGHT_V06_PUBLIC_PREDICATES
            .iter()
            .all(|predicate| self.get(*predicate))
    }

    pub fn first_failed(&self) -> Option<DaylightV06PublicPredicate> {
        DAYLIGHT_V06_PUBLIC_PREDICATES
            .iter()
            .copied()
            .find(|predicate| !self.get(*predicate))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaylightV06PrivatePredicates {
    pub derive_ok: bool,
    pub aead_dec: bool,
    pub payload_ok: bool,
    pub commit_ok: bool,
    pub leak_ok: bool,
}

impl DaylightV06PrivatePredicates {
    pub const fn all_passed() -> Self {
        Self {
            derive_ok: true,
            aead_dec: true,
            payload_ok: true,
            commit_ok: true,
            leak_ok: true,
        }
    }

    pub const fn all_failed() -> Self {
        Self {
            derive_ok: false,
            aead_dec: false,
            payload_ok: false,
            commit_ok: false,
            leak_ok: false,
        }
    }

    pub const fn get(&self, predicate: DaylightV06PrivatePredicate) -> bool {
        match predicate {
            DaylightV06PrivatePredicate::DeriveOk => self.derive_ok,
            DaylightV06PrivatePredicate::AeadDec => self.aead_dec,
            DaylightV06PrivatePredicate::PayloadOk => self.payload_ok,
            DaylightV06PrivatePredicate::CommitOk => self.commit_ok,
            DaylightV06PrivatePredicate::LeakOk => self.leak_ok,
        }
    }

    pub fn with(mut self, predicate: DaylightV06PrivatePredicate, value: bool) -> Self {
        match predicate {
            DaylightV06PrivatePredicate::DeriveOk => self.derive_ok = value,
            DaylightV06PrivatePredicate::AeadDec => self.aead_dec = value,
            DaylightV06PrivatePredicate::PayloadOk => self.payload_ok = value,
            DaylightV06PrivatePredicate::CommitOk => self.commit_ok = value,
            DaylightV06PrivatePredicate::LeakOk => self.leak_ok = value,
        }
        self
    }

    pub fn all_hold(&self) -> bool {
        DAYLIGHT_V06_PRIVATE_PREDICATES
            .iter()
            .all(|predicate| self.get(*predicate))
    }

    pub fn first_failed(&self) -> Option<DaylightV06PrivatePredicate> {
        DAYLIGHT_V06_PRIVATE_PREDICATES
            .iter()
            .copied()
            .find(|predicate| !self.get(*predicate))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaylightV06OpenPredicateState {
    pub public: DaylightV06PublicPredicates,
    pub private: DaylightV06PrivatePredicates,
}

impl DaylightV06OpenPredicateState {
    pub const fn all_passed() -> Self {
        Self {
            public: DaylightV06PublicPredicates::all_passed(),
            private: DaylightV06PrivatePredicates::all_passed(),
        }
    }

    pub fn private_ops_allowed(&self) -> bool {
        self.public.all_hold()
    }

    pub fn open_succeeds(&self) -> bool {
        self.public.all_hold() && self.private.all_hold()
    }

    pub fn first_failed_public(&self) -> Option<DaylightV06PublicPredicate> {
        self.public.first_failed()
    }

    pub fn first_failed_private(&self) -> Option<DaylightV06PrivatePredicate> {
        if self.public.all_hold() {
            self.private.first_failed()
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaylightV06ClaimBoundary {
    pub component_total: u16,
    pub cap_ceiling: u16,
    pub score_max: u16,
    pub production_allowed: bool,
    pub runtime_containment_claim: bool,
    pub whole_system_post_quantum_safety_claim: bool,
    pub external_review_claim: bool,
    pub official_endorsement_claim: bool,
    pub legal_safety_nullifier_triggered: bool,
}

impl DaylightV06ClaimBoundary {
    pub const fn final_score(&self) -> u16 {
        if self.legal_safety_nullifier_triggered {
            0
        } else if self.component_total < self.cap_ceiling {
            self.component_total
        } else {
            self.cap_ceiling
        }
    }

    pub const fn zero_claims_hold(&self) -> bool {
        !self.production_allowed
            && !self.runtime_containment_claim
            && !self.whole_system_post_quantum_safety_claim
            && !self.external_review_claim
            && !self.official_endorsement_claim
    }
}

pub const DAYLIGHT_V06_8250_RESEARCH_BOUNDARY: DaylightV06ClaimBoundary =
    DaylightV06ClaimBoundary {
        component_total: 8250,
        cap_ceiling: 8250,
        score_max: 10000,
        production_allowed: false,
        runtime_containment_claim: false,
        whole_system_post_quantum_safety_claim: false,
        external_review_claim: false,
        official_endorsement_claim: false,
        legal_safety_nullifier_triggered: false,
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
    fn daylight_v06_predicate_names_match_m4_model() {
        let public_names: Vec<&str> = DAYLIGHT_V06_PUBLIC_PREDICATES
            .iter()
            .map(|predicate| predicate.name())
            .collect();
        let private_names: Vec<&str> = DAYLIGHT_V06_PRIVATE_PREDICATES
            .iter()
            .map(|predicate| predicate.name())
            .collect();

        assert_eq!(
            public_names,
            vec![
                "ParseOK",
                "SuiteOK",
                "AuxHashOK",
                "KEMBlockOK",
                "ModeOK",
                "PolicyOK",
                "ClaimOK",
                "GateOK",
                "ProvenanceOK",
                "ContentReviewPreOK",
                "V_Auth",
                "NoDowngradeFinal",
                "LogOK",
                "InstallOK",
                "WitnessOK",
            ]
        );
        assert_eq!(
            private_names,
            vec!["DeriveOK", "AEAD.Dec", "PayloadOK", "CommitOK", "LeakOK"]
        );
    }

    #[test]
    fn daylight_v06_open_truth_table_is_fail_closed() {
        let total_predicates =
            DAYLIGHT_V06_PUBLIC_PREDICATES.len() + DAYLIGHT_V06_PRIVATE_PREDICATES.len();
        let mut state_count = 0usize;

        for mask in 0u32..(1u32 << total_predicates) {
            let mut public = DaylightV06PublicPredicates::all_failed();
            let mut private = DaylightV06PrivatePredicates::all_failed();

            for (index, predicate) in DAYLIGHT_V06_PUBLIC_PREDICATES.iter().enumerate() {
                public = public.with(*predicate, (mask & (1u32 << index)) != 0);
            }
            for (offset, predicate) in DAYLIGHT_V06_PRIVATE_PREDICATES.iter().enumerate() {
                let index = DAYLIGHT_V06_PUBLIC_PREDICATES.len() + offset;
                private = private.with(*predicate, (mask & (1u32 << index)) != 0);
            }

            let state = DaylightV06OpenPredicateState { public, private };
            assert_eq!(state.private_ops_allowed(), public.all_hold());
            assert_eq!(
                state.open_succeeds(),
                public.all_hold() && private.all_hold()
            );
            if !public.all_hold() {
                assert!(state.first_failed_public().is_some());
                assert_eq!(state.first_failed_private(), None);
            } else if !private.all_hold() {
                assert!(state.first_failed_private().is_some());
            }
            state_count += 1;
        }

        assert_eq!(state_count, 1usize << total_predicates);
        assert!(DaylightV06OpenPredicateState::all_passed().open_succeeds());
    }

    #[test]
    fn daylight_v06_8250_boundary_keeps_nonclaims_zero() {
        let boundary = DAYLIGHT_V06_8250_RESEARCH_BOUNDARY;
        assert_eq!(boundary.component_total, 8250);
        assert_eq!(boundary.cap_ceiling, 8250);
        assert_eq!(boundary.score_max, 10000);
        assert_eq!(boundary.final_score(), 8250);
        assert!(boundary.zero_claims_hold());
        assert!(!boundary.legal_safety_nullifier_triggered);
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
