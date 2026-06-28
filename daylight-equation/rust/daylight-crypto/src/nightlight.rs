//! Nightlight defensive battery for Daylight v6.
//!
//! Nightlight is an equation/invariant battery over the existing Daylight v6
//! evidence surfaces. It does not add attack logic, offensive scanning,
//! production authority, runtime containment, or a new Open authorization path.

use crate::v6::{
    artifact_hash_v6, daylight_envelope_bytes_v6, daylight_open_failure_name_v6,
    daylight_v6_provider_kem_evidence, daylight_v6_provider_private_roundtrip_evidence,
    daylight_v6_reference_negative_corpus_evidence, daylight_v6_reference_seal_open_evidence,
    daylight_v6_schema_vector, daylight_vector_public_precheck_v6, encode_cbor_value, hb_v6, hc_v6,
    CborValue, DaylightConformanceLevelV6, DaylightContentScopeV6, DaylightEnvelopeV6,
    DaylightFrostAuthV6, DaylightLeakValueV6, DaylightPolicyV6, DaylightRejectionStageV6,
};
use crate::{AeadAlgorithm, DaylightCryptoError, DaylightOpenFailure};
use daylight_model::{Action, Mode, Profile};

pub const NIGHTLIGHT_V6_EQUATION_BATTERY_SCHEMA: &str = "nightlight-v6-equation-battery-v1";
pub const NIGHTLIGHT_V6_DEEP_ASSESSMENT_SCHEMA: &str = "nightlight-v6-deep-assault-assessment-v1";
const NIGHTLIGHT_MIN_REFERENCE_NEGATIVE_CASES: usize = 12;
const NIGHTLIGHT_MIN_PUBLIC_SIMULATION_CASES: usize = 40;
const NIGHTLIGHT_LEARNING_EPOCHS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightFailureCountV6 {
    pub failure: DaylightOpenFailure,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightRejectionStageCountV6 {
    pub stage: DaylightRejectionStageV6,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightPublicSimulationCaseV6 {
    pub case_id: &'static str,
    pub mutation: &'static str,
    pub expected_stage: DaylightRejectionStageV6,
    pub actual_stage: DaylightRejectionStageV6,
    pub fail_closed: bool,
    pub private_path_reached: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightV6EquationBattery {
    pub schema: &'static str,
    pub subject: &'static str,
    pub profile: &'static str,
    pub score_delta: i32,
    pub production_allowed: bool,
    pub runtime_containment_claim: bool,
    pub whole_system_post_quantum_safety_claim: bool,
    pub offensive_logic_added: bool,
    pub network_required: bool,
    pub open_ended_gate: bool,
    pub minimum_reference_negative_cases: usize,
    pub minimum_public_simulation_cases: usize,
    pub equation_checks_total: usize,
    pub equation_checks_failed: usize,
    pub equation_holds: bool,
    pub efficiency_checks_total: usize,
    pub efficiency_checks_failed: usize,
    pub efficiency_holds: bool,
    pub defensive_battery_ready: bool,
    pub provider_backed_kem: bool,
    pub provider_backed_private_roundtrip: bool,
    pub provider_backed_reference_seal_open: bool,
    pub public_authority_external: bool,
    pub schema_public_precheck_rejection_stage: DaylightRejectionStageV6,
    pub private_public_precheck_rejection_stage: DaylightRejectionStageV6,
    pub reference_public_precheck_rejection_stage: DaylightRejectionStageV6,
    pub total_negative_cases: usize,
    pub fail_closed_negative_cases: usize,
    pub public_simulation_cases_total: usize,
    pub public_simulation_fail_closed_cases: usize,
    pub public_simulation_all_fail_closed: bool,
    pub adversarial_cases_total: usize,
    pub adversarial_cases_fail_closed: usize,
    pub public_precheck_stop_count: usize,
    pub private_path_mutation_count: usize,
    pub private_path_reach_count: usize,
    pub failure_counts: Vec<NightlightFailureCountV6>,
    pub public_simulation_stage_counts: Vec<NightlightRejectionStageCountV6>,
    pub public_simulation_cases: Vec<NightlightPublicSimulationCaseV6>,
    pub artifact_hash: [u8; 64],
    pub schema_omega_hash: [u8; 64],
    pub private_omega_hash: [u8; 64],
    pub reference_omega_hash: [u8; 64],
    pub private_ciphertext_hash: [u8; 64],
    pub reference_ciphertext_hash: [u8; 64],
    pub private_com_a_hash: [u8; 64],
    pub reference_com_a_hash: [u8; 64],
    pub negative_case_set_hash: [u8; 64],
    pub public_simulation_case_set_hash: [u8; 64],
    pub battery_hash: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightLearningArmV6 {
    pub arm_id: &'static str,
    pub category: &'static str,
    pub cases_total: usize,
    pub fail_closed_cases: usize,
    pub private_path_reach_count: usize,
    pub unique_public_stages: usize,
    pub risk_weight: u64,
    pub novelty_score: u64,
    pub learned_priority: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightLearningEpochV6 {
    pub epoch: usize,
    pub selected_arm: &'static str,
    pub learned_priority: u64,
    pub rationale: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightLearningRecommendationV6 {
    pub rank: usize,
    pub gap_id: &'static str,
    pub target: &'static str,
    pub rationale: &'static str,
    pub priority: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NightlightV6DeepAssessment {
    pub schema: &'static str,
    pub subject: &'static str,
    pub algorithm: &'static str,
    pub defensive_only: bool,
    pub learning_enabled: bool,
    pub offensive_logic_added: bool,
    pub network_required: bool,
    pub score_delta: i32,
    pub input_adversarial_cases: usize,
    pub fail_closed_cases: usize,
    pub learning_epochs: usize,
    pub learning_arms_total: usize,
    pub public_stage_target_total: usize,
    pub public_stage_covered: usize,
    pub public_stage_gap_count: usize,
    pub private_failure_target_total: usize,
    pub private_failure_covered: usize,
    pub private_failure_gap_count: usize,
    pub recommendations_total: usize,
    pub top_priority: u64,
    pub arms: Vec<NightlightLearningArmV6>,
    pub epochs: Vec<NightlightLearningEpochV6>,
    pub recommendations: Vec<NightlightLearningRecommendationV6>,
    pub learning_hash: [u8; 64],
}

pub fn nightlight_v6_equation_battery() -> Result<NightlightV6EquationBattery, DaylightCryptoError>
{
    let schema = daylight_v6_schema_vector()?;
    let kem = daylight_v6_provider_kem_evidence()?;
    let private = daylight_v6_provider_private_roundtrip_evidence()?;
    let reference = daylight_v6_reference_seal_open_evidence()?;
    let negative = daylight_v6_reference_negative_corpus_evidence()?;

    let fail_closed_negative_cases = negative
        .cases
        .iter()
        .filter(|case| case.expected_failure == case.actual_failure)
        .count();
    let public_precheck_stop_count = negative
        .cases
        .iter()
        .filter(|case| case.public_precheck_required && !case.private_path_reached)
        .count();
    let private_path_mutation_count = negative
        .cases
        .iter()
        .filter(|case| !case.public_precheck_required && case.private_path_reached)
        .count();
    let private_path_reach_count = negative
        .cases
        .iter()
        .filter(|case| case.private_path_reached)
        .count();
    let failure_counts = nightlight_failure_counts(&negative.cases);
    let negative_case_set_hash = hb_v6(&nightlight_negative_case_material(&negative.cases));
    let public_simulation_cases = nightlight_public_simulation_cases()?;
    let public_simulation_fail_closed_cases = public_simulation_cases
        .iter()
        .filter(|case| case.fail_closed)
        .count();
    let public_simulation_cases_total = public_simulation_cases.len();
    let public_simulation_all_fail_closed =
        public_simulation_fail_closed_cases == public_simulation_cases_total;
    let public_simulation_stage_counts =
        nightlight_rejection_stage_counts(&public_simulation_cases);
    let public_simulation_case_set_hash = hb_v6(&nightlight_public_simulation_material(
        &public_simulation_cases,
    ));
    let adversarial_cases_total = negative.total_cases + public_simulation_cases_total;
    let adversarial_cases_fail_closed =
        fail_closed_negative_cases + public_simulation_fail_closed_cases;

    let private_auth_bound =
        auth_msg_binds_h1(&private.transcript.auth_msg, &private.transcript.h1);
    let reference_auth_bound =
        auth_msg_binds_h1(&reference.opened.auth_msg, &reference.opened.transcript.h1);
    let same_artifact_opened = private.artifact_hash == private.opened_artifact_hash
        && private.artifact_hash == reference.artifact_hash
        && reference.artifact_hash == reference.opened_artifact_hash;
    let seal_outputs_domain_separated = private.ciphertext_hash != reference.ciphertext_hash
        && private.envelope.com_a != reference.envelope.com_a
        && private.com_a_hash != reference.com_a_hash;

    let mut equation_checks = CheckCounts::default();
    equation_checks
        .record(schema.expected_rejection_stage == DaylightRejectionStageV6::RejectAuthSignature);
    equation_checks.record(
        private.public_precheck_rejection_stage == DaylightRejectionStageV6::RejectAuthSignature,
    );
    equation_checks.record(
        reference.public_precheck_rejection_stage == DaylightRejectionStageV6::RejectAuthSignature,
    );
    equation_checks.record(!schema.private_kem_allowed && !schema.aead_dec_allowed);
    equation_checks.record(kem.provider_backed_kem && kem.mlkem1024_decaps_matches);
    equation_checks.record(kem.dhkem_p384_decaps_matches);
    equation_checks.record(kem.key_schedule.envelope_key != kem.key_schedule.commitment_key);
    equation_checks.record(private.provider_backed_private_roundtrip);
    equation_checks.record(!private.provider_backed_reference_seal_open);
    equation_checks.record(private.opened_artifact_matches && private.commitment_matches);
    equation_checks.record(private.aead_roundtrip_matches);
    equation_checks.record(reference.provider_backed_reference_seal_open);
    equation_checks.record(reference.public_authority_external);
    equation_checks.record(reference.opened_artifact_matches);
    equation_checks.record(same_artifact_opened);
    equation_checks.record(private_auth_bound && reference_auth_bound);
    equation_checks.record(seal_outputs_domain_separated);
    equation_checks
        .record(negative.all_fail_closed && fail_closed_negative_cases == negative.total_cases);
    equation_checks.record(public_simulation_all_fail_closed);
    equation_checks.record(negative.total_cases == negative.cases.len());
    equation_checks.record(public_simulation_cases_total >= NIGHTLIGHT_MIN_PUBLIC_SIMULATION_CASES);
    equation_checks.record(
        !kem.production_allowed
            && !private.production_allowed
            && !reference.production_allowed
            && !negative.production_allowed,
    );

    let mut efficiency_checks = CheckCounts::default();
    efficiency_checks.record(negative.total_cases >= NIGHTLIGHT_MIN_REFERENCE_NEGATIVE_CASES);
    efficiency_checks.record(public_precheck_stop_count >= 10);
    efficiency_checks.record(private_path_mutation_count >= 2);
    efficiency_checks.record(private_path_reach_count == private_path_mutation_count);
    efficiency_checks
        .record(public_precheck_stop_count + private_path_mutation_count >= negative.total_cases);
    efficiency_checks.record(
        negative
            .cases
            .iter()
            .all(|case| !case.public_precheck_required || !case.private_path_reached),
    );
    efficiency_checks.record(
        negative
            .cases
            .iter()
            .filter(|case| !case.public_precheck_required)
            .all(|case| case.private_path_reached),
    );
    efficiency_checks.record(!schema.private_kem_allowed && !schema.aead_dec_allowed);
    efficiency_checks.record(!kem.provider_backed_reference_seal_open);
    efficiency_checks
        .record(public_simulation_cases_total >= NIGHTLIGHT_MIN_PUBLIC_SIMULATION_CASES);
    efficiency_checks.record(
        public_simulation_cases
            .iter()
            .all(|case| !case.private_path_reached),
    );

    let equation_holds = equation_checks.failed == 0;
    let efficiency_holds = efficiency_checks.failed == 0;
    let defensive_battery_ready = equation_holds && efficiency_holds;
    if !defensive_battery_ready {
        return Err(DaylightCryptoError::VerificationRejected);
    }

    let production_allowed = false;
    let runtime_containment_claim = false;
    let whole_system_post_quantum_safety_claim = false;
    let offensive_logic_added = false;
    let network_required = false;
    let open_ended_gate = true;
    let artifact_hash = private.artifact_hash;
    let schema_omega_hash = hb_v6(&schema.omega);
    let private_omega_hash = hb_v6(&private.omega);
    let reference_omega_hash = hb_v6(&reference.omega);
    let private_ciphertext_hash = private.ciphertext_hash;
    let reference_ciphertext_hash = reference.ciphertext_hash;
    let private_com_a_hash = private.com_a_hash;
    let reference_com_a_hash = reference.com_a_hash;
    let battery_hash = hb_v6(&nightlight_battery_material(
        artifact_hash,
        schema_omega_hash,
        private_omega_hash,
        reference_omega_hash,
        negative_case_set_hash,
        public_simulation_case_set_hash,
        equation_checks.total,
        efficiency_checks.total,
        adversarial_cases_total,
        public_precheck_stop_count,
        private_path_mutation_count,
    ));

    Ok(NightlightV6EquationBattery {
        schema: NIGHTLIGHT_V6_EQUATION_BATTERY_SCHEMA,
        subject: "Nightlight_Daylight_v6_equation_battery",
        profile: "defensive-equation-battery",
        score_delta: 0,
        production_allowed,
        runtime_containment_claim,
        whole_system_post_quantum_safety_claim,
        offensive_logic_added,
        network_required,
        open_ended_gate,
        minimum_reference_negative_cases: NIGHTLIGHT_MIN_REFERENCE_NEGATIVE_CASES,
        minimum_public_simulation_cases: NIGHTLIGHT_MIN_PUBLIC_SIMULATION_CASES,
        equation_checks_total: equation_checks.total,
        equation_checks_failed: equation_checks.failed,
        equation_holds,
        efficiency_checks_total: efficiency_checks.total,
        efficiency_checks_failed: efficiency_checks.failed,
        efficiency_holds,
        defensive_battery_ready,
        provider_backed_kem: kem.provider_backed_kem,
        provider_backed_private_roundtrip: private.provider_backed_private_roundtrip,
        provider_backed_reference_seal_open: reference.provider_backed_reference_seal_open,
        public_authority_external: reference.public_authority_external,
        schema_public_precheck_rejection_stage: schema.expected_rejection_stage,
        private_public_precheck_rejection_stage: private.public_precheck_rejection_stage,
        reference_public_precheck_rejection_stage: reference.public_precheck_rejection_stage,
        total_negative_cases: negative.total_cases,
        fail_closed_negative_cases,
        public_simulation_cases_total,
        public_simulation_fail_closed_cases,
        public_simulation_all_fail_closed,
        adversarial_cases_total,
        adversarial_cases_fail_closed,
        public_precheck_stop_count,
        private_path_mutation_count,
        private_path_reach_count,
        failure_counts,
        public_simulation_stage_counts,
        public_simulation_cases,
        artifact_hash,
        schema_omega_hash,
        private_omega_hash,
        reference_omega_hash,
        private_ciphertext_hash,
        reference_ciphertext_hash,
        private_com_a_hash,
        reference_com_a_hash,
        negative_case_set_hash,
        public_simulation_case_set_hash,
        battery_hash,
    })
}

pub fn nightlight_v6_deep_assessment() -> Result<NightlightV6DeepAssessment, DaylightCryptoError> {
    let battery = nightlight_v6_equation_battery()?;
    let negative = daylight_v6_reference_negative_corpus_evidence()?;
    let mut arms = nightlight_learning_arms(&battery, &negative.cases);
    arms.sort_by(|left, right| {
        right
            .learned_priority
            .cmp(&left.learned_priority)
            .then_with(|| left.arm_id.cmp(right.arm_id))
    });

    let epochs = arms
        .iter()
        .take(NIGHTLIGHT_LEARNING_EPOCHS)
        .enumerate()
        .map(|(index, arm)| NightlightLearningEpochV6 {
            epoch: index + 1,
            selected_arm: arm.arm_id,
            learned_priority: arm.learned_priority,
            rationale: learning_rationale(arm.arm_id),
        })
        .collect::<Vec<_>>();

    let public_stage_target_total = nightlight_public_stage_targets().len();
    let public_stage_covered = nightlight_public_stage_targets()
        .iter()
        .filter(|stage| {
            battery
                .public_simulation_stage_counts
                .iter()
                .any(|count| count.stage == **stage)
        })
        .count();
    let public_stage_gap_count = public_stage_target_total - public_stage_covered;

    let private_failure_target_total = nightlight_private_failure_targets().len();
    let private_failure_covered = nightlight_private_failure_targets()
        .iter()
        .filter(|failure| {
            battery
                .failure_counts
                .iter()
                .any(|count| count.failure == **failure)
        })
        .count();
    let private_failure_gap_count = private_failure_target_total - private_failure_covered;

    let recommendations = nightlight_learning_recommendations(&battery);
    let top_priority = recommendations
        .iter()
        .map(|recommendation| recommendation.priority)
        .max()
        .unwrap_or(0);
    let learning_hash = hb_v6(&nightlight_learning_material(
        &battery,
        &arms,
        &epochs,
        &recommendations,
    ));

    Ok(NightlightV6DeepAssessment {
        schema: NIGHTLIGHT_V6_DEEP_ASSESSMENT_SCHEMA,
        subject: "Nightlight_Daylight_v6_deep_learning_assessment",
        algorithm: "deterministic-coverage-learning-v1",
        defensive_only: true,
        learning_enabled: true,
        offensive_logic_added: false,
        network_required: false,
        score_delta: 0,
        input_adversarial_cases: battery.adversarial_cases_total,
        fail_closed_cases: battery.adversarial_cases_fail_closed,
        learning_epochs: epochs.len(),
        learning_arms_total: arms.len(),
        public_stage_target_total,
        public_stage_covered,
        public_stage_gap_count,
        private_failure_target_total,
        private_failure_covered,
        private_failure_gap_count,
        recommendations_total: recommendations.len(),
        top_priority,
        arms,
        epochs,
        recommendations,
        learning_hash,
    })
}

#[derive(Default)]
struct CheckCounts {
    total: usize,
    failed: usize,
}

impl CheckCounts {
    fn record(&mut self, condition: bool) {
        self.total += 1;
        if !condition {
            self.failed += 1;
        }
    }
}

fn auth_msg_binds_h1(auth_msg: &[u8], h1: &[u8; 64]) -> bool {
    auth_msg
        .len()
        .checked_sub(h1.len())
        .map(|offset| &auth_msg[offset..] == h1)
        .unwrap_or(false)
}

fn nightlight_public_simulation_cases(
) -> Result<Vec<NightlightPublicSimulationCaseV6>, DaylightCryptoError> {
    let schema = daylight_v6_schema_vector()?;
    let base = schema.envelope;
    let mut cases = Vec::new();

    push_public_bytes_case(
        &mut cases,
        "P01_empty_omega",
        "omega=[]",
        DaylightRejectionStageV6::RejectParse,
        Vec::new(),
    )?;
    push_public_bytes_case(
        &mut cases,
        "P02_truncated_omega",
        "omega=omega[..len/2]",
        DaylightRejectionStageV6::RejectParse,
        schema.omega[..schema.omega.len() / 2].to_vec(),
    )?;
    let mut trailing = schema.omega.clone();
    trailing.push(0);
    push_public_bytes_case(
        &mut cases,
        "P03_trailing_cbor",
        "omega=omega||00",
        DaylightRejectionStageV6::RejectParse,
        trailing,
    )?;
    push_public_bytes_case(
        &mut cases,
        "P04_noncanonical_uint",
        "omega=noncanonical-cbor-uint",
        DaylightRejectionStageV6::RejectParse,
        vec![0x18, 0x00],
    )?;

    push_public_value_case(
        &mut cases,
        "P05_null_envelope",
        "omega=null",
        DaylightRejectionStageV6::RejectSchema,
        CborValue::Null,
    )?;
    push_public_value_case(
        &mut cases,
        "P06_wrong_magic",
        "envelope.magic=not-daylight",
        DaylightRejectionStageV6::RejectSchema,
        cbor_map_replace(
            base.to_cbor(),
            0,
            CborValue::Text("NOT-DAYLIGHT".to_string()),
        )?,
    )?;
    push_public_value_case(
        &mut cases,
        "P07_extra_envelope_key",
        "envelope.extra_key=99",
        DaylightRejectionStageV6::RejectSchema,
        cbor_map_insert(base.to_cbor(), 99, CborValue::Bool(true))?,
    )?;
    push_public_value_case(
        &mut cases,
        "P08_wrong_com_a_length",
        "envelope.com_A_len=31",
        DaylightRejectionStageV6::RejectSchema,
        cbor_map_replace(base.to_cbor(), 4, CborValue::Bytes(vec![0u8; 31]))?,
    )?;
    let mut version_5 = base.clone();
    version_5.header.version = 5;
    push_public_envelope_case(
        &mut cases,
        "P09_header_version_5",
        "header.version=5",
        DaylightRejectionStageV6::RejectSchema,
        version_5,
    )?;

    let mut suite_id_mismatch = base.clone();
    suite_id_mismatch.header.suite_id[0] ^= 0x80;
    push_public_envelope_case(
        &mut cases,
        "P10_suite_id_mismatch",
        "header.suite_id[0]^=0x80",
        DaylightRejectionStageV6::RejectSuite,
        suite_id_mismatch,
    )?;
    let mut release_downgraded = base.clone();
    release_downgraded.header.release_level = 0;
    push_public_envelope_case(
        &mut cases,
        "P11_release_level_0_for_open",
        "header.release_level=0",
        DaylightRejectionStageV6::RejectSuite,
        release_downgraded,
    )?;
    let mut mode_downgraded = base.clone();
    mode_downgraded.header.mode = Mode::Compact;
    push_public_envelope_case(
        &mut cases,
        "P12_public_mode_for_open",
        "header.mode=compact",
        DaylightRejectionStageV6::RejectSchema,
        mode_downgraded,
    )?;
    let mut bad_conformance = base.clone();
    bad_conformance.header.conformance_min = DaylightConformanceLevelV6::C5Frost;
    push_public_envelope_case(
        &mut cases,
        "P13_c5_frost_for_d2_hybrid",
        "header.conformance_min=C5Frost",
        DaylightRejectionStageV6::RejectSuite,
        bad_conformance,
    )?;

    let mut bad_policy_hash = base.clone();
    bad_policy_hash.header.policy_hash[0] ^= 0x80;
    push_public_envelope_case(
        &mut cases,
        "P14_policy_hash_mismatch",
        "header.policy_hash[0]^=0x80",
        DaylightRejectionStageV6::RejectAuxHash,
        bad_policy_hash,
    )?;
    let mut bad_keyset_hash = base.clone();
    bad_keyset_hash.header.keyset_hash[0] ^= 0x80;
    push_public_envelope_case(
        &mut cases,
        "P15_keyset_hash_mismatch",
        "header.keyset_hash[0]^=0x80",
        DaylightRejectionStageV6::RejectAuxHash,
        bad_keyset_hash,
    )?;
    let mut bad_claims_hash = base.clone();
    bad_claims_hash.header.claims_hash[0] ^= 0x80;
    push_public_envelope_case(
        &mut cases,
        "P16_claims_hash_mismatch",
        "header.claims_hash[0]^=0x80",
        DaylightRejectionStageV6::RejectAuxHash,
        bad_claims_hash,
    )?;
    let mut unexpected_provenance = base.clone();
    unexpected_provenance.aux_block.provenance_obj =
        Some(CborValue::Text("unhashed-provenance".to_string()));
    push_public_envelope_case(
        &mut cases,
        "P17_unhashed_provenance",
        "aux.provenance_obj=Some",
        DaylightRejectionStageV6::RejectAuxHash,
        unexpected_provenance,
    )?;
    let mut unexpected_install = base.clone();
    unexpected_install.aux_block.install_manifest =
        Some(CborValue::Text("unhashed-install".to_string()));
    push_public_envelope_case(
        &mut cases,
        "P18_unhashed_install_manifest",
        "aux.install_manifest=Some",
        DaylightRejectionStageV6::RejectAuxHash,
        unexpected_install,
    )?;

    push_policy_case(
        &mut cases,
        &base,
        "P19_policy_id_mismatch",
        "policy.policy_id!=header.policy_id",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.policy_id = "different-policy".to_string(),
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P20_policy_disallows_profile",
        "policy.allowed_profiles=[D3Root]",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.allowed_profiles = vec![Profile::D3Root],
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P21_policy_disallows_aead",
        "policy.allowed_aeads=[ChaCha20Poly1305]",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.allowed_aeads = vec![AeadAlgorithm::ChaCha20Poly1305],
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P22_policy_disallows_open_action",
        "policy.allowed_actions=[Research,Proof]",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.allowed_actions = vec![Action::Research, Action::Proof],
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P23_policy_disallows_keyset",
        "policy.allowed_keyset_hashes=[]",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.allowed_keyset_hashes.clear(),
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P24_policy_expired",
        "policy.expiry_epoch=0",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.expiry_epoch = Some(0),
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P25_policy_requires_provenance",
        "policy.require_provenance=true",
        DaylightRejectionStageV6::RejectPolicy,
        |policy| policy.require_provenance = true,
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P26_policy_min_release_2",
        "policy.open_min_release=2",
        DaylightRejectionStageV6::RejectDowngrade,
        |policy| policy.min_mode_by_action = vec![(Action::Open, (2, Mode::Hybrid))],
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P27_policy_requires_exact_review",
        "policy.require_exact_content_approval=true",
        DaylightRejectionStageV6::RejectReview,
        |policy| policy.require_exact_content_approval = true,
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P28_policy_requires_witness",
        "policy.require_witness=true",
        DaylightRejectionStageV6::RejectWitness,
        |policy| policy.require_witness = true,
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P29_policy_requires_log",
        "policy.log_required_actions=[Open]",
        DaylightRejectionStageV6::RejectLog,
        |policy| policy.log_required_actions = vec![Action::Open],
    )?;
    let mut review_scope = base.clone();
    review_scope.header.content_scope = DaylightContentScopeV6::PublicCommitment;
    review_scope.header.leak_value = DaylightLeakValueV6::PublicCommitment {
        artifact_len: 0,
        artifact_hash: artifact_hash_v6(b""),
    };
    push_public_envelope_case(
        &mut cases,
        "P30_public_commitment_without_review",
        "header.content_scope=PublicCommitment,no_review_receipt",
        DaylightRejectionStageV6::RejectReview,
        review_scope,
    )?;

    let mut disallowed_claim = base.clone();
    disallowed_claim.aux_block.claims_obj = CborValue::Array(vec![claim_cbor(
        7,
        "release-too-low",
        CborValue::Bool(true),
    )]);
    refresh_claims_hash(&mut disallowed_claim)?;
    push_public_envelope_case(
        &mut cases,
        "P31_claim_class_7_release_1",
        "claims=[class=7]",
        DaylightRejectionStageV6::RejectClaims,
        disallowed_claim,
    )?;
    let mut unknown_claim = base.clone();
    unknown_claim.aux_block.claims_obj =
        CborValue::Array(vec![claim_cbor(8, "unknown-class", CborValue::Bool(true))]);
    refresh_claims_hash(&mut unknown_claim)?;
    push_public_envelope_case(
        &mut cases,
        "P32_claim_class_8",
        "claims=[class=8]",
        DaylightRejectionStageV6::RejectClaims,
        unknown_claim,
    )?;
    let mut malformed_claim = base.clone();
    malformed_claim.aux_block.claims_obj = CborValue::Array(vec![CborValue::Null]);
    refresh_claims_hash(&mut malformed_claim)?;
    push_public_envelope_case(
        &mut cases,
        "P33_claim_null",
        "claims=[null]",
        DaylightRejectionStageV6::RejectClaims,
        malformed_claim,
    )?;
    push_policy_case(
        &mut cases,
        &base,
        "P34_policy_disallows_claim_classes",
        "policy.allowed_claim_classes=[]",
        DaylightRejectionStageV6::RejectClaims,
        |policy| policy.allowed_claim_classes.clear(),
    )?;

    let mut short_ek_q = base.clone();
    short_ek_q.aux_block.keyset_obj = cbor_map_replace(
        short_ek_q.aux_block.keyset_obj.clone(),
        0,
        CborValue::Bytes(vec![0u8; 16]),
    )?;
    refresh_keyset_hash(&mut short_ek_q)?;
    push_public_envelope_case(
        &mut cases,
        "P35_keyset_short_ek_q",
        "keyset.ek_Q_len=16",
        DaylightRejectionStageV6::RejectKemBlock,
        short_ek_q,
    )?;
    let mut q_kem_id_mismatch = base.clone();
    q_kem_id_mismatch.kem_block.q_kem_key_id[0] ^= 0x80;
    push_public_envelope_case(
        &mut cases,
        "P36_q_kem_key_id_mismatch",
        "kem.q_kem_key_id[0]^=0x80",
        DaylightRejectionStageV6::RejectKemBlock,
        q_kem_id_mismatch,
    )?;
    let mut c_kem_id_mismatch = base.clone();
    c_kem_id_mismatch.kem_block.c_kem_key_id[0] ^= 0x80;
    push_public_envelope_case(
        &mut cases,
        "P37_c_kem_key_id_mismatch",
        "kem.c_kem_key_id[0]^=0x80",
        DaylightRejectionStageV6::RejectKemBlock,
        c_kem_id_mismatch,
    )?;
    let short_enc_q =
        cbor_map_replace(base.kem_block.to_cbor(), 2, CborValue::Bytes(vec![0u8; 16]))?;
    push_public_value_case(
        &mut cases,
        "P38_short_enc_q",
        "kem.enc_Q_len=16",
        DaylightRejectionStageV6::RejectKemBlock,
        cbor_map_replace(base.to_cbor(), 2, short_enc_q)?,
    )?;
    let short_enc_c =
        cbor_map_replace(base.kem_block.to_cbor(), 3, CborValue::Bytes(vec![0u8; 16]))?;
    push_public_value_case(
        &mut cases,
        "P39_short_enc_c",
        "kem.enc_C_len=16",
        DaylightRejectionStageV6::RejectKemBlock,
        cbor_map_replace(base.to_cbor(), 2, short_enc_c)?,
    )?;

    let mut short_q_sig = base.clone();
    short_q_sig.auth_block.q_sigs[0].sig.truncate(16);
    push_public_envelope_case(
        &mut cases,
        "P40_short_q_signature",
        "auth.q_sig.sig_len=16",
        DaylightRejectionStageV6::RejectAuthBlock,
        short_q_sig,
    )?;
    let mut duplicate_q_sig = base.clone();
    duplicate_q_sig
        .auth_block
        .q_sigs
        .push(duplicate_q_sig.auth_block.q_sigs[0].clone());
    push_public_envelope_case(
        &mut cases,
        "P41_duplicate_q_signature_key",
        "auth.q_sigs=duplicate_key",
        DaylightRejectionStageV6::RejectAuthBlock,
        duplicate_q_sig,
    )?;
    let mut short_h_sig = base.clone();
    short_h_sig.auth_block.h_sig = Some(vec![0u8; 16]);
    push_public_envelope_case(
        &mut cases,
        "P42_short_h_signature",
        "auth.h_sig_len=16",
        DaylightRejectionStageV6::RejectAuthBlock,
        short_h_sig,
    )?;
    let mut unexpected_frost = base.clone();
    unexpected_frost.auth_block.frost_auth = Some(DaylightFrostAuthV6 {
        sig_f: vec![],
        frost_transcript: CborValue::Null,
    });
    push_public_envelope_case(
        &mut cases,
        "P43_unexpected_frost_auth",
        "auth.frost_auth=Some_for_D2Hybrid",
        DaylightRejectionStageV6::RejectAuthBlock,
        unexpected_frost,
    )?;
    push_public_value_case(
        &mut cases,
        "P44_null_auth_block",
        "auth_block=null",
        DaylightRejectionStageV6::RejectAuthBlock,
        cbor_map_replace(base.to_cbor(), 5, CborValue::Null)?,
    )?;
    push_public_envelope_case(
        &mut cases,
        "P45_valid_schema_public_precheck",
        "baseline_schema_vector",
        DaylightRejectionStageV6::RejectAuthSignature,
        base,
    )?;

    Ok(cases)
}

fn push_policy_case<F>(
    cases: &mut Vec<NightlightPublicSimulationCaseV6>,
    base: &DaylightEnvelopeV6,
    case_id: &'static str,
    mutation: &'static str,
    expected_stage: DaylightRejectionStageV6,
    mutate: F,
) -> Result<(), DaylightCryptoError>
where
    F: FnOnce(&mut DaylightPolicyV6),
{
    let mut envelope = base.clone();
    let mut policy = DaylightPolicyV6::from_cbor(&envelope.aux_block.policy_obj)?;
    mutate(&mut policy);
    envelope.aux_block.policy_obj = policy.to_cbor();
    envelope.header.policy_hash = hc_v6(&envelope.aux_block.policy_obj)?;
    push_public_envelope_case(cases, case_id, mutation, expected_stage, envelope)
}

fn push_public_envelope_case(
    cases: &mut Vec<NightlightPublicSimulationCaseV6>,
    case_id: &'static str,
    mutation: &'static str,
    expected_stage: DaylightRejectionStageV6,
    envelope: DaylightEnvelopeV6,
) -> Result<(), DaylightCryptoError> {
    push_public_bytes_case(
        cases,
        case_id,
        mutation,
        expected_stage,
        daylight_envelope_bytes_v6(&envelope)?,
    )
}

fn push_public_value_case(
    cases: &mut Vec<NightlightPublicSimulationCaseV6>,
    case_id: &'static str,
    mutation: &'static str,
    expected_stage: DaylightRejectionStageV6,
    value: CborValue,
) -> Result<(), DaylightCryptoError> {
    push_public_bytes_case(
        cases,
        case_id,
        mutation,
        expected_stage,
        encode_cbor_value(&value)?,
    )
}

fn push_public_bytes_case(
    cases: &mut Vec<NightlightPublicSimulationCaseV6>,
    case_id: &'static str,
    mutation: &'static str,
    expected_stage: DaylightRejectionStageV6,
    omega: Vec<u8>,
) -> Result<(), DaylightCryptoError> {
    let actual_stage = match daylight_vector_public_precheck_v6(&omega, Some(1)) {
        Err(stage) => stage,
        Ok(_) => return Err(DaylightCryptoError::VerificationRejected),
    };
    if actual_stage != expected_stage {
        return Err(DaylightCryptoError::VerificationRejected);
    }
    cases.push(NightlightPublicSimulationCaseV6 {
        case_id,
        mutation,
        expected_stage,
        actual_stage,
        fail_closed: true,
        private_path_reached: false,
    });
    Ok(())
}

fn cbor_map_replace(
    value: CborValue,
    key: u64,
    replacement: CborValue,
) -> Result<CborValue, DaylightCryptoError> {
    let CborValue::Map(mut entries) = value else {
        return Err(DaylightCryptoError::DecodeRejected("expected CBOR map"));
    };
    let mut replaced = false;
    for (candidate, value) in &mut entries {
        if *candidate == key {
            *value = replacement.clone();
            replaced = true;
        }
    }
    if !replaced {
        return Err(DaylightCryptoError::DecodeRejected("missing CBOR map key"));
    }
    Ok(CborValue::Map(entries))
}

fn cbor_map_insert(
    value: CborValue,
    key: u64,
    replacement: CborValue,
) -> Result<CborValue, DaylightCryptoError> {
    let CborValue::Map(mut entries) = value else {
        return Err(DaylightCryptoError::DecodeRejected("expected CBOR map"));
    };
    entries.push((key, replacement));
    entries.sort_by_key(|(candidate, _)| *candidate);
    Ok(CborValue::Map(entries))
}

fn refresh_claims_hash(envelope: &mut DaylightEnvelopeV6) -> Result<(), DaylightCryptoError> {
    envelope.header.claims_hash = hc_v6(&envelope.aux_block.claims_obj)?;
    Ok(())
}

fn refresh_keyset_hash(envelope: &mut DaylightEnvelopeV6) -> Result<(), DaylightCryptoError> {
    envelope.header.keyset_hash = hc_v6(&envelope.aux_block.keyset_obj)?;
    Ok(())
}

fn claim_cbor(claim_class: u8, claim_name: &str, claim_value: CborValue) -> CborValue {
    CborValue::Map(vec![
        (0, CborValue::UInt(u64::from(claim_class))),
        (1, CborValue::Text(claim_name.to_string())),
        (2, claim_value),
    ])
}

fn nightlight_failure_counts(
    cases: &[crate::v6::DaylightV6ReferenceNegativeCase],
) -> Vec<NightlightFailureCountV6> {
    let order = [
        DaylightOpenFailure::Parse,
        DaylightOpenFailure::Suite,
        DaylightOpenFailure::Env,
        DaylightOpenFailure::Mode,
        DaylightOpenFailure::Policy,
        DaylightOpenFailure::Gate,
        DaylightOpenFailure::Provenance,
        DaylightOpenFailure::Install,
        DaylightOpenFailure::Witness,
        DaylightOpenFailure::Log,
        DaylightOpenFailure::LogMonotone,
        DaylightOpenFailure::Claim,
        DaylightOpenFailure::NoDowngrade,
        DaylightOpenFailure::AuthQ,
        DaylightOpenFailure::AuthH,
        DaylightOpenFailure::AuthFUnsupported,
        DaylightOpenFailure::Nonce,
        DaylightOpenFailure::Derive,
        DaylightOpenFailure::Aead,
        DaylightOpenFailure::Commit,
        DaylightOpenFailure::Leak,
    ];
    order
        .iter()
        .filter_map(|failure| {
            let count = cases
                .iter()
                .filter(|case| case.actual_failure == *failure)
                .count();
            (count > 0).then_some(NightlightFailureCountV6 {
                failure: *failure,
                count,
            })
        })
        .collect()
}

fn nightlight_rejection_stage_counts(
    cases: &[NightlightPublicSimulationCaseV6],
) -> Vec<NightlightRejectionStageCountV6> {
    let order = [
        DaylightRejectionStageV6::RejectParse,
        DaylightRejectionStageV6::RejectSchema,
        DaylightRejectionStageV6::RejectSuite,
        DaylightRejectionStageV6::RejectAuxHash,
        DaylightRejectionStageV6::RejectPolicy,
        DaylightRejectionStageV6::RejectClaims,
        DaylightRejectionStageV6::RejectKemBlock,
        DaylightRejectionStageV6::RejectAuthBlock,
        DaylightRejectionStageV6::RejectAuthSignature,
        DaylightRejectionStageV6::RejectReview,
        DaylightRejectionStageV6::RejectDowngrade,
        DaylightRejectionStageV6::RejectLog,
        DaylightRejectionStageV6::RejectInstall,
        DaylightRejectionStageV6::RejectWitness,
        DaylightRejectionStageV6::RejectDecap,
        DaylightRejectionStageV6::RejectAead,
        DaylightRejectionStageV6::RejectPayload,
        DaylightRejectionStageV6::RejectCommit,
        DaylightRejectionStageV6::RejectLeak,
    ];
    order
        .iter()
        .filter_map(|stage| {
            let count = cases
                .iter()
                .filter(|case| case.actual_stage == *stage)
                .count();
            (count > 0).then_some(NightlightRejectionStageCountV6 {
                stage: *stage,
                count,
            })
        })
        .collect()
}

fn nightlight_negative_case_material(
    cases: &[crate::v6::DaylightV6ReferenceNegativeCase],
) -> Vec<u8> {
    let mut material = Vec::new();
    for case in cases {
        material.extend_from_slice(case.case_id.as_bytes());
        material.push(b'|');
        material.extend_from_slice(case.mutation.as_bytes());
        material.push(b'|');
        material.extend_from_slice(daylight_open_failure_name_v6(case.expected_failure).as_bytes());
        material.push(b'|');
        material.extend_from_slice(daylight_open_failure_name_v6(case.actual_failure).as_bytes());
        material.push(b'|');
        material.push(u8::from(case.public_precheck_required));
        material.push(b'|');
        material.push(u8::from(case.private_path_reached));
        material.push(b'\n');
    }
    material
}

fn nightlight_public_simulation_material(cases: &[NightlightPublicSimulationCaseV6]) -> Vec<u8> {
    let mut material = Vec::new();
    for case in cases {
        material.extend_from_slice(case.case_id.as_bytes());
        material.push(b'|');
        material.extend_from_slice(case.mutation.as_bytes());
        material.push(b'|');
        material.extend_from_slice(case.expected_stage.as_str().as_bytes());
        material.push(b'|');
        material.extend_from_slice(case.actual_stage.as_str().as_bytes());
        material.push(b'|');
        material.push(u8::from(case.fail_closed));
        material.push(b'|');
        material.push(u8::from(case.private_path_reached));
        material.push(b'\n');
    }
    material
}

fn nightlight_battery_material(
    artifact_hash: [u8; 64],
    schema_omega_hash: [u8; 64],
    private_omega_hash: [u8; 64],
    reference_omega_hash: [u8; 64],
    negative_case_set_hash: [u8; 64],
    public_simulation_case_set_hash: [u8; 64],
    equation_checks_total: usize,
    efficiency_checks_total: usize,
    adversarial_cases_total: usize,
    public_precheck_stop_count: usize,
    private_path_mutation_count: usize,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(NIGHTLIGHT_V6_EQUATION_BATTERY_SCHEMA.as_bytes());
    material.extend_from_slice(&artifact_hash);
    material.extend_from_slice(&schema_omega_hash);
    material.extend_from_slice(&private_omega_hash);
    material.extend_from_slice(&reference_omega_hash);
    material.extend_from_slice(&negative_case_set_hash);
    material.extend_from_slice(&public_simulation_case_set_hash);
    push_u64(&mut material, equation_checks_total);
    push_u64(&mut material, efficiency_checks_total);
    push_u64(&mut material, adversarial_cases_total);
    push_u64(&mut material, public_precheck_stop_count);
    push_u64(&mut material, private_path_mutation_count);
    material
}

fn push_u64(material: &mut Vec<u8>, value: usize) {
    material.extend_from_slice(&(value as u64).to_be_bytes());
}

#[derive(Clone)]
struct NightlightArmAccumulator {
    arm_id: &'static str,
    category: &'static str,
    risk_weight: u64,
    cases_total: usize,
    fail_closed_cases: usize,
    private_path_reach_count: usize,
    public_stages: Vec<DaylightRejectionStageV6>,
}

impl NightlightArmAccumulator {
    fn new(arm_id: &'static str, category: &'static str, risk_weight: u64) -> Self {
        Self {
            arm_id,
            category,
            risk_weight,
            cases_total: 0,
            fail_closed_cases: 0,
            private_path_reach_count: 0,
            public_stages: Vec::new(),
        }
    }

    fn add_public(&mut self, case: &NightlightPublicSimulationCaseV6) {
        self.cases_total += 1;
        self.fail_closed_cases += usize::from(case.fail_closed);
        self.private_path_reach_count += usize::from(case.private_path_reached);
        if !self.public_stages.contains(&case.actual_stage) {
            self.public_stages.push(case.actual_stage);
        }
    }

    fn add_reference(&mut self, case: &crate::v6::DaylightV6ReferenceNegativeCase) {
        self.cases_total += 1;
        self.fail_closed_cases += usize::from(case.expected_failure == case.actual_failure);
        self.private_path_reach_count += usize::from(case.private_path_reached);
    }

    fn finish(self) -> Option<NightlightLearningArmV6> {
        if self.cases_total == 0 {
            return None;
        }
        let unique_public_stages = self.public_stages.len();
        let novelty_score = (unique_public_stages as u64 * 125)
            + (self.private_path_reach_count as u64 * 175)
            + (self.cases_total as u64 * 25);
        let fail_closed_score = (self.fail_closed_cases as u64 * 1000) / self.cases_total as u64;
        let learned_priority = (self.risk_weight * 10) + novelty_score + fail_closed_score;
        Some(NightlightLearningArmV6 {
            arm_id: self.arm_id,
            category: self.category,
            cases_total: self.cases_total,
            fail_closed_cases: self.fail_closed_cases,
            private_path_reach_count: self.private_path_reach_count,
            unique_public_stages,
            risk_weight: self.risk_weight,
            novelty_score,
            learned_priority,
        })
    }
}

fn nightlight_learning_arms(
    battery: &NightlightV6EquationBattery,
    negative_cases: &[crate::v6::DaylightV6ReferenceNegativeCase],
) -> Vec<NightlightLearningArmV6> {
    let mut accumulators = vec![
        NightlightArmAccumulator::new("parser", "malformed input parser boundary", 70),
        NightlightArmAccumulator::new("schema", "typed envelope schema boundary", 75),
        NightlightArmAccumulator::new("suite", "suite and mode downgrade boundary", 90),
        NightlightArmAccumulator::new("aux_hash", "auxiliary object hash binding", 95),
        NightlightArmAccumulator::new("policy", "static policy gate", 85),
        NightlightArmAccumulator::new("claims", "claim class and shape gate", 80),
        NightlightArmAccumulator::new("kem_shape", "KEM identifier and shape gate", 105),
        NightlightArmAccumulator::new("auth_shape", "authorization block shape gate", 105),
        NightlightArmAccumulator::new("authorization", "public authorization boundary", 115),
        NightlightArmAccumulator::new("review", "review receipt gate", 90),
        NightlightArmAccumulator::new("downgrade", "downgrade denial gate", 95),
        NightlightArmAccumulator::new("log", "log evidence gate", 85),
        NightlightArmAccumulator::new("witness", "witness evidence gate", 85),
        NightlightArmAccumulator::new("reference_auth", "reference authorization denial", 115),
        NightlightArmAccumulator::new("reference_gate", "reference public gate denial", 95),
        NightlightArmAccumulator::new("reference_policy", "reference policy denial", 85),
        NightlightArmAccumulator::new("reference_claim", "reference claim denial", 80),
        NightlightArmAccumulator::new("reference_log", "reference log denial", 85),
        NightlightArmAccumulator::new("reference_install", "reference install denial", 90),
        NightlightArmAccumulator::new("reference_witness", "reference witness denial", 90),
        NightlightArmAccumulator::new(
            "reference_private",
            "reference private mutation denial",
            120,
        ),
    ];

    for case in &battery.public_simulation_cases {
        if let Some(arm) = accumulators
            .iter_mut()
            .find(|arm| arm.arm_id == public_case_arm_id(case.actual_stage))
        {
            arm.add_public(case);
        }
    }
    for case in negative_cases {
        if let Some(arm) = accumulators
            .iter_mut()
            .find(|arm| arm.arm_id == reference_case_arm_id(case.actual_failure))
        {
            arm.add_reference(case);
        }
    }

    accumulators
        .into_iter()
        .filter_map(NightlightArmAccumulator::finish)
        .collect()
}

fn public_case_arm_id(stage: DaylightRejectionStageV6) -> &'static str {
    match stage {
        DaylightRejectionStageV6::RejectParse => "parser",
        DaylightRejectionStageV6::RejectSchema => "schema",
        DaylightRejectionStageV6::RejectSuite => "suite",
        DaylightRejectionStageV6::RejectAuxHash => "aux_hash",
        DaylightRejectionStageV6::RejectPolicy => "policy",
        DaylightRejectionStageV6::RejectClaims => "claims",
        DaylightRejectionStageV6::RejectKemBlock => "kem_shape",
        DaylightRejectionStageV6::RejectAuthBlock => "auth_shape",
        DaylightRejectionStageV6::RejectAuthSignature => "authorization",
        DaylightRejectionStageV6::RejectReview => "review",
        DaylightRejectionStageV6::RejectDowngrade => "downgrade",
        DaylightRejectionStageV6::RejectLog => "log",
        DaylightRejectionStageV6::RejectWitness => "witness",
        _ => "schema",
    }
}

fn reference_case_arm_id(failure: DaylightOpenFailure) -> &'static str {
    match failure {
        DaylightOpenFailure::AuthQ | DaylightOpenFailure::AuthH => "reference_auth",
        DaylightOpenFailure::Gate | DaylightOpenFailure::NoDowngrade => "reference_gate",
        DaylightOpenFailure::Policy => "reference_policy",
        DaylightOpenFailure::Claim => "reference_claim",
        DaylightOpenFailure::Log => "reference_log",
        DaylightOpenFailure::Install => "reference_install",
        DaylightOpenFailure::Witness => "reference_witness",
        DaylightOpenFailure::Aead
        | DaylightOpenFailure::Commit
        | DaylightOpenFailure::Derive
        | DaylightOpenFailure::Leak
        | DaylightOpenFailure::Nonce => "reference_private",
        _ => "reference_gate",
    }
}

fn nightlight_public_stage_targets() -> [DaylightRejectionStageV6; 14] {
    [
        DaylightRejectionStageV6::RejectParse,
        DaylightRejectionStageV6::RejectSchema,
        DaylightRejectionStageV6::RejectSuite,
        DaylightRejectionStageV6::RejectAuxHash,
        DaylightRejectionStageV6::RejectPolicy,
        DaylightRejectionStageV6::RejectClaims,
        DaylightRejectionStageV6::RejectKemBlock,
        DaylightRejectionStageV6::RejectAuthBlock,
        DaylightRejectionStageV6::RejectAuthSignature,
        DaylightRejectionStageV6::RejectReview,
        DaylightRejectionStageV6::RejectDowngrade,
        DaylightRejectionStageV6::RejectLog,
        DaylightRejectionStageV6::RejectInstall,
        DaylightRejectionStageV6::RejectWitness,
    ]
}

fn nightlight_private_failure_targets() -> [DaylightOpenFailure; 4] {
    [
        DaylightOpenFailure::Derive,
        DaylightOpenFailure::Aead,
        DaylightOpenFailure::Commit,
        DaylightOpenFailure::Leak,
    ]
}

fn learning_rationale(arm_id: &str) -> &'static str {
    match arm_id {
        "reference_private" => "private mutation cases exercise late fail-closed commitments",
        "authorization" => "authorization remains the final public fail-closed boundary",
        "kem_shape" => "KEM shape gates protect provider-backed derivation inputs",
        "auth_shape" => "auth block shape gates protect signature verification inputs",
        "aux_hash" => "aux hash binding prevents unbound policy/keyset/claim substitution",
        "suite" => "suite and mode checks protect downgrade boundaries",
        "review" => "review gates protect content-scope escalation",
        "downgrade" => "downgrade gates protect release and mode floors",
        "reference_auth" => "reference auth denial keeps private Open behind public authority",
        _ => "coverage-learning selected this arm by risk and novelty score",
    }
}

fn nightlight_learning_recommendations(
    battery: &NightlightV6EquationBattery,
) -> Vec<NightlightLearningRecommendationV6> {
    let mut recommendations = Vec::new();
    if !has_public_stage(battery, DaylightRejectionStageV6::RejectInstall) {
        recommendations.push(NightlightLearningRecommendationV6 {
            rank: 0,
            gap_id: "missing_public_install_stage",
            target: "add install-action public validation simulation",
            rationale: "public stage targets include REJECT_INSTALL but the current public corpus does not reach it",
            priority: 980,
        });
    }
    if !has_private_failure(battery, DaylightOpenFailure::Derive) {
        recommendations.push(NightlightLearningRecommendationV6 {
            rank: 0,
            gap_id: "missing_private_derive_failure",
            target: "add deterministic bad-recipient-key decapsulation denial",
            rationale: "private failure targets include Derive while current private mutations cover AEAD and Commit",
            priority: 960,
        });
    }
    if !has_private_failure(battery, DaylightOpenFailure::Leak) {
        recommendations.push(NightlightLearningRecommendationV6 {
            rank: 0,
            gap_id: "missing_private_leak_failure",
            target: "add deterministic leak-value mismatch denial",
            rationale: "leak validation is a late boundary and should have a direct defensive regression case",
            priority: 940,
        });
    }
    if public_stage_count(battery, DaylightRejectionStageV6::RejectAuthSignature) <= 1 {
        recommendations.push(NightlightLearningRecommendationV6 {
            rank: 0,
            gap_id: "sparse_auth_signature_stage",
            target: "add more public authorization-denial variants",
            rationale: "REJECT_AUTH_SIGNATURE is the intended final public boundary and currently has sparse variants",
            priority: 900,
        });
    }
    if public_stage_count(battery, DaylightRejectionStageV6::RejectReview) <= 2 {
        recommendations.push(NightlightLearningRecommendationV6 {
            rank: 0,
            gap_id: "sparse_review_stage",
            target: "add review receipt shape and hash-binding simulations",
            rationale:
                "review gates protect content-scope escalation and need broader defensive coverage",
            priority: 860,
        });
    }
    if public_stage_count(battery, DaylightRejectionStageV6::RejectLog) <= 1
        || public_stage_count(battery, DaylightRejectionStageV6::RejectWitness) <= 1
    {
        recommendations.push(NightlightLearningRecommendationV6 {
            rank: 0,
            gap_id: "sparse_log_witness_stages",
            target: "add log and witness object-shape simulations",
            rationale:
                "log and witness gates are represented but still shallow in the public corpus",
            priority: 830,
        });
    }

    recommendations.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.gap_id.cmp(right.gap_id))
    });
    for (index, recommendation) in recommendations.iter_mut().enumerate() {
        recommendation.rank = index + 1;
    }
    recommendations
}

fn has_public_stage(
    battery: &NightlightV6EquationBattery,
    stage: DaylightRejectionStageV6,
) -> bool {
    public_stage_count(battery, stage) > 0
}

fn public_stage_count(
    battery: &NightlightV6EquationBattery,
    stage: DaylightRejectionStageV6,
) -> usize {
    battery
        .public_simulation_stage_counts
        .iter()
        .find(|count| count.stage == stage)
        .map(|count| count.count)
        .unwrap_or(0)
}

fn has_private_failure(
    battery: &NightlightV6EquationBattery,
    failure: DaylightOpenFailure,
) -> bool {
    battery
        .failure_counts
        .iter()
        .any(|count| count.failure == failure)
}

fn nightlight_learning_material(
    battery: &NightlightV6EquationBattery,
    arms: &[NightlightLearningArmV6],
    epochs: &[NightlightLearningEpochV6],
    recommendations: &[NightlightLearningRecommendationV6],
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(NIGHTLIGHT_V6_DEEP_ASSESSMENT_SCHEMA.as_bytes());
    material.extend_from_slice(&battery.battery_hash);
    push_u64(&mut material, battery.adversarial_cases_total);
    for arm in arms {
        material.extend_from_slice(arm.arm_id.as_bytes());
        material.push(b'|');
        material.extend_from_slice(arm.category.as_bytes());
        push_u64(&mut material, arm.cases_total);
        push_u64(&mut material, arm.fail_closed_cases);
        push_u64(&mut material, arm.private_path_reach_count);
        push_u64(&mut material, arm.unique_public_stages);
        push_u64(&mut material, arm.risk_weight as usize);
        push_u64(&mut material, arm.novelty_score as usize);
        push_u64(&mut material, arm.learned_priority as usize);
    }
    for epoch in epochs {
        push_u64(&mut material, epoch.epoch);
        material.extend_from_slice(epoch.selected_arm.as_bytes());
        push_u64(&mut material, epoch.learned_priority as usize);
    }
    for recommendation in recommendations {
        push_u64(&mut material, recommendation.rank);
        material.extend_from_slice(recommendation.gap_id.as_bytes());
        material.push(b'|');
        material.extend_from_slice(recommendation.target.as_bytes());
        push_u64(&mut material, recommendation.priority as usize);
    }
    material
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex_lower;

    #[test]
    fn nightlight_v6_equation_battery_holds() {
        let battery = nightlight_v6_equation_battery().unwrap();
        assert_eq!(battery.schema, NIGHTLIGHT_V6_EQUATION_BATTERY_SCHEMA);
        assert_eq!(battery.score_delta, 0);
        assert!(!battery.production_allowed);
        assert!(!battery.runtime_containment_claim);
        assert!(!battery.whole_system_post_quantum_safety_claim);
        assert!(!battery.offensive_logic_added);
        assert!(!battery.network_required);
        assert!(battery.open_ended_gate);
        assert!(battery.equation_holds);
        assert_eq!(battery.equation_checks_failed, 0);
        assert!(battery.efficiency_holds);
        assert_eq!(battery.efficiency_checks_failed, 0);
        assert!(battery.defensive_battery_ready);
        assert!(battery.total_negative_cases >= battery.minimum_reference_negative_cases);
        assert_eq!(
            battery.fail_closed_negative_cases,
            battery.total_negative_cases
        );
        assert!(battery.public_simulation_cases_total >= battery.minimum_public_simulation_cases);
        assert_eq!(
            battery.public_simulation_fail_closed_cases,
            battery.public_simulation_cases_total
        );
        assert!(battery.public_simulation_all_fail_closed);
        assert_eq!(
            battery.adversarial_cases_total,
            battery.total_negative_cases + battery.public_simulation_cases_total
        );
        assert_eq!(
            battery.adversarial_cases_fail_closed,
            battery.fail_closed_negative_cases + battery.public_simulation_fail_closed_cases
        );
        assert!(battery.public_precheck_stop_count >= 10);
        assert!(battery.private_path_mutation_count >= 2);
        assert_eq!(
            battery.private_path_reach_count,
            battery.private_path_mutation_count
        );
        assert!(battery
            .public_simulation_stage_counts
            .iter()
            .any(|count| count.stage == DaylightRejectionStageV6::RejectParse));
        assert!(battery
            .public_simulation_stage_counts
            .iter()
            .any(|count| count.stage == DaylightRejectionStageV6::RejectAuthSignature));
        assert_ne!(
            battery.private_ciphertext_hash,
            battery.reference_ciphertext_hash
        );
        assert_ne!(battery.private_com_a_hash, battery.reference_com_a_hash);
    }

    #[test]
    fn nightlight_v6_equation_battery_file_matches_implementation() {
        let fields = parse_vector_file(include_str!(
            "../vectors/nightlight-v6-equation-battery-v1.txt"
        ));
        let battery = nightlight_v6_equation_battery().unwrap();

        assert_eq!(vector_field(&fields, "version"), battery.schema);
        assert_eq!(vector_field(&fields, "subject"), battery.subject);
        assert_eq!(vector_field(&fields, "profile"), battery.profile);
        assert_eq!(
            vector_field(&fields, "scope"),
            "no-network-no-offensive-logic"
        );
        assert_eq!(
            vector_field(&fields, "expected_result"),
            "defensive_battery_ready"
        );
        assert_eq!(
            vector_field(&fields, "score_delta"),
            battery.score_delta.to_string()
        );
        assert_eq!(
            vector_field(&fields, "production_allowed"),
            battery.production_allowed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "runtime_containment_claim"),
            battery.runtime_containment_claim.to_string()
        );
        assert_eq!(
            vector_field(&fields, "whole_system_post_quantum_safety_claim"),
            battery.whole_system_post_quantum_safety_claim.to_string()
        );
        assert_eq!(
            vector_field(&fields, "offensive_logic_added"),
            battery.offensive_logic_added.to_string()
        );
        assert_eq!(
            vector_field(&fields, "network_required"),
            battery.network_required.to_string()
        );
        assert_eq!(
            vector_field(&fields, "open_ended_gate"),
            battery.open_ended_gate.to_string()
        );
        assert_eq!(
            vector_field(&fields, "minimum_reference_negative_cases"),
            battery.minimum_reference_negative_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "minimum_public_simulation_cases"),
            battery.minimum_public_simulation_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "equation_checks_total"),
            battery.equation_checks_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "equation_checks_failed"),
            battery.equation_checks_failed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "equation_holds"),
            battery.equation_holds.to_string()
        );
        assert_eq!(
            vector_field(&fields, "efficiency_checks_total"),
            battery.efficiency_checks_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "efficiency_checks_failed"),
            battery.efficiency_checks_failed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "efficiency_holds"),
            battery.efficiency_holds.to_string()
        );
        assert_eq!(
            vector_field(&fields, "defensive_battery_ready"),
            battery.defensive_battery_ready.to_string()
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_kem"),
            battery.provider_backed_kem.to_string()
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_private_roundtrip"),
            battery.provider_backed_private_roundtrip.to_string()
        );
        assert_eq!(
            vector_field(&fields, "provider_backed_reference_seal_open"),
            battery.provider_backed_reference_seal_open.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_authority_external"),
            battery.public_authority_external.to_string()
        );
        assert_eq!(
            vector_field(&fields, "schema_public_precheck_rejection_stage"),
            battery.schema_public_precheck_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "private_public_precheck_rejection_stage"),
            battery.private_public_precheck_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "reference_public_precheck_rejection_stage"),
            battery.reference_public_precheck_rejection_stage.as_str()
        );
        assert_eq!(
            vector_field(&fields, "total_negative_cases"),
            battery.total_negative_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "fail_closed_negative_cases"),
            battery.fail_closed_negative_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_simulation_cases_total"),
            battery.public_simulation_cases_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_simulation_fail_closed_cases"),
            battery.public_simulation_fail_closed_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_simulation_all_fail_closed"),
            battery.public_simulation_all_fail_closed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "adversarial_cases_total"),
            battery.adversarial_cases_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "adversarial_cases_fail_closed"),
            battery.adversarial_cases_fail_closed.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_precheck_stop_count"),
            battery.public_precheck_stop_count.to_string()
        );
        assert_eq!(
            vector_field(&fields, "private_path_mutation_count"),
            battery.private_path_mutation_count.to_string()
        );
        assert_eq!(
            vector_field(&fields, "private_path_reach_count"),
            battery.private_path_reach_count.to_string()
        );
        for failure_count in &battery.failure_counts {
            let key = format!(
                "failure_count_{}",
                daylight_open_failure_name_v6(failure_count.failure)
            );
            assert_eq!(vector_field(&fields, &key), failure_count.count.to_string());
        }
        for stage_count in &battery.public_simulation_stage_counts {
            let key = format!("public_stage_count_{}", stage_count.stage.as_str());
            assert_eq!(vector_field(&fields, &key), stage_count.count.to_string());
        }
        for (index, case) in battery.public_simulation_cases.iter().enumerate() {
            let key = format!("public_simulation_case_{:02}", index + 1);
            let expected = format!(
                "{}|{}|expected={}|actual={}|fail_closed={}|private_path_reached={}",
                case.case_id,
                case.mutation,
                case.expected_stage.as_str(),
                case.actual_stage.as_str(),
                case.fail_closed,
                case.private_path_reached
            );
            assert_eq!(vector_field(&fields, &key), expected);
        }
        assert_eq!(
            vector_field(&fields, "artifact_sha3_512_hex"),
            hex_lower(&battery.artifact_hash)
        );
        assert_eq!(
            vector_field(&fields, "schema_omega_sha3_512_hex"),
            hex_lower(&battery.schema_omega_hash)
        );
        assert_eq!(
            vector_field(&fields, "private_omega_sha3_512_hex"),
            hex_lower(&battery.private_omega_hash)
        );
        assert_eq!(
            vector_field(&fields, "reference_omega_sha3_512_hex"),
            hex_lower(&battery.reference_omega_hash)
        );
        assert_eq!(
            vector_field(&fields, "private_ciphertext_sha3_512_hex"),
            hex_lower(&battery.private_ciphertext_hash)
        );
        assert_eq!(
            vector_field(&fields, "reference_ciphertext_sha3_512_hex"),
            hex_lower(&battery.reference_ciphertext_hash)
        );
        assert_eq!(
            vector_field(&fields, "private_com_a_sha3_512_hex"),
            hex_lower(&battery.private_com_a_hash)
        );
        assert_eq!(
            vector_field(&fields, "reference_com_a_sha3_512_hex"),
            hex_lower(&battery.reference_com_a_hash)
        );
        assert_eq!(
            vector_field(&fields, "negative_case_set_sha3_512_hex"),
            hex_lower(&battery.negative_case_set_hash)
        );
        assert_eq!(
            vector_field(&fields, "public_simulation_case_set_sha3_512_hex"),
            hex_lower(&battery.public_simulation_case_set_hash)
        );
        assert_eq!(
            vector_field(&fields, "battery_sha3_512_hex"),
            hex_lower(&battery.battery_hash)
        );
    }

    #[test]
    fn nightlight_v6_deep_assessment_holds() {
        let assessment = nightlight_v6_deep_assessment().unwrap();

        assert_eq!(assessment.schema, NIGHTLIGHT_V6_DEEP_ASSESSMENT_SCHEMA);
        assert_eq!(
            assessment.subject,
            "Nightlight_Daylight_v6_deep_learning_assessment"
        );
        assert_eq!(assessment.algorithm, "deterministic-coverage-learning-v1");
        assert!(assessment.defensive_only);
        assert!(assessment.learning_enabled);
        assert!(!assessment.offensive_logic_added);
        assert!(!assessment.network_required);
        assert_eq!(assessment.score_delta, 0);
        assert_eq!(
            assessment.input_adversarial_cases,
            assessment.fail_closed_cases
        );
        assert!(assessment.input_adversarial_cases >= 57);
        assert_eq!(assessment.learning_epochs, NIGHTLIGHT_LEARNING_EPOCHS);
        assert!(assessment.learning_arms_total >= 20);
        assert_eq!(assessment.public_stage_target_total, 14);
        assert!(assessment.public_stage_covered >= 13);
        assert_eq!(
            assessment.public_stage_gap_count,
            assessment.public_stage_target_total - assessment.public_stage_covered
        );
        assert_eq!(assessment.private_failure_target_total, 4);
        assert!(assessment.private_failure_covered >= 2);
        assert_eq!(
            assessment.private_failure_gap_count,
            assessment.private_failure_target_total - assessment.private_failure_covered
        );
        assert!(assessment.recommendations_total >= 3);
        assert!(assessment.top_priority >= 900);
        assert_eq!(assessment.arms.len(), assessment.learning_arms_total);
        assert_eq!(assessment.epochs.len(), assessment.learning_epochs);
        assert_eq!(
            assessment.recommendations.len(),
            assessment.recommendations_total
        );
        assert!(assessment.arms.windows(2).all(|window| {
            window[0].learned_priority > window[1].learned_priority
                || (window[0].learned_priority == window[1].learned_priority
                    && window[0].arm_id <= window[1].arm_id)
        }));
        assert!(assessment
            .arms
            .iter()
            .all(|arm| arm.cases_total == arm.fail_closed_cases));
        assert!(assessment.epochs.iter().all(|epoch| assessment
            .arms
            .iter()
            .any(|arm| arm.arm_id == epoch.selected_arm)));
        assert!(assessment
            .recommendations
            .iter()
            .any(|recommendation| recommendation.gap_id == "missing_public_install_stage"));
        assert!(assessment
            .recommendations
            .iter()
            .any(|recommendation| recommendation.gap_id == "missing_private_derive_failure"));
        assert!(assessment
            .recommendations
            .iter()
            .any(|recommendation| recommendation.gap_id == "missing_private_leak_failure"));
    }

    #[test]
    fn nightlight_v6_deep_assessment_file_matches_implementation() {
        let fields = parse_vector_file(include_str!(
            "../vectors/nightlight-v6-deep-assault-assessment-v1.txt"
        ));
        let assessment = nightlight_v6_deep_assessment().unwrap();

        assert_eq!(vector_field(&fields, "version"), assessment.schema);
        assert_eq!(vector_field(&fields, "subject"), assessment.subject);
        assert_eq!(vector_field(&fields, "algorithm"), assessment.algorithm);
        assert_eq!(
            vector_field(&fields, "expected_result"),
            "learning_guided_gap_assessment"
        );
        assert_eq!(
            vector_field(&fields, "defensive_only"),
            assessment.defensive_only.to_string()
        );
        assert_eq!(
            vector_field(&fields, "learning_enabled"),
            assessment.learning_enabled.to_string()
        );
        assert_eq!(
            vector_field(&fields, "offensive_logic_added"),
            assessment.offensive_logic_added.to_string()
        );
        assert_eq!(
            vector_field(&fields, "network_required"),
            assessment.network_required.to_string()
        );
        assert_eq!(
            vector_field(&fields, "score_delta"),
            assessment.score_delta.to_string()
        );
        assert_eq!(
            vector_field(&fields, "input_adversarial_cases"),
            assessment.input_adversarial_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "fail_closed_cases"),
            assessment.fail_closed_cases.to_string()
        );
        assert_eq!(
            vector_field(&fields, "learning_epochs"),
            assessment.learning_epochs.to_string()
        );
        assert_eq!(
            vector_field(&fields, "learning_arms_total"),
            assessment.learning_arms_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_stage_target_total"),
            assessment.public_stage_target_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_stage_covered"),
            assessment.public_stage_covered.to_string()
        );
        assert_eq!(
            vector_field(&fields, "public_stage_gap_count"),
            assessment.public_stage_gap_count.to_string()
        );
        assert_eq!(
            vector_field(&fields, "private_failure_target_total"),
            assessment.private_failure_target_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "private_failure_covered"),
            assessment.private_failure_covered.to_string()
        );
        assert_eq!(
            vector_field(&fields, "private_failure_gap_count"),
            assessment.private_failure_gap_count.to_string()
        );
        assert_eq!(
            vector_field(&fields, "recommendations_total"),
            assessment.recommendations_total.to_string()
        );
        assert_eq!(
            vector_field(&fields, "top_priority"),
            assessment.top_priority.to_string()
        );
        for (index, arm) in assessment.arms.iter().enumerate() {
            let expected = format!(
                "{}|{}|cases={}|fail_closed={}|private_path_reach={}|unique_public_stages={}|risk_weight={}|novelty={}|priority={}",
                arm.arm_id,
                arm.category,
                arm.cases_total,
                arm.fail_closed_cases,
                arm.private_path_reach_count,
                arm.unique_public_stages,
                arm.risk_weight,
                arm.novelty_score,
                arm.learned_priority
            );
            assert_eq!(
                vector_field(&fields, &format!("learning_arm_{:02}", index + 1)),
                expected
            );
        }
        for (index, epoch) in assessment.epochs.iter().enumerate() {
            let expected = format!(
                "epoch={}|arm={}|priority={}|rationale={}",
                epoch.epoch, epoch.selected_arm, epoch.learned_priority, epoch.rationale
            );
            assert_eq!(
                vector_field(&fields, &format!("learning_epoch_{:02}", index + 1)),
                expected
            );
        }
        for recommendation in &assessment.recommendations {
            let expected = format!(
                "{}|target={}|priority={}|rationale={}",
                recommendation.gap_id,
                recommendation.target,
                recommendation.priority,
                recommendation.rationale
            );
            assert_eq!(
                vector_field(
                    &fields,
                    &format!("learning_recommendation_{:02}", recommendation.rank)
                ),
                expected
            );
        }
        assert_eq!(
            vector_field(&fields, "learning_hash_hex"),
            hex_lower(&assessment.learning_hash)
        );
    }

    fn parse_vector_file(input: &str) -> Vec<(String, String)> {
        input
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (key, value) = line.split_once('=').expect("vector line must contain '='");
                (key.to_string(), value.to_string())
            })
            .collect()
    }

    fn vector_field(fields: &[(String, String)], key: &str) -> String {
        fields
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("missing vector field: {key}"))
    }
}
