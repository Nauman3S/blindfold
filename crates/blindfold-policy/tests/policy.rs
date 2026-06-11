//! Integration tests for destination-aware policy behavior.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use blindfold_core::{Action, Destination, SecretKind, Sensitivity, Source};
use blindfold_policy::{
    AllowReason, AllowRule, DecisionAction, DecisionBasis, DenyRule, Operation, Policy,
    PolicyError, Preset, Request, RuleId, RuleScope, SourceContext,
};

const PRESETS: [Preset; 4] = [Preset::Chill, Preset::Balanced, Preset::Strict, Preset::Ci];
const OPERATIONS: [Operation; 2] = [Operation::Disclose, Operation::Restore];
const KINDS: [SecretKind; 8] = [
    SecretKind::ApiKey,
    SecretKind::Token,
    SecretKind::Password,
    SecretKind::PrivateKey,
    SecretKind::Certificate,
    SecretKind::CredentialUrl,
    SecretKind::PersonallyIdentifiableInformation,
    SecretKind::Other,
];
const SENSITIVITIES: [Sensitivity; 5] = [
    Sensitivity::Public,
    Sensitivity::Internal,
    Sensitivity::Confidential,
    Sensitivity::Secret,
    Sensitivity::Restricted,
];
const SOURCES: [SourceContext; 9] = [
    SourceContext::Environment,
    SourceContext::File,
    SourceContext::StandardInput,
    SourceContext::ProcessOutput,
    SourceContext::Request,
    SourceContext::Response,
    SourceContext::Tool,
    SourceContext::Unknown,
    SourceContext::Unsupported,
];
const DESTINATIONS: [Destination; 9] = [
    Destination::ModelProvider,
    Destination::Agent,
    Destination::Tool,
    Destination::ChildProcess,
    Destination::File,
    Destination::Log,
    Destination::Audit,
    Destination::User,
    Destination::TrustedLocal,
];

#[test]
fn complete_builtin_matrix_is_deterministic_and_matches_contract() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let mut evaluated = 0_u32;

    for preset in PRESETS {
        let policy = Policy::preset(preset);
        for operation in OPERATIONS {
            for kind in KINDS {
                for sensitivity in SENSITIVITIES {
                    for source in SOURCES {
                        for destination in DESTINATIONS {
                            let request =
                                Request::new(operation, kind, sensitivity, source, destination);
                            let first = policy.evaluate_at(request, now);
                            let second = policy.evaluate_at(request, now);
                            let expected = expected_action(
                                preset,
                                operation,
                                kind,
                                sensitivity,
                                source,
                                destination,
                            );

                            assert_eq!(first, second);
                            assert_eq!(first.action(), expected);
                            assert_eq!(first.explanation().basis(), expected_basis(request));
                            assert_eq!(first.explanation().action(), expected);
                            assert_eq!(first.explanation().preset(), preset);
                            assert_eq!(first.explanation().operation(), operation);
                            assert_eq!(first.explanation().kind(), kind);
                            assert_eq!(first.explanation().sensitivity(), sensitivity);
                            assert_eq!(first.explanation().source(), source);
                            assert_eq!(first.explanation().destination(), destination);
                            assert_eq!(first.explanation().rule_id(), None);
                            assert_eq!(first.explanation().allow_reason(), None);
                            evaluated += 1;
                        }
                    }
                }
            }
        }
    }

    assert_eq!(evaluated, 25_920);
}

#[test]
fn explicit_deny_wins_over_explicit_allow_regardless_of_rule_order() {
    let scope =
        RuleScope::new(Operation::Restore, Destination::ChildProcess).with_kind(SecretKind::ApiKey);
    let first_deny = DenyRule::new(RuleId::new(90), scope);
    let selected_deny = DenyRule::new(RuleId::new(4), scope);
    let allow = AllowRule::new(RuleId::new(3), scope, AllowReason::RequiredOperation);
    let request = Request::new(
        Operation::Restore,
        SecretKind::ApiKey,
        Sensitivity::Secret,
        SourceContext::Environment,
        Destination::ChildProcess,
    );
    let now = SystemTime::UNIX_EPOCH;

    for policy in [
        Policy::new(Preset::Chill, vec![first_deny, selected_deny], vec![allow]),
        Policy::new(Preset::Chill, vec![selected_deny, first_deny], vec![allow]),
    ] {
        let decision = policy.evaluate_at(request, now);
        assert_eq!(decision.action(), DecisionAction::Block);
        assert_eq!(decision.explanation().basis(), DecisionBasis::ExplicitDeny);
        assert_eq!(decision.explanation().rule_id(), Some(RuleId::new(4)));
    }
}

#[test]
fn restoration_requires_active_explicit_allow_and_trusted_destination() {
    let expiry = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let scope = RuleScope::new(Operation::Restore, Destination::TrustedLocal)
        .with_kind(SecretKind::Token)
        .with_source(SourceContext::Environment);
    let policy = Policy::new(
        Preset::Balanced,
        Vec::new(),
        vec![
            AllowRule::new(RuleId::new(7), scope, AllowReason::RequiredOperation)
                .expiring_at(expiry),
        ],
    );
    let request = Request::new(
        Operation::Restore,
        SecretKind::Token,
        Sensitivity::Secret,
        SourceContext::Environment,
        Destination::TrustedLocal,
    );

    let active = policy.evaluate_at(request, expiry - Duration::from_nanos(1));
    assert_eq!(active.action(), DecisionAction::Restore);
    assert_eq!(active.action().as_core_action(), Action::Allow);
    assert_eq!(active.explanation().basis(), DecisionBasis::ExplicitAllow);
    assert_eq!(active.explanation().rule_id(), Some(RuleId::new(7)));
    assert_eq!(
        active.explanation().allow_reason(),
        Some(AllowReason::RequiredOperation)
    );

    let expired = policy.evaluate_at(request, expiry);
    assert_eq!(expired.action(), DecisionAction::Block);
    assert_eq!(expired.explanation().basis(), DecisionBasis::Preset);

    for destination in DESTINATIONS {
        if matches!(
            destination,
            Destination::ChildProcess | Destination::TrustedLocal
        ) {
            continue;
        }
        let invalid = Policy::new(
            Preset::Balanced,
            Vec::new(),
            vec![AllowRule::new(
                RuleId::new(8),
                RuleScope::new(Operation::Restore, destination).with_kind(SecretKind::Token),
                AllowReason::RequiredOperation,
            )],
        );
        assert_eq!(
            invalid.validation_error(),
            Some(PolicyError::UntrustedRestoreDestination)
        );
    }
}

#[test]
fn invariant_denies_raw_secrets_to_untrusted_destinations_even_with_allow() {
    for destination in [
        Destination::ModelProvider,
        Destination::Agent,
        Destination::Tool,
        Destination::Log,
        Destination::Audit,
    ] {
        let scope =
            RuleScope::new(Operation::Disclose, destination).with_sensitivity(Sensitivity::Secret);
        let policy = Policy::new(
            Preset::Chill,
            Vec::new(),
            vec![AllowRule::new(
                RuleId::new(1),
                scope,
                AllowReason::Compatibility,
            )],
        );
        let decision = policy.evaluate_at(
            Request::new(
                Operation::Disclose,
                SecretKind::Password,
                Sensitivity::Secret,
                SourceContext::File,
                destination,
            ),
            SystemTime::UNIX_EPOCH,
        );

        assert_eq!(decision.action(), DecisionAction::Block);
        assert_eq!(decision.explanation().basis(), DecisionBasis::Invariant);
        assert_eq!(decision.explanation().rule_id(), None);
    }
}

#[test]
fn invalid_policy_blocks_every_request_without_exposing_rule_details() {
    let duplicate = RuleId::new(42);
    let policy = Policy::new(
        Preset::Chill,
        vec![DenyRule::new(
            duplicate,
            RuleScope::new(Operation::Disclose, Destination::File),
        )],
        vec![AllowRule::new(
            duplicate,
            RuleScope::new(Operation::Disclose, Destination::User)
                .with_sensitivity(Sensitivity::Public),
            AllowReason::TestFixture,
        )],
    );
    assert_eq!(
        policy.validation_error(),
        Some(PolicyError::DuplicateRuleId)
    );

    for destination in DESTINATIONS {
        let decision = policy.evaluate_at(
            Request::new(
                Operation::Disclose,
                SecretKind::Other,
                Sensitivity::Public,
                SourceContext::StandardInput,
                destination,
            ),
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(decision.action(), DecisionAction::Block);
        assert_eq!(decision.explanation().basis(), DecisionBasis::InvalidPolicy);
        assert_eq!(decision.explanation().rule_id(), None);
    }

    let overbroad = Policy::new(
        Preset::Balanced,
        Vec::new(),
        vec![AllowRule::new(
            RuleId::new(1),
            RuleScope::new(Operation::Restore, Destination::ChildProcess),
            AllowReason::RequiredOperation,
        )],
    );
    assert_eq!(
        overbroad.validation_error(),
        Some(PolicyError::OverbroadAllowRule)
    );

    let unsupported_source = Policy::new(
        Preset::Balanced,
        Vec::new(),
        vec![AllowRule::new(
            RuleId::new(2),
            RuleScope::new(Operation::Disclose, Destination::File)
                .with_source(SourceContext::Unsupported),
            AllowReason::Compatibility,
        )],
    );
    assert_eq!(
        unsupported_source.validation_error(),
        Some(PolicyError::UnsupportedSource)
    );
}

#[test]
fn source_reduction_and_explanations_do_not_copy_dynamic_metadata() {
    let path_marker = "private-path-marker";
    let variable_marker = "PRIVATE_VARIABLE_MARKER";
    let tool_marker = "private-tool-marker";
    let cases = [
        (
            Source::File(PathBuf::from(path_marker)),
            SourceContext::File,
            path_marker,
        ),
        (
            Source::EnvironmentVariable(variable_marker.to_owned()),
            SourceContext::Environment,
            variable_marker,
        ),
        (
            Source::Tool(tool_marker.to_owned()),
            SourceContext::Tool,
            tool_marker,
        ),
    ];

    for (source, expected_source, marker) in cases {
        let request = Request::from_source(
            Operation::Disclose,
            SecretKind::Other,
            Sensitivity::Confidential,
            &source,
            Destination::ModelProvider,
        );
        let decision =
            Policy::preset(Preset::Balanced).evaluate_at(request, SystemTime::UNIX_EPOCH);
        let debug = format!("{decision:?}");

        assert_eq!(request.source(), expected_source);
        assert!(!debug.contains(marker));
    }
}

fn expected_basis(request: Request) -> DecisionBasis {
    if is_invariant(request) {
        DecisionBasis::Invariant
    } else {
        DecisionBasis::Preset
    }
}

fn expected_action(
    preset: Preset,
    operation: Operation,
    kind: SecretKind,
    sensitivity: Sensitivity,
    source: SourceContext,
    destination: Destination,
) -> DecisionAction {
    let request = Request::new(operation, kind, sensitivity, source, destination);
    if is_invariant(request) {
        return DecisionAction::Block;
    }
    if operation == Operation::Restore {
        return DecisionAction::Block;
    }
    if sensitivity == Sensitivity::Public {
        return DecisionAction::Allow;
    }
    if sensitivity == Sensitivity::Restricted
        || (kind == SecretKind::PrivateKey && sensitivity >= Sensitivity::Secret)
    {
        return DecisionAction::Block;
    }
    if source == SourceContext::Unknown {
        return match preset {
            Preset::Chill | Preset::Balanced => DecisionAction::Redact,
            Preset::Strict | Preset::Ci => DecisionAction::Block,
        };
    }
    if source == SourceContext::Environment && sensitivity >= Sensitivity::Confidential {
        return DecisionAction::Redact;
    }

    match preset {
        Preset::Chill => expected_chill(sensitivity, destination),
        Preset::Balanced => expected_balanced(sensitivity, destination),
        Preset::Strict => expected_strict(sensitivity, destination),
        Preset::Ci => expected_ci(sensitivity),
    }
}

fn expected_chill(sensitivity: Sensitivity, destination: Destination) -> DecisionAction {
    match sensitivity {
        Sensitivity::Internal => match destination {
            Destination::ModelProvider | Destination::Log | Destination::Audit => {
                DecisionAction::Redact
            }
            Destination::Agent | Destination::Tool => DecisionAction::Warn,
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Allow,
            _ => DecisionAction::Block,
        },
        Sensitivity::Confidential => match destination {
            Destination::ChildProcess | Destination::File | Destination::User => {
                DecisionAction::Warn
            }
            Destination::TrustedLocal => DecisionAction::Allow,
            Destination::ModelProvider
            | Destination::Agent
            | Destination::Tool
            | Destination::Log
            | Destination::Audit => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        Sensitivity::Secret => match destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        _ => DecisionAction::Block,
    }
}

fn expected_balanced(sensitivity: Sensitivity, destination: Destination) -> DecisionAction {
    match sensitivity {
        Sensitivity::Internal => match destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Allow,
            Destination::ModelProvider
            | Destination::Agent
            | Destination::Tool
            | Destination::Log
            | Destination::Audit => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        Sensitivity::Confidential => match destination {
            Destination::TrustedLocal => DecisionAction::Allow,
            Destination::ModelProvider
            | Destination::Agent
            | Destination::Tool
            | Destination::ChildProcess
            | Destination::File
            | Destination::Log
            | Destination::Audit
            | Destination::User => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        Sensitivity::Secret => match destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        _ => DecisionAction::Block,
    }
}

fn expected_strict(sensitivity: Sensitivity, destination: Destination) -> DecisionAction {
    match sensitivity {
        Sensitivity::Internal => match destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Warn,
            Destination::ModelProvider
            | Destination::Agent
            | Destination::Tool
            | Destination::Log
            | Destination::Audit => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        Sensitivity::Confidential | Sensitivity::Secret => match destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        _ => DecisionAction::Block,
    }
}

fn expected_ci(sensitivity: Sensitivity) -> DecisionAction {
    match sensitivity {
        Sensitivity::Internal | Sensitivity::Confidential => DecisionAction::Redact,
        _ => DecisionAction::Block,
    }
}

fn is_invariant(request: Request) -> bool {
    request.source() == SourceContext::Unsupported
        || (request.operation() == Operation::Restore
            && !matches!(
                request.destination(),
                Destination::ChildProcess | Destination::TrustedLocal
            ))
        || (request.operation() == Operation::Disclose
            && request.sensitivity() >= Sensitivity::Secret
            && matches!(
                request.destination(),
                Destination::ModelProvider
                    | Destination::Agent
                    | Destination::Tool
                    | Destination::Log
                    | Destination::Audit
            ))
}
