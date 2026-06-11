//! Destination-aware policy decisions for Blindfold.
//!
//! The policy engine is deliberately deterministic when called through
//! [`Policy::evaluate_at`]: every input, including the clock used for expiring allow
//! rules, is supplied by the caller. Invalid policy fails closed. Explicit deny rules
//! take precedence over allow rules, and allow rules cannot override hard security
//! invariants.
//!
//! Explanations contain only typed, non-sensitive metadata. In particular, source
//! paths, environment-variable names, tool names, and free-form rule text are never
//! copied into a [`Decision`].

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::time::SystemTime;

use blindfold_core::{Action, Destination, SecretKind, Sensitivity, Source};

/// A built-in policy profile.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Preset {
    /// Lower-friction handling for local interactive work.
    Chill,
    /// General-purpose handling that balances usability and disclosure prevention.
    #[default]
    Balanced,
    /// Conservative handling that rejects unknown sensitive source contexts.
    Strict,
    /// Non-interactive handling with redacted output and prohibited-finding failures.
    Ci,
}

/// The operation being authorized.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operation {
    /// Move a detected raw value across a destination boundary.
    Disclose,
    /// Resolve a `SafeRef` and provide its plaintext to a destination.
    Restore,
}

/// A source classification that cannot contain source names, paths, or values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceContext {
    /// Content read from an environment variable.
    Environment,
    /// Content read from a file.
    File,
    /// Content received on standard input.
    StandardInput,
    /// Content captured from a child process.
    ProcessOutput,
    /// Content received in an inbound request.
    Request,
    /// Content received in an upstream response.
    Response,
    /// Content crossing a tool boundary.
    Tool,
    /// Content whose origin is not known.
    Unknown,
    /// A future source variant unknown to this policy crate.
    Unsupported,
}

impl From<&Source> for SourceContext {
    fn from(source: &Source) -> Self {
        match source {
            Source::EnvironmentVariable(_) => Self::Environment,
            Source::File(_) => Self::File,
            Source::StandardInput => Self::StandardInput,
            Source::ProcessOutput => Self::ProcessOutput,
            Source::Request => Self::Request,
            Source::Response => Self::Response,
            Source::Tool(_) => Self::Tool,
            Source::Unknown => Self::Unknown,
            _ => Self::Unsupported,
        }
    }
}

/// Inputs used for one policy decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    operation: Operation,
    kind: SecretKind,
    sensitivity: Sensitivity,
    source: SourceContext,
    destination: Destination,
}

impl Request {
    /// Creates a request from safe, already-classified metadata.
    #[must_use]
    pub const fn new(
        operation: Operation,
        kind: SecretKind,
        sensitivity: Sensitivity,
        source: SourceContext,
        destination: Destination,
    ) -> Self {
        Self {
            operation,
            kind,
            sensitivity,
            source,
            destination,
        }
    }

    /// Creates a request while reducing a core source to safe source context.
    #[must_use]
    pub fn from_source(
        operation: Operation,
        kind: SecretKind,
        sensitivity: Sensitivity,
        source: &Source,
        destination: Destination,
    ) -> Self {
        Self::new(
            operation,
            kind,
            sensitivity,
            SourceContext::from(source),
            destination,
        )
    }

    /// Returns the requested operation.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Returns the detector classification.
    #[must_use]
    pub const fn kind(self) -> SecretKind {
        self.kind
    }

    /// Returns the sensitivity classification.
    #[must_use]
    pub const fn sensitivity(self) -> Sensitivity {
        self.sensitivity
    }

    /// Returns the safe source classification.
    #[must_use]
    pub const fn source(self) -> SourceContext {
        self.source
    }

    /// Returns the destination boundary.
    #[must_use]
    pub const fn destination(self) -> Destination {
        self.destination
    }
}

/// A policy result with explicit restoration semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecisionAction {
    /// Permit the original value to cross the boundary.
    Allow,
    /// Replace the value with a restorable `SafeRef`.
    Redact,
    /// Permit the operation while surfacing a safe warning.
    Warn,
    /// Refuse the operation.
    Block,
    /// Resolve a `SafeRef` and provide plaintext to the authorized destination.
    Restore,
}

impl DecisionAction {
    /// Converts the decision to the closest core boundary action.
    ///
    /// Restoration maps to [`Action::Allow`] because restoration authorization is
    /// represented explicitly by this type before the plaintext crosses the boundary.
    #[must_use]
    pub const fn as_core_action(self) -> Action {
        match self {
            Self::Allow | Self::Restore => Action::Allow,
            Self::Redact => Action::ReplaceWithSafeRef,
            Self::Warn => Action::Warn,
            Self::Block => Action::Block,
        }
    }
}

/// Stable justification attached to an explicit allow rule.
///
/// This closed enum avoids placing arbitrary text into decisions, logs, or diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AllowReason {
    /// A reviewed local operation requires the value.
    RequiredOperation,
    /// A reviewed compatibility path temporarily requires the value.
    Compatibility,
    /// A synthetic fixture requires the value during testing.
    TestFixture,
    /// A time-bounded incident response operation requires the value.
    IncidentResponse,
}

/// A stable numeric identifier for a policy rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleId(u64);

impl RuleId {
    /// Creates a rule identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric rule identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A rule scope with an exact operation and destination.
///
/// Optional dimensions act as wildcards. Requiring operation and destination keeps
/// allow rules bound to a concrete boundary and prevents a broad global allow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleScope {
    operation: Operation,
    destination: Destination,
    kind: Option<SecretKind>,
    sensitivity: Option<Sensitivity>,
    source: Option<SourceContext>,
}

impl RuleScope {
    /// Creates a scope for an exact operation and destination.
    #[must_use]
    pub const fn new(operation: Operation, destination: Destination) -> Self {
        Self {
            operation,
            destination,
            kind: None,
            sensitivity: None,
            source: None,
        }
    }

    /// Restricts the scope to one detector classification.
    #[must_use]
    pub const fn with_kind(mut self, kind: SecretKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Restricts the scope to one sensitivity.
    #[must_use]
    pub const fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = Some(sensitivity);
        self
    }

    /// Restricts the scope to one safe source context.
    #[must_use]
    pub const fn with_source(mut self, source: SourceContext) -> Self {
        self.source = Some(source);
        self
    }

    /// Returns the scoped operation.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Returns the scoped destination.
    #[must_use]
    pub const fn destination(self) -> Destination {
        self.destination
    }

    /// Returns the optional detector-class restriction.
    #[must_use]
    pub const fn kind(self) -> Option<SecretKind> {
        self.kind
    }

    /// Returns the optional sensitivity restriction.
    #[must_use]
    pub const fn sensitivity(self) -> Option<Sensitivity> {
        self.sensitivity
    }

    /// Returns the optional source-context restriction.
    #[must_use]
    pub const fn source(self) -> Option<SourceContext> {
        self.source
    }

    fn matches(self, request: Request) -> bool {
        self.operation == request.operation
            && self.destination == request.destination
            && self.kind.is_none_or(|kind| kind == request.kind)
            && self
                .sensitivity
                .is_none_or(|sensitivity| sensitivity == request.sensitivity)
            && self.source.is_none_or(|source| source == request.source)
    }
}

/// An explicit deny rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenyRule {
    id: RuleId,
    scope: RuleScope,
}

impl DenyRule {
    /// Creates an explicit deny rule.
    #[must_use]
    pub const fn new(id: RuleId, scope: RuleScope) -> Self {
        Self { id, scope }
    }

    /// Returns the stable rule identifier.
    #[must_use]
    pub const fn id(self) -> RuleId {
        self.id
    }

    /// Returns the rule scope.
    #[must_use]
    pub const fn scope(self) -> RuleScope {
        self.scope
    }
}

/// An explicit allow rule with a safe reason and optional expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowRule {
    id: RuleId,
    scope: RuleScope,
    reason: AllowReason,
    expires_at: Option<SystemTime>,
}

impl AllowRule {
    /// Creates an allow rule that does not expire.
    #[must_use]
    pub const fn new(id: RuleId, scope: RuleScope, reason: AllowReason) -> Self {
        Self {
            id,
            scope,
            reason,
            expires_at: None,
        }
    }

    /// Adds an absolute expiry. The rule is inactive at and after this instant.
    #[must_use]
    pub const fn expiring_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Returns the stable rule identifier.
    #[must_use]
    pub const fn id(self) -> RuleId {
        self.id
    }

    /// Returns the rule scope.
    #[must_use]
    pub const fn scope(self) -> RuleScope {
        self.scope
    }

    /// Returns the reviewed reason.
    #[must_use]
    pub const fn reason(self) -> AllowReason {
        self.reason
    }

    /// Returns the optional absolute expiry.
    #[must_use]
    pub const fn expires_at(self) -> Option<SystemTime> {
        self.expires_at
    }

    fn is_active(self, now: SystemTime) -> bool {
        self.expires_at.is_none_or(|expiry| now < expiry)
    }
}

/// The safe reason a decision was selected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecisionBasis {
    /// A hard security invariant denied the operation.
    Invariant,
    /// The policy was invalid and therefore failed closed.
    InvalidPolicy,
    /// An explicit deny rule matched.
    ExplicitDeny,
    /// An explicit active allow rule matched.
    ExplicitAllow,
    /// The selected preset supplied the result.
    Preset,
}

/// Safe metadata explaining a policy result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Explanation {
    preset: Preset,
    operation: Operation,
    kind: SecretKind,
    sensitivity: Sensitivity,
    source: SourceContext,
    destination: Destination,
    action: DecisionAction,
    basis: DecisionBasis,
    rule_id: Option<RuleId>,
    allow_reason: Option<AllowReason>,
}

impl Explanation {
    /// Returns the active preset.
    #[must_use]
    pub const fn preset(self) -> Preset {
        self.preset
    }

    /// Returns the evaluated operation.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Returns the detector classification.
    #[must_use]
    pub const fn kind(self) -> SecretKind {
        self.kind
    }

    /// Returns the sensitivity.
    #[must_use]
    pub const fn sensitivity(self) -> Sensitivity {
        self.sensitivity
    }

    /// Returns the reduced source context.
    #[must_use]
    pub const fn source(self) -> SourceContext {
        self.source
    }

    /// Returns the destination.
    #[must_use]
    pub const fn destination(self) -> Destination {
        self.destination
    }

    /// Returns the selected action.
    #[must_use]
    pub const fn action(self) -> DecisionAction {
        self.action
    }

    /// Returns the precedence tier that selected the action.
    #[must_use]
    pub const fn basis(self) -> DecisionBasis {
        self.basis
    }

    /// Returns the matched rule identifier, when a rule selected the action.
    #[must_use]
    pub const fn rule_id(self) -> Option<RuleId> {
        self.rule_id
    }

    /// Returns the reviewed allow reason when an allow rule selected the action.
    #[must_use]
    pub const fn allow_reason(self) -> Option<AllowReason> {
        self.allow_reason
    }
}

/// A policy result and its safe explanation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    action: DecisionAction,
    explanation: Explanation,
}

impl Decision {
    /// Returns the selected action.
    #[must_use]
    pub const fn action(self) -> DecisionAction {
        self.action
    }

    /// Returns safe, structured explanation metadata.
    #[must_use]
    pub const fn explanation(self) -> Explanation {
        self.explanation
    }

    /// Returns whether the operation may continue.
    ///
    /// Redaction may continue after replacement; warning may continue after the caller
    /// surfaces a safe warning. Only [`DecisionAction::Block`] refuses the operation.
    #[must_use]
    pub const fn permits_operation(self) -> bool {
        !matches!(self.action, DecisionAction::Block)
    }
}

/// A fail-closed policy validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PolicyError {
    /// Two rules use the same identifier.
    DuplicateRuleId,
    /// A restoration allow rule targets an untrusted destination.
    UntrustedRestoreDestination,
    /// An allow rule does not restrict kind, sensitivity, or source.
    OverbroadAllowRule,
    /// A future unsupported destination appears in a rule.
    UnsupportedDestination,
    /// A future unsupported source context appears in a rule.
    UnsupportedSource,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DuplicateRuleId => "policy contains duplicate rule identifiers",
            Self::UntrustedRestoreDestination => {
                "policy allows restoration to an untrusted destination"
            }
            Self::OverbroadAllowRule => "policy contains an overbroad allow rule",
            Self::UnsupportedDestination => "policy rule contains an unsupported destination",
            Self::UnsupportedSource => "policy rule contains an unsupported source",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PolicyError {}

/// A validated-or-fail-closed policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    preset: Preset,
    deny_rules: Vec<DenyRule>,
    allow_rules: Vec<AllowRule>,
    validation_error: Option<PolicyError>,
}

impl Policy {
    /// Creates a preset policy without explicit rules.
    #[must_use]
    pub fn preset(preset: Preset) -> Self {
        Self::new(preset, Vec::new(), Vec::new())
    }

    /// Creates and validates a policy.
    ///
    /// Invalid policy remains representable so every subsequent evaluation can fail
    /// closed. Call [`Policy::validation_error`] during configuration loading to reject
    /// invalid policy before serving requests.
    #[must_use]
    pub fn new(preset: Preset, deny_rules: Vec<DenyRule>, allow_rules: Vec<AllowRule>) -> Self {
        let validation_error = validate_rules(&deny_rules, &allow_rules).err();
        Self {
            preset,
            deny_rules,
            allow_rules,
            validation_error,
        }
    }

    /// Returns the active preset.
    #[must_use]
    pub const fn active_preset(&self) -> Preset {
        self.preset
    }

    /// Returns the validation failure that causes all decisions to block.
    #[must_use]
    pub const fn validation_error(&self) -> Option<PolicyError> {
        self.validation_error
    }

    /// Evaluates a request using the system clock for allow-rule expiry.
    ///
    /// Use [`Policy::evaluate_at`] where reproducibility or clock control is required.
    #[must_use]
    pub fn evaluate(&self, request: Request) -> Decision {
        self.evaluate_at(request, SystemTime::now())
    }

    /// Deterministically evaluates a request at a caller-supplied instant.
    ///
    /// Precedence is hard invariant, invalid policy, explicit deny, active explicit
    /// allow, then preset default.
    #[must_use]
    pub fn evaluate_at(&self, request: Request, now: SystemTime) -> Decision {
        if violates_invariant(request) {
            return self.decision(
                request,
                DecisionAction::Block,
                DecisionBasis::Invariant,
                None,
            );
        }
        if self.validation_error.is_some() {
            return self.decision(
                request,
                DecisionAction::Block,
                DecisionBasis::InvalidPolicy,
                None,
            );
        }
        if let Some(rule) = self
            .deny_rules
            .iter()
            .copied()
            .filter(|rule| rule.scope.matches(request))
            .min_by_key(|rule| rule.id)
        {
            return self.decision(
                request,
                DecisionAction::Block,
                DecisionBasis::ExplicitDeny,
                Some((rule.id, None)),
            );
        }
        if let Some(rule) = self
            .allow_rules
            .iter()
            .copied()
            .filter(|rule| rule.scope.matches(request) && rule.is_active(now))
            .min_by_key(|rule| rule.id)
        {
            let action = match request.operation {
                Operation::Disclose => DecisionAction::Allow,
                Operation::Restore => DecisionAction::Restore,
            };
            return self.decision(
                request,
                action,
                DecisionBasis::ExplicitAllow,
                Some((rule.id, Some(rule.reason))),
            );
        }

        self.decision(
            request,
            preset_action(self.preset, request),
            DecisionBasis::Preset,
            None,
        )
    }

    fn decision(
        &self,
        request: Request,
        action: DecisionAction,
        basis: DecisionBasis,
        rule: Option<(RuleId, Option<AllowReason>)>,
    ) -> Decision {
        let (rule_id, allow_reason) = rule.map_or((None, None), |(id, reason)| (Some(id), reason));
        Decision {
            action,
            explanation: Explanation {
                preset: self.preset,
                operation: request.operation,
                kind: request.kind,
                sensitivity: request.sensitivity,
                source: request.source,
                destination: request.destination,
                action,
                basis,
                rule_id,
                allow_reason,
            },
        }
    }
}

fn validate_rules(deny_rules: &[DenyRule], allow_rules: &[AllowRule]) -> Result<(), PolicyError> {
    let mut ids = HashSet::with_capacity(deny_rules.len() + allow_rules.len());
    for (id, scope) in deny_rules
        .iter()
        .map(|rule| (rule.id, rule.scope))
        .chain(allow_rules.iter().map(|rule| (rule.id, rule.scope)))
    {
        if !ids.insert(id) {
            return Err(PolicyError::DuplicateRuleId);
        }
        validate_scope(scope)?;
    }
    for rule in allow_rules {
        if rule.scope.kind.is_none()
            && rule.scope.sensitivity.is_none()
            && rule.scope.source.is_none()
        {
            return Err(PolicyError::OverbroadAllowRule);
        }
        if rule.scope.operation == Operation::Restore
            && !is_trusted_restore_destination(rule.scope.destination)
        {
            return Err(PolicyError::UntrustedRestoreDestination);
        }
    }
    Ok(())
}

fn validate_scope(scope: RuleScope) -> Result<(), PolicyError> {
    if !is_known_destination(scope.destination) {
        return Err(PolicyError::UnsupportedDestination);
    }
    if scope.source == Some(SourceContext::Unsupported) {
        return Err(PolicyError::UnsupportedSource);
    }
    Ok(())
}

const fn is_known_destination(destination: Destination) -> bool {
    matches!(
        destination,
        Destination::ModelProvider
            | Destination::Agent
            | Destination::Tool
            | Destination::ChildProcess
            | Destination::File
            | Destination::Log
            | Destination::Audit
            | Destination::User
            | Destination::TrustedLocal
    )
}

const fn is_trusted_restore_destination(destination: Destination) -> bool {
    matches!(
        destination,
        Destination::ChildProcess | Destination::TrustedLocal
    )
}

fn violates_invariant(request: Request) -> bool {
    if !is_known_destination(request.destination)
        || request.source == SourceContext::Unsupported
        || !is_known_sensitivity(request.sensitivity)
        || !is_known_kind(request.kind)
    {
        return true;
    }

    match request.operation {
        Operation::Restore => !is_trusted_restore_destination(request.destination),
        Operation::Disclose => {
            request.sensitivity >= Sensitivity::Secret
                && matches!(
                    request.destination,
                    Destination::ModelProvider
                        | Destination::Agent
                        | Destination::Tool
                        | Destination::Log
                        | Destination::Audit
                )
        }
    }
}

const fn is_known_sensitivity(sensitivity: Sensitivity) -> bool {
    matches!(
        sensitivity,
        Sensitivity::Public
            | Sensitivity::Internal
            | Sensitivity::Confidential
            | Sensitivity::Secret
            | Sensitivity::Restricted
    )
}

const fn is_known_kind(kind: SecretKind) -> bool {
    matches!(
        kind,
        SecretKind::ApiKey
            | SecretKind::Token
            | SecretKind::Password
            | SecretKind::PrivateKey
            | SecretKind::Certificate
            | SecretKind::CredentialUrl
            | SecretKind::PersonallyIdentifiableInformation
            | SecretKind::Other
    )
}

fn preset_action(preset: Preset, request: Request) -> DecisionAction {
    if request.operation == Operation::Restore {
        return DecisionAction::Block;
    }
    if request.sensitivity == Sensitivity::Public {
        return DecisionAction::Allow;
    }
    if request.sensitivity == Sensitivity::Restricted
        || (request.kind == SecretKind::PrivateKey && request.sensitivity >= Sensitivity::Secret)
    {
        return DecisionAction::Block;
    }
    if request.source == SourceContext::Unknown {
        return match preset {
            Preset::Chill | Preset::Balanced => DecisionAction::Redact,
            Preset::Strict | Preset::Ci => DecisionAction::Block,
        };
    }
    if request.source == SourceContext::Environment
        && request.sensitivity >= Sensitivity::Confidential
    {
        return DecisionAction::Redact;
    }

    match preset {
        Preset::Chill => chill_action(request),
        Preset::Balanced => balanced_action(request),
        Preset::Strict => strict_action(request),
        Preset::Ci => ci_action(request),
    }
}

fn chill_action(request: Request) -> DecisionAction {
    match request.sensitivity {
        Sensitivity::Internal => match request.destination {
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
        Sensitivity::Confidential => match request.destination {
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
        Sensitivity::Secret => match request.destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        _ => DecisionAction::Block,
    }
}

fn balanced_action(request: Request) -> DecisionAction {
    match request.sensitivity {
        Sensitivity::Internal => match request.destination {
            Destination::ModelProvider
            | Destination::Agent
            | Destination::Tool
            | Destination::Log
            | Destination::Audit => DecisionAction::Redact,
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Allow,
            _ => DecisionAction::Block,
        },
        Sensitivity::Confidential => match request.destination {
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
        Sensitivity::Secret => match request.destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        _ => DecisionAction::Block,
    }
}

fn strict_action(request: Request) -> DecisionAction {
    match request.sensitivity {
        Sensitivity::Internal => match request.destination {
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
        Sensitivity::Confidential | Sensitivity::Secret => match request.destination {
            Destination::ChildProcess
            | Destination::File
            | Destination::User
            | Destination::TrustedLocal => DecisionAction::Redact,
            _ => DecisionAction::Block,
        },
        _ => DecisionAction::Block,
    }
}

fn ci_action(request: Request) -> DecisionAction {
    match request.sensitivity {
        Sensitivity::Internal | Sensitivity::Confidential => DecisionAction::Redact,
        _ => DecisionAction::Block,
    }
}
