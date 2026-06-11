//! Integration and property-like tests for the public detector API.

use blindfold_detectors::{
    DetectorSet, DotenvCatalog, RedactionMode, RedactionOptions, Redactor, SecretKind,
};

const FIXTURE: &str = include_str!("fixtures/sample.env");

fn detectors() -> DetectorSet {
    DetectorSet::new()
        .unwrap_or_else(|error| unreachable!("embedded detector patterns must compile: {error}"))
}

#[test]
fn fixture_detection_has_precise_non_overlapping_spans() {
    let findings = detectors().detect(FIXTURE);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].kind(), SecretKind::OpenAiApiKey);
    assert_eq!(findings[1].kind(), SecretKind::CredentialUrl);

    for window in findings.windows(2) {
        assert!(window[0].span().end() <= window[1].span().start());
    }
    assert_eq!(&FIXTURE[findings[1].span().as_range()], "s3cr3t-value");
}

#[test]
fn env_reference_mode_uses_catalog_and_falls_back_safely() {
    let catalog = DotenvCatalog::parse(FIXTURE);
    let input =
        "first=sk-proj-abcdefghijklmnopqrstuvwxyz012345 second=xoxb-1234567890-abcdefghijkl";
    let output = Redactor::new(detectors())
        .redact(
            input,
            RedactionOptions::new(RedactionMode::EnvRef).with_dotenv(&catalog),
        )
        .unwrap_or_else(|error| unreachable!("redaction must succeed: {error}"));

    assert_eq!(
        output.text(),
        "first=${OPENAI_API_KEY} second=[REDACTED:slack_token]"
    );
}

#[test]
fn arbitrary_ascii_inputs_preserve_span_and_redaction_invariants() {
    let detector_set = detectors();
    let redactor = Redactor::new(
        DetectorSet::new()
            .unwrap_or_else(|error| unreachable!("embedded patterns must compile: {error}")),
    );
    let alphabet = b"abcXYZ019_-.:=/ \n";
    let mut state = 0x5eed_u64;

    for length in 0..256 {
        let mut input = String::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            input.push(char::from(alphabet[(state as usize) % alphabet.len()]));
        }
        let findings = detector_set.detect(&input);
        for finding in &findings {
            assert!(finding.span().start() < finding.span().end());
            assert!(finding.span().end() <= input.len());
            assert!(input.get(finding.span().as_range()).is_some());
        }
        for window in findings.windows(2) {
            assert!(window[0].span().end() <= window[1].span().start());
        }
        let output = redactor
            .redact(&input, RedactionOptions::new(RedactionMode::Placeholder))
            .unwrap_or_else(|error| unreachable!("valid spans must redact: {error}"));
        assert!(!output.text().contains('\0'));
    }
}
