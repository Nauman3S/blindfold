use std::cmp::Reverse;

use crate::Finding;

/// Resolves overlapping findings deterministically.
///
/// Higher confidence wins, then the longer span, then the earlier span. The
/// returned findings are sorted by ascending byte position.
#[must_use]
pub fn resolve_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_unstable_by_key(|finding| {
        (
            Reverse(finding.confidence()),
            Reverse(finding.span().len()),
            finding.span().start(),
            finding.kind(),
        )
    });

    let mut selected: Vec<Finding> = Vec::with_capacity(findings.len());
    for finding in findings {
        if selected
            .iter()
            .all(|existing| !existing.span().overlaps(finding.span()))
        {
            selected.push(finding);
        }
    }
    selected.sort_unstable_by_key(|finding| (finding.span().start(), finding.span().end()));
    selected
}

#[cfg(test)]
mod tests {
    use crate::{Confidence, Finding, SecretKind, Span};

    use super::resolve_overlaps;

    fn span(start: usize, end: usize) -> Span {
        Span::new(start, end)
            .unwrap_or_else(|error| unreachable!("test span must be valid: {error}"))
    }

    #[test]
    fn confidence_then_length_determine_winner() {
        let findings = vec![
            Finding::new(
                SecretKind::Token,
                span(2, 20),
                Confidence::Contextual,
                "context",
            ),
            Finding::new(
                SecretKind::GitHubToken,
                span(4, 18),
                Confidence::Certain,
                "github",
            ),
            Finding::new(SecretKind::ApiKey, span(30, 35), Confidence::High, "short"),
            Finding::new(SecretKind::ApiKey, span(29, 36), Confidence::High, "long"),
        ];

        let resolved = resolve_overlaps(findings);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].kind(), SecretKind::GitHubToken);
        assert_eq!(resolved[1].span(), span(29, 36));
    }
}
