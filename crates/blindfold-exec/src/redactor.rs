const REDACTION: &[u8] = b"[REDACTED]";

pub(crate) struct StreamingRedactor {
    patterns: Vec<Vec<u8>>,
    maximum_pattern_length: usize,
    pending: Vec<u8>,
    output: BoundedOutput,
    bytes_read: u64,
    redactions: u64,
}

impl StreamingRedactor {
    pub(crate) fn new(patterns: &[Vec<u8>], output_limit: usize) -> Self {
        let mut patterns = patterns.to_vec();
        patterns.sort_unstable_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        patterns.dedup();
        let maximum_pattern_length = patterns.iter().map(Vec::len).max().unwrap_or(1);
        Self {
            patterns,
            maximum_pattern_length,
            pending: Vec::new(),
            output: BoundedOutput::new(output_limit),
            bytes_read: 0,
            redactions: 0,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.bytes_read = self
            .bytes_read
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.pending.extend_from_slice(bytes);
        self.process(false);
    }

    pub(crate) fn finish(mut self) -> RedactionSummary {
        self.process(true);
        RedactionSummary {
            output: self.output.bytes,
            bytes_read: self.bytes_read,
            redactions: self.redactions,
            truncated: self.output.truncated,
        }
    }

    fn process(&mut self, at_end: bool) {
        let process_before = if at_end {
            self.pending.len()
        } else {
            self.pending
                .len()
                .saturating_sub(self.maximum_pattern_length.saturating_sub(1))
        };
        let mut cursor = 0;

        while cursor < process_before {
            if let Some(pattern_length) = self.match_length(cursor) {
                self.output.push(REDACTION);
                self.redactions = self.redactions.saturating_add(1);
                cursor += pattern_length;
            } else {
                self.output.push(&self.pending[cursor..=cursor]);
                cursor += 1;
            }
        }
        self.pending.drain(..cursor);
    }

    fn match_length(&self, offset: usize) -> Option<usize> {
        self.patterns
            .iter()
            .find(|pattern| self.pending[offset..].starts_with(pattern))
            .map(Vec::len)
    }
}

pub(crate) struct RedactionSummary {
    pub(crate) output: Vec<u8>,
    pub(crate) bytes_read: u64,
    pub(crate) redactions: u64,
    pub(crate) truncated: bool,
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl BoundedOutput {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            truncated: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let available = self.limit.saturating_sub(self.bytes.len());
        let retained = available.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..retained]);
        self.truncated |= retained < bytes.len();
    }
}

#[cfg(test)]
mod tests {
    use super::StreamingRedactor;

    #[test]
    fn redacts_every_split_without_a_newline() {
        let secret = b"split-secret-value".to_vec();
        for split in 0..=secret.len() {
            let mut redactor = StreamingRedactor::new(std::slice::from_ref(&secret), 1024);
            redactor.push(&secret[..split]);
            redactor.push(&secret[split..]);
            let result = redactor.finish();

            assert_eq!(result.output, b"[REDACTED]");
            assert_eq!(result.redactions, 1);
        }
    }

    #[test]
    fn handles_overlapping_and_duplicate_patterns() {
        let patterns = vec![b"token".to_vec(), b"token-long".to_vec(), b"token".to_vec()];
        let mut redactor = StreamingRedactor::new(&patterns, 1024);
        redactor.push(b"token-long token");
        let result = redactor.finish();

        assert_eq!(result.output, b"[REDACTED] [REDACTED]");
        assert_eq!(result.redactions, 2);
    }

    #[test]
    fn bounds_expanding_redacted_output() {
        let mut redactor = StreamingRedactor::new(&[b"x".to_vec()], 12);
        redactor.push(b"xxxx");
        let result = redactor.finish();

        assert_eq!(result.output.len(), 12);
        assert!(result.truncated);
        assert_eq!(result.redactions, 4);
    }
}
