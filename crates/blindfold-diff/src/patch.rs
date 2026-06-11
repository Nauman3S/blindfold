use std::fmt;

/// A parsed unified patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Patch {
    files: Vec<FilePatch>,
}

impl Patch {
    /// Returns file sections in patch order.
    #[must_use]
    pub fn files(&self) -> &[FilePatch] {
        &self.files
    }
}

/// The type of file-level change represented by a patch section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FileChange {
    /// A file was added.
    Added,
    /// A file was modified.
    Modified,
    /// A file was deleted.
    Deleted,
    /// A file was renamed.
    Renamed,
    /// Git reported a binary change without textual hunks.
    Binary,
}

/// A file section in a unified patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePatch {
    old_path: Option<String>,
    new_path: Option<String>,
    change: FileChange,
    hunks: Vec<Hunk>,
}

impl FilePatch {
    /// Returns the path before the change, if the file existed.
    #[must_use]
    pub fn old_path(&self) -> Option<&str> {
        self.old_path.as_deref()
    }

    /// Returns the path after the change, if the file exists.
    #[must_use]
    pub fn new_path(&self) -> Option<&str> {
        self.new_path.as_deref()
    }

    /// Returns the file-level change type.
    #[must_use]
    pub const fn change(&self) -> FileChange {
        self.change
    }

    /// Returns textual hunks in patch order.
    #[must_use]
    pub fn hunks(&self) -> &[Hunk] {
        &self.hunks
    }
}

/// A unified-diff hunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hunk {
    old_start: usize,
    new_start: usize,
    lines: Vec<PatchLine>,
}

impl Hunk {
    /// Returns the first old-file line number.
    #[must_use]
    pub const fn old_start(&self) -> usize {
        self.old_start
    }

    /// Returns the first new-file line number.
    #[must_use]
    pub const fn new_start(&self) -> usize {
        self.new_start
    }

    /// Returns hunk lines in patch order.
    #[must_use]
    pub fn lines(&self) -> &[PatchLine] {
        &self.lines
    }
}

/// The role of a line inside a unified-diff hunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PatchLineKind {
    /// A line present in both versions.
    Context,
    /// A line added to the new version.
    Added,
    /// A line removed from the old version.
    Removed,
}

/// A parsed line inside a hunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchLine {
    kind: PatchLineKind,
    old_line: Option<usize>,
    new_line: Option<usize>,
    content: String,
}

impl PatchLine {
    /// Returns whether this is context, added, or removed content.
    #[must_use]
    pub const fn kind(&self) -> PatchLineKind {
        self.kind
    }

    /// Returns the old-file line number when applicable.
    #[must_use]
    pub const fn old_line(&self) -> Option<usize> {
        self.old_line
    }

    /// Returns the new-file line number when applicable.
    #[must_use]
    pub const fn new_line(&self) -> Option<usize> {
        self.new_line
    }

    /// Returns line content without the diff prefix.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

/// A safe, stable reason patch parsing failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PatchError {
    /// A hunk appeared before a file section.
    HunkWithoutFile,
    /// A hunk header was syntactically invalid.
    InvalidHunkHeader,
    /// A line inside a hunk had no valid diff prefix.
    InvalidHunkLine,
    /// Hunk line counts did not match its header.
    HunkCountMismatch,
    /// A supplied non-empty input contained no recognizable patch sections.
    NoFileSections,
}

impl fmt::Display for PatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HunkWithoutFile => "patch hunk has no file section",
            Self::InvalidHunkHeader => "patch contains an invalid hunk header",
            Self::InvalidHunkLine => "patch contains an invalid hunk line",
            Self::HunkCountMismatch => "patch hunk line counts do not match its header",
            Self::NoFileSections => "input contains no recognizable patch sections",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PatchError {}

#[derive(Debug)]
struct FileBuilder {
    old_path: Option<String>,
    new_path: Option<String>,
    renamed: bool,
    binary: bool,
    hunks: Vec<Hunk>,
}

impl FileBuilder {
    fn new(old_path: Option<String>, new_path: Option<String>) -> Self {
        Self {
            old_path,
            new_path,
            renamed: false,
            binary: false,
            hunks: Vec::new(),
        }
    }

    fn finish(self) -> FilePatch {
        let change = if self.binary {
            FileChange::Binary
        } else if self.renamed {
            FileChange::Renamed
        } else if self.old_path.is_none() {
            FileChange::Added
        } else if self.new_path.is_none() {
            FileChange::Deleted
        } else {
            FileChange::Modified
        };
        FilePatch {
            old_path: self.old_path,
            new_path: self.new_path,
            change,
            hunks: self.hunks,
        }
    }
}

#[derive(Debug)]
struct HunkBuilder {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    old_seen: usize,
    new_seen: usize,
    lines: Vec<PatchLine>,
}

impl HunkBuilder {
    fn push(&mut self, line: &str) -> Result<(), PatchError> {
        let (kind, content) = match line.as_bytes().first() {
            Some(b' ') => (PatchLineKind::Context, &line[1..]),
            Some(b'+') => (PatchLineKind::Added, &line[1..]),
            Some(b'-') => (PatchLineKind::Removed, &line[1..]),
            _ => return Err(PatchError::InvalidHunkLine),
        };
        let old_line = match kind {
            PatchLineKind::Context | PatchLineKind::Removed => {
                let line = self.old_start + self.old_seen;
                self.old_seen += 1;
                Some(line)
            }
            PatchLineKind::Added => None,
        };
        let new_line = match kind {
            PatchLineKind::Context | PatchLineKind::Added => {
                let line = self.new_start + self.new_seen;
                self.new_seen += 1;
                Some(line)
            }
            PatchLineKind::Removed => None,
        };
        self.lines.push(PatchLine {
            kind,
            old_line,
            new_line,
            content: content.to_owned(),
        });
        Ok(())
    }

    fn finish(self) -> Result<Hunk, PatchError> {
        if self.old_seen != self.old_count || self.new_seen != self.new_count {
            return Err(PatchError::HunkCountMismatch);
        }
        Ok(Hunk {
            old_start: self.old_start,
            new_start: self.new_start,
            lines: self.lines,
        })
    }
}

/// Parses Git-style or ordinary unified patch text.
///
/// Empty input is a valid patch with no file sections.
///
/// # Errors
///
/// Returns [`PatchError`] for malformed hunk headers, invalid hunk lines,
/// mismatched hunk counts, or unrecognized non-empty input.
pub fn parse_patch(input: &str) -> Result<Patch, PatchError> {
    let mut files = Vec::new();
    let mut file: Option<FileBuilder> = None;
    let mut hunk: Option<HunkBuilder> = None;

    for line in input.lines() {
        if line.starts_with("diff --git ") {
            finish_hunk(&mut file, &mut hunk)?;
            finish_file(&mut files, &mut file);
            let (old_path, new_path) = parse_diff_paths(line);
            file = Some(FileBuilder::new(old_path, new_path));
        } else if line.starts_with("@@ ") {
            finish_hunk(&mut file, &mut hunk)?;
            if file.is_none() {
                return Err(PatchError::HunkWithoutFile);
            }
            hunk = Some(parse_hunk_header(line)?);
        } else if let Some(active_hunk) = hunk.as_mut() {
            if line == r"\ No newline at end of file" {
                continue;
            }
            active_hunk.push(line)?;
        } else if let Some(path) = line.strip_prefix("--- ") {
            if file.is_none() {
                file = Some(FileBuilder::new(None, None));
            }
            if let Some(active_file) = file.as_mut() {
                active_file.old_path = parse_header_path(path);
            }
        } else if let Some(path) = line.strip_prefix("+++ ") {
            if file.is_none() {
                file = Some(FileBuilder::new(None, None));
            }
            if let Some(active_file) = file.as_mut() {
                active_file.new_path = parse_header_path(path);
            }
        } else if let Some(path) = line.strip_prefix("rename from ") {
            if let Some(active_file) = file.as_mut() {
                active_file.old_path = Some(unquote_path(path));
                active_file.renamed = true;
            }
        } else if let Some(path) = line.strip_prefix("rename to ") {
            if let Some(active_file) = file.as_mut() {
                active_file.new_path = Some(unquote_path(path));
                active_file.renamed = true;
            }
        } else if (line.starts_with("Binary files ") || line == "GIT binary patch")
            && let Some(active_file) = file.as_mut()
        {
            active_file.binary = true;
        }
    }

    finish_hunk(&mut file, &mut hunk)?;
    finish_file(&mut files, &mut file);

    if files.is_empty() && !input.trim().is_empty() {
        return Err(PatchError::NoFileSections);
    }
    Ok(Patch { files })
}

fn finish_hunk(
    file: &mut Option<FileBuilder>,
    hunk: &mut Option<HunkBuilder>,
) -> Result<(), PatchError> {
    let Some(active_hunk) = hunk.take() else {
        return Ok(());
    };
    let active_file = file.as_mut().ok_or(PatchError::HunkWithoutFile)?;
    active_file.hunks.push(active_hunk.finish()?);
    Ok(())
}

fn finish_file(files: &mut Vec<FilePatch>, file: &mut Option<FileBuilder>) {
    if let Some(active_file) = file.take() {
        files.push(active_file.finish());
    }
}

fn parse_hunk_header(line: &str) -> Result<HunkBuilder, PatchError> {
    let body = line
        .strip_prefix("@@ -")
        .and_then(|rest| rest.split_once(" @@").map(|(ranges, _)| ranges))
        .ok_or(PatchError::InvalidHunkHeader)?;
    let (old, new) = body.split_once(" +").ok_or(PatchError::InvalidHunkHeader)?;
    let (old_start, old_count) = parse_range(old)?;
    let (new_start, new_count) = parse_range(new)?;
    Ok(HunkBuilder {
        old_start,
        old_count,
        new_start,
        new_count,
        old_seen: 0,
        new_seen: 0,
        lines: Vec::new(),
    })
}

fn parse_range(range: &str) -> Result<(usize, usize), PatchError> {
    let (start, count) = range.split_once(',').unwrap_or((range, "1"));
    let start = start.parse().map_err(|_| PatchError::InvalidHunkHeader)?;
    let count = count.parse().map_err(|_| PatchError::InvalidHunkHeader)?;
    Ok((start, count))
}

fn parse_diff_paths(line: &str) -> (Option<String>, Option<String>) {
    let body = line.strip_prefix("diff --git ").unwrap_or_default();
    let mut parts = body.split_whitespace();
    let old_path = parts.next().and_then(parse_git_path);
    let new_path = parts.next().and_then(parse_git_path);
    (old_path, new_path)
}

fn parse_header_path(path: &str) -> Option<String> {
    let path = path.split_once('\t').map_or(path, |(value, _)| value);
    parse_git_path(path)
}

fn parse_git_path(path: &str) -> Option<String> {
    if path == "/dev/null" {
        return None;
    }
    let path = path
        .strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path);
    Some(unquote_path(path))
}

fn unquote_path(path: &str) -> String {
    path.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(path)
        .replace(r#"\""#, "\"")
        .replace(r"\\", r"\")
}
