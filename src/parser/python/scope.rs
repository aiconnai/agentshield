//! Indentation-based tracking of the function a Python line belongs to.

use super::patterns::FUNC_DEF_RE;

struct Frame {
    name: String,
    indent: usize,
    key: String,
}

/// The stack of `def`s enclosing the current line, advanced one line at a time.
#[derive(Default)]
pub(crate) struct FunctionScopes {
    frames: Vec<Frame>,
}

impl FunctionScopes {
    /// Move to `line` (the zero-based `line_idx`-th line of the file): leave
    /// functions the line is no longer indented inside, and enter the one it
    /// defines.
    pub(crate) fn advance(&mut self, line: &str, line_idx: usize) {
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        if !line.trim().is_empty() {
            while self
                .frames
                .last()
                .is_some_and(|frame| indent <= frame.indent)
            {
                self.frames.pop();
            }
        }
        if let Some(cap) = FUNC_DEF_RE.captures(line) {
            self.frames.push(Frame {
                name: cap[1].to_string(),
                indent,
                key: format!("{}@{}", &cap[1], line_idx + 1),
            });
        }
    }

    /// Name of the innermost enclosing function.
    pub(crate) fn current_name(&self) -> Option<&str> {
        self.frames.last().map(|frame| frame.name.as_str())
    }

    /// Indentation of the innermost enclosing function's `def`.
    pub(crate) fn current_indent(&self) -> Option<usize> {
        self.frames.last().map(|frame| frame.indent)
    }

    /// Unique `/`-joined path of the enclosing functions; empty at module
    /// level. Same-named functions get different paths.
    pub(crate) fn path(&self) -> String {
        self.frames
            .iter()
            .map(|frame| frame.key.as_str())
            .collect::<Vec<_>>()
            .join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionScopes;

    fn paths(code: &str) -> Vec<String> {
        let mut scopes = FunctionScopes::default();
        code.lines()
            .enumerate()
            .map(|(idx, line)| {
                scopes.advance(line, idx);
                scopes.path()
            })
            .collect()
    }

    #[test]
    fn tracks_nesting_and_sibling_functions() {
        let paths = paths(
            "x = 1\ndef a():\n    y = 2\n    def b():\n        z = 3\n    w = 4\ndef a():\n    v = 5\n",
        );
        assert_eq!(paths[0], "");
        assert_eq!(paths[2], "a@2");
        assert_eq!(paths[4], "a@2/b@4");
        assert_eq!(paths[5], "a@2");
        assert_eq!(paths[7], "a@7");
    }

    #[test]
    fn blank_lines_do_not_leave_the_function() {
        let paths = paths("def a():\n    x = 1\n\n    y = 2\n");
        assert_eq!(paths[2], "a@1");
        assert_eq!(paths[3], "a@1");
    }
}
