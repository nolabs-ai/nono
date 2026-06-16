//! CLI-owned diagnostic rendering and stderr heuristics.
//!
//! The core `nono::diagnostic` module owns the structured denial records; this
//! module owns all user-facing diagnostic UX: the `nono diagnostic` footer,
//! CLI flag suggestions, policy explanations, and best-effort parsing of a
//! command's own error output.

mod formatter;

pub use formatter::{
    CommandContext, DiagnosticFormatter, DiagnosticMode, ErrorObservation, PolicyExplanation,
    analyze_error_output,
};
