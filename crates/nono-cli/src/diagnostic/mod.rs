//! CLI diagnostic footer and stderr parsing.
//!
//! Structured denial records live in `nono::diagnostic`. This module renders
//! them and applies CLI-specific policy labels and flag formatting.

mod formatter;

pub use formatter::{
    CommandContext, DiagnosticFormatter, DiagnosticMode, ErrorObservation, PolicyExplanation,
    analyze_error_output,
};
