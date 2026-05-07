//! Shell completion script generation.
//!
//! Implements `nono completion <shell>`, which writes a completion script for
//! the requested shell to stdout.  Users pipe or redirect the output into their
//! shell's completion directory:
//!
//! ```text
//! nono completion bash   >> ~/.bashrc
//! nono completion zsh    > ~/.zfunc/_nono
//! nono completion fish   > ~/.config/fish/completions/nono.fish
//! nono completion powershell >> $PROFILE
//! ```

use clap::CommandFactory;
use clap_complete::{Generator, Shell};
use nono::{NonoError, Result};
use std::io::Write;

use crate::cli::{Cli, CompletionShell, CompletionsArgs};

/// Run `nono completion <shell>`.
///
/// Writes the completion script for `shell` to stdout and returns `Ok(())`.
/// On I/O failure (e.g. the pipe is closed) the error is propagated as a
/// [`nono::NonoError::Io`] variant.
pub(crate) fn run_completions(args: CompletionsArgs) -> Result<()> {
    let shell = to_clap_shell(&args.shell);
    let mut cmd = Cli::command();
    let mut stdout = std::io::stdout();

    try_generate(shell, &mut cmd, "nono", &mut stdout).map_err(NonoError::Io)?;
    stdout.flush().map_err(NonoError::Io)
}

/// Generate completions while preserving write errors instead of panicking.
fn try_generate<G, S>(
    generator: G,
    cmd: &mut clap::Command,
    bin_name: S,
    buf: &mut dyn Write,
) -> std::io::Result<()>
where
    G: Generator,
    S: Into<String>,
{
    cmd.set_bin_name(bin_name);
    cmd.build();
    generator.try_generate(cmd, buf)
}

/// Convert our `CompletionShell` value-enum to the `clap_complete::Shell` type.
fn to_clap_shell(shell: &CompletionShell) -> Shell {
    match shell {
        CompletionShell::Bash => Shell::Bash,
        CompletionShell::Zsh => Shell::Zsh,
        CompletionShell::Fish => Shell::Fish,
        CompletionShell::PowerShell => Shell::PowerShell,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CompletionShell;

    type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn generate_to_string(shell: CompletionShell) -> TestResult<String> {
        let clap_shell = to_clap_shell(&shell);
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        try_generate(clap_shell, &mut cmd, "nono", &mut buf)?;
        Ok(String::from_utf8(buf)?)
    }

    #[test]
    fn test_bash_completions_contain_binary_name() -> TestResult<()> {
        let output = generate_to_string(CompletionShell::Bash)?;
        assert!(
            output.contains("nono"),
            "bash completions should reference the binary name"
        );
        Ok(())
    }

    #[test]
    fn test_zsh_completions_contain_binary_name() -> TestResult<()> {
        let output = generate_to_string(CompletionShell::Zsh)?;
        assert!(
            output.contains("nono"),
            "zsh completions should reference the binary name"
        );
        Ok(())
    }

    #[test]
    fn test_fish_completions_contain_binary_name() -> TestResult<()> {
        let output = generate_to_string(CompletionShell::Fish)?;
        assert!(
            output.contains("nono"),
            "fish completions should reference the binary name"
        );
        Ok(())
    }

    #[test]
    fn test_powershell_completions_non_empty() -> TestResult<()> {
        let output = generate_to_string(CompletionShell::PowerShell)?;
        assert!(
            !output.is_empty(),
            "powershell completions must not be empty"
        );
        Ok(())
    }

    #[test]
    fn test_bash_completions_contain_subcommands() -> TestResult<()> {
        let output = generate_to_string(CompletionShell::Bash)?;
        // Core subcommands must appear in bash completions
        for sub in &["run", "shell", "wrap", "learn", "why", "setup"] {
            assert!(
                output.contains(sub),
                "bash completions missing subcommand: {sub}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_completions_args_parse_all_shells() {
        use crate::cli::Cli;
        use clap::Parser;

        for shell in &["bash", "zsh", "fish", "powershell"] {
            let cli = Cli::parse_from(["nono", "completion", shell]);
            assert!(
                matches!(cli.command, crate::cli::Commands::Completions(_)),
                "completions command should parse for shell: {shell}"
            );
        }
    }

    #[test]
    fn test_completion_write_errors_are_returned() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut cmd = Cli::command();
        let mut writer = FailingWriter;
        let result = try_generate(Shell::Bash, &mut cmd, "nono", &mut writer);

        assert!(result.is_err(), "write errors must be returned");
    }
}
