use crate::exec_strategy::StartupTimeoutConfig;
use crate::output::format_startup_blocked;
use std::io::{self, IsTerminal, Write};

pub(crate) fn print_terminal_safe_stderr(message: &str) {
    let mut stderr = io::stderr();
    if stderr.is_terminal() {
        let normalized = message.replace('\n', "\r\n");
        let _ = writeln!(stderr, "\r{}", normalized);
    } else {
        let _ = writeln!(stderr, "{}", message);
    }
}

fn notify_startup_termination(timeout_cfg: StartupTimeoutConfig<'_>, has_output: bool) {
    let lines = format_startup_blocked(
        timeout_cfg.program,
        timeout_cfg.timeout.as_secs(),
        has_output,
        timeout_cfg.recommended_profile,
    );

    let mut tty_out = match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(file) => file,
        Err(_) => {
            for line in &lines {
                print_terminal_safe_stderr(line);
            }
            return;
        }
    };

    let _ = writeln!(tty_out);
    for line in &lines {
        let _ = writeln!(tty_out, "{}", line);
    }
    let _ = tty_out.flush();
}

pub(crate) fn notify_startup_termination_for_child(
    timeout_cfg: StartupTimeoutConfig<'_>,
    has_output: bool,
    pty: Option<&mut crate::pty_proxy::PtyProxy>,
) {
    if let Some(proxy) = pty {
        // Restore the terminal from raw mode so the message renders cleanly.
        proxy.pause_terminal_for_prompt();
        notify_startup_termination(timeout_cfg, has_output);
        return;
    }

    notify_startup_termination(timeout_cfg, has_output);
}
