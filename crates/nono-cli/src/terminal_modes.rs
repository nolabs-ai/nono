//! Terminal modes omitted from vt100's screen snapshots but needed after an
//! approval view. Parse controls structurally, including across output chunks.

#[derive(Clone, Copy)]
struct BufferModes {
    top: u16,
    bottom: u16,
    origin: bool,
}

impl BufferModes {
    fn new(rows: u16) -> Self {
        Self {
            top: 1,
            bottom: rows,
            origin: false,
        }
    }
}

struct Modes {
    rows: u16,
    buffers: [BufferModes; 2],
    alternate: bool,
    wrap: bool,
    focus: bool,
    synchronized: bool,
}

impl Modes {
    fn new(rows: u16) -> Self {
        Self {
            rows,
            buffers: [BufferModes::new(rows); 2],
            alternate: false,
            wrap: true,
            focus: false,
            synchronized: false,
        }
    }
}

impl vte::Perform for Modes {
    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        ignore: bool,
        action: char,
    ) {
        if ignore {
            return;
        }
        let buffer = &mut self.buffers[usize::from(self.alternate)];
        if intermediates.is_empty() && action == 'r' {
            let mut params = params.iter();
            let top = params
                .next()
                .and_then(|v| v.first())
                .copied()
                .unwrap_or(1)
                .max(1);
            let bottom = params
                .next()
                .and_then(|v| v.first())
                .copied()
                .filter(|v| *v != 0)
                .unwrap_or(self.rows)
                .min(self.rows);
            (buffer.top, buffer.bottom) = if top < bottom {
                (top, bottom)
            } else {
                (1, self.rows)
            };
        } else if intermediates == b"?" && matches!(action, 'h' | 'l') {
            let enabled = action == 'h';
            for param in params {
                match param {
                    [6] => self.buffers[usize::from(self.alternate)].origin = enabled,
                    [7] => self.wrap = enabled,
                    [47] | [1049] => {
                        if enabled && param == [1049] {
                            self.buffers[1] = BufferModes::new(self.rows);
                        }
                        self.alternate = enabled;
                    }
                    [1004] => self.focus = enabled,
                    [2026] => self.synchronized = enabled,
                    _ => {}
                }
            }
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], ignore: bool, byte: u8) {
        if !ignore && intermediates.is_empty() && byte == b'c' {
            *self = Self::new(self.rows);
        }
    }
}

pub(crate) struct TerminalModes {
    parser: vte::Parser,
    state: Modes,
}

impl TerminalModes {
    pub(crate) fn new(rows: u16) -> Self {
        Self {
            parser: vte::Parser::new(),
            state: Modes::new(rows),
        }
    }

    pub(crate) fn observe(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.state, bytes);
    }

    pub(crate) fn resize(&mut self, rows: u16) {
        self.state.rows = rows;
        for buffer in &mut self.state.buffers {
            buffer.top = buffer.top.min(rows);
            buffer.bottom = rows;
        }
    }

    pub(crate) fn restore(&self, (row, col): (u16, u16)) -> Vec<u8> {
        let buffer = self.state.buffers[usize::from(self.state.alternate)];
        let mut text = String::new();
        if buffer.top != 1 || buffer.bottom != self.state.rows || buffer.origin {
            text.push_str(&format!("\x1b[{};{}r", buffer.top, buffer.bottom));
            if buffer.origin {
                text.push_str("\x1b[?6h");
            }
            let row = if buffer.origin {
                row.saturating_sub(buffer.top - 1)
            } else {
                row
            };
            text.push_str(&format!(
                "\x1b[{};{}H",
                row.saturating_add(1),
                col.saturating_add(1)
            ));
        }
        for (mode, enabled) in [
            (7, self.state.wrap),
            (1004, self.state.focus),
            (2026, self.state.synchronized),
        ] {
            text.push_str(&format!("\x1b[?{mode}{}", if enabled { 'h' } else { 'l' }));
        }
        text.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_fragmented_regions_and_modes_without_parsing_osc_payloads() {
        let mut modes = TerminalModes::new(24);
        modes.observe(b"\x1b[3;");
        modes.observe(b"18r\x1b[?6h\x1b[?7l\x1b[?1004h");
        modes.observe(b"\x1b]0;fake [1;2r\x07");
        let restored = String::from_utf8(modes.restore((5, 7))).expect("ASCII controls");
        assert!(restored.contains("\x1b[3;18r"));
        assert!(restored.contains("\x1b[?6h\x1b[4;8H"));
        assert!(restored.contains("\x1b[?7l\x1b[?1004h"));
    }

    #[test]
    fn alternate_buffer_and_resize_keep_regions_separate() {
        let mut modes = TerminalModes::new(24);
        modes.observe(b"\x1b[3;18r\x1b[?1049h\x1b[4;20r\x1b[?1049l");
        assert!(
            String::from_utf8(modes.restore((5, 0)))
                .expect("controls")
                .contains("\x1b[3;18r")
        );
        modes.resize(30);
        assert!(
            String::from_utf8(modes.restore((5, 0)))
                .expect("controls")
                .contains("\x1b[3;30r")
        );
    }
}
