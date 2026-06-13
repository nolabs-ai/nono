//! Theme system for nono CLI output
//!
//! Provides named color themes inspired by Catppuccin and other popular
//! terminal palettes. Users select a theme via `--theme`, `NONO_THEME`
//! env var, or `[ui] theme = "..."` in config.toml.

use colored::Colorize;
use std::sync::OnceLock;

/// RGB color tuple
#[derive(Debug, Clone, Copy)]
pub struct Rgb(pub u8, pub u8, pub u8);

/// Apply an Rgb color to text.
pub fn fg(s: &str, c: Rgb) -> colored::ColoredString {
    s.truecolor(c.0, c.1, c.2)
}

/// Apply an Rgb background + foreground.
pub fn badge(label: &str, bg: Rgb, fg_color: Rgb) -> String {
    format!(
        "{}",
        label
            .on_truecolor(bg.0, bg.1, bg.2)
            .truecolor(fg_color.0, fg_color.1, fg_color.2)
            .bold()
    )
}

/// A complete color theme for CLI output
#[derive(Debug, Clone)]
pub struct Theme {
    /// Theme display name
    pub name: &'static str,

    // -- Brand --
    /// Primary brand accent (nono orange in default themes)
    pub brand: Rgb,

    // -- Semantic colors --
    /// Success / read access / positive states
    pub green: Rgb,
    /// Warning / write access / caution states
    pub yellow: Rgb,
    /// Error / denied / destructive states
    pub red: Rgb,
    /// Network / informational highlights
    pub blue: Rgb,
    /// IPC / secondary informational
    pub teal: Rgb,

    // -- Surface colors --
    /// Primary text (paths, values)
    pub text: Rgb,
    /// Secondary / muted text (labels, metadata)
    pub subtext: Rgb,
    /// Dim elements (borders, rules, separators)
    pub overlay: Rgb,
    /// Very dim elements (badge backgrounds for subtle items)
    pub surface: Rgb,
}

// Built-in themes

/// Catppuccin Mocha (dark) - warm and rich
pub const MOCHA: Theme = Theme {
    name: "mocha",
    brand: Rgb(250, 179, 135),   // Peach
    green: Rgb(166, 218, 149),   // Green
    yellow: Rgb(249, 226, 175),  // Yellow
    red: Rgb(243, 139, 168),     // Red
    blue: Rgb(137, 180, 250),    // Blue
    teal: Rgb(148, 226, 213),    // Teal
    text: Rgb(205, 214, 244),    // Text
    subtext: Rgb(147, 153, 178), // Subtext0
    overlay: Rgb(108, 112, 134), // Overlay0
    surface: Rgb(69, 71, 90),    // Surface1
};

/// Catppuccin Latte (light) - clean and bright
pub const LATTE: Theme = Theme {
    name: "latte",
    brand: Rgb(254, 100, 11),    // Peach
    green: Rgb(64, 160, 43),     // Green
    yellow: Rgb(223, 142, 29),   // Yellow
    red: Rgb(210, 15, 57),       // Red
    blue: Rgb(30, 102, 245),     // Blue
    teal: Rgb(23, 146, 153),     // Teal
    text: Rgb(76, 79, 105),      // Text
    subtext: Rgb(108, 111, 133), // Subtext0
    overlay: Rgb(140, 143, 161), // Overlay0
    surface: Rgb(188, 192, 204), // Surface1
};

/// Catppuccin Frappe (medium dark) - muted and sophisticated
pub const FRAPPE: Theme = Theme {
    name: "frappe",
    brand: Rgb(239, 159, 118),   // Peach
    green: Rgb(166, 209, 137),   // Green
    yellow: Rgb(229, 200, 144),  // Yellow
    red: Rgb(231, 130, 132),     // Red
    blue: Rgb(140, 170, 238),    // Blue
    teal: Rgb(129, 200, 190),    // Teal
    text: Rgb(198, 208, 245),    // Text
    subtext: Rgb(148, 156, 187), // Subtext0
    overlay: Rgb(115, 121, 148), // Overlay0
    surface: Rgb(65, 69, 89),    // Surface1
};

/// Catppuccin Macchiato (dark) - deep and vivid
pub const MACCHIATO: Theme = Theme {
    name: "macchiato",
    brand: Rgb(245, 169, 127),   // Peach
    green: Rgb(166, 218, 149),   // Green (same as mocha)
    yellow: Rgb(238, 212, 159),  // Yellow
    red: Rgb(237, 135, 150),     // Red
    blue: Rgb(138, 173, 244),    // Blue
    teal: Rgb(139, 213, 202),    // Teal
    text: Rgb(202, 211, 245),    // Text
    subtext: Rgb(148, 155, 187), // Subtext0
    overlay: Rgb(110, 115, 141), // Overlay0
    surface: Rgb(54, 58, 79),    // Surface1
};

/// Tokyo Night - cool blues and purples
pub const TOKYO_NIGHT: Theme = Theme {
    name: "tokyo-night",
    brand: Rgb(255, 158, 100),   // Orange
    green: Rgb(158, 206, 106),   // Green
    yellow: Rgb(224, 175, 104),  // Yellow
    red: Rgb(247, 118, 142),     // Red
    blue: Rgb(122, 162, 247),    // Blue
    teal: Rgb(115, 218, 202),    // Teal
    text: Rgb(192, 202, 245),    // Foreground
    subtext: Rgb(134, 150, 187), // Comment-ish
    overlay: Rgb(86, 95, 137),   // LineNr
    surface: Rgb(52, 59, 88),    // Surface
};

/// Minimal - plain ANSI-friendly grayscale with orange accent
pub const MINIMAL: Theme = Theme {
    name: "minimal",
    brand: Rgb(204, 102, 0), // Classic nono orange
    green: Rgb(80, 200, 80),
    yellow: Rgb(220, 180, 50),
    red: Rgb(220, 70, 70),
    blue: Rgb(80, 150, 220),
    teal: Rgb(80, 190, 190),
    text: Rgb(220, 220, 220),
    subtext: Rgb(140, 140, 140),
    overlay: Rgb(80, 80, 80),
    surface: Rgb(55, 55, 55),
};

// Global theme state

static THEME: OnceLock<Theme> = OnceLock::new();

/// Initialize the global theme. Call once at startup.
///
/// Resolution order: CLI flag > env var > config file > default (mocha).
pub fn init(cli_theme: Option<&str>, config_theme: Option<&str>) {
    let chosen = if let Some(t) = cli_theme {
        t
    } else if let Ok(val) = std::env::var("NONO_THEME") {
        // Leak the string so we get a &'static str - this runs once at startup
        Box::leak(val.into_boxed_str())
    } else {
        config_theme.unwrap_or("mocha")
    };

    if !is_valid(chosen) {
        tracing::warn!(
            "unknown theme '{}', using mocha. available: {}",
            chosen,
            available_themes().join(", "),
        );
    }

    let theme = resolve(chosen);
    tracing::debug!("theme: {}", theme.name);
    // Ignore error if already set (shouldn't happen)
    let _ = THEME.set(theme);
}

/// Get the current theme. Falls back to Mocha if not initialized.
pub fn current() -> &'static Theme {
    THEME.get().unwrap_or(&MOCHA)
}

/// Resolve a theme name to a Theme value
fn resolve(name: &str) -> Theme {
    match name.to_lowercase().as_str() {
        "mocha" | "catppuccin-mocha" | "catppuccin" => MOCHA,
        "latte" | "catppuccin-latte" => LATTE,
        "frappe" | "catppuccin-frappe" => FRAPPE,
        "macchiato" | "catppuccin-macchiato" => MACCHIATO,
        "tokyo-night" | "tokyo" | "tokyonight" => TOKYO_NIGHT,
        "minimal" | "plain" => MINIMAL,
        _ => MOCHA,
    }
}

/// List available theme names
pub fn available_themes() -> &'static [&'static str] {
    &[
        "mocha",
        "latte",
        "frappe",
        "macchiato",
        "tokyo-night",
        "minimal",
    ]
}

/// Check whether a theme name is recognized
pub fn is_valid(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "mocha"
            | "catppuccin-mocha"
            | "catppuccin"
            | "latte"
            | "catppuccin-latte"
            | "frappe"
            | "catppuccin-frappe"
            | "macchiato"
            | "catppuccin-macchiato"
            | "tokyo-night"
            | "tokyo"
            | "tokyonight"
            | "minimal"
            | "plain"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_known_themes() {
        assert_eq!(resolve("mocha").name, "mocha");
        assert_eq!(resolve("latte").name, "latte");
        assert_eq!(resolve("frappe").name, "frappe");
        assert_eq!(resolve("macchiato").name, "macchiato");
        assert_eq!(resolve("tokyo-night").name, "tokyo-night");
        assert_eq!(resolve("minimal").name, "minimal");
    }

    #[test]
    fn test_resolve_aliases() {
        assert_eq!(resolve("catppuccin").name, "mocha");
        assert_eq!(resolve("catppuccin-latte").name, "latte");
        assert_eq!(resolve("tokyo").name, "tokyo-night");
        assert_eq!(resolve("plain").name, "minimal");
    }

    #[test]
    fn test_resolve_unknown_falls_back() {
        assert_eq!(resolve("nonexistent").name, "mocha");
    }

    #[test]
    fn test_current_before_init() {
        // Should return mocha as default
        assert_eq!(current().name, "mocha");
    }

    #[test]
    fn test_available_themes_not_empty() {
        let themes = available_themes();
        assert!(!themes.is_empty());
        // Every listed theme should resolve to a theme with a matching name
        for name in themes {
            let t = resolve(name);
            assert_eq!(t.name, *name);
        }
    }

    #[test]
    fn test_all_color_slots_used() {
        // Verify all theme fields are accessible (catches dead code)
        let t = &MOCHA;
        let _brand = t.brand;
        let _green = t.green;
        let _yellow = t.yellow;
        let _red = t.red;
        let _blue = t.blue;
        let _teal = t.teal;
        let _text = t.text;
        let _subtext = t.subtext;
        let _overlay = t.overlay;
        let _surface = t.surface;
        assert!(!t.name.is_empty());
    }
}
