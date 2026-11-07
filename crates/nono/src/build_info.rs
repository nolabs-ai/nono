//! Build provenance shared by the CLI and the proxy.
//!
//! `build.rs` embeds the short source revision as `NONO_BUILD_REV`; builds
//! without a discoverable revision report `unknown`.

/// Package version and source revision.
pub const VERSION_WITH_REVISION: &str = concat!(
    "v",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("NONO_BUILD_REV"),
    ")"
);
