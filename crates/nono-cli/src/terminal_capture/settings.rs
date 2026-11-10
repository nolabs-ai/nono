//! Recording settings from profiles, flags and environment (NEP-0010 §7).
//!
//! Profiles merge with "can only be raised" semantics in
//! [`crate::profile::SessionRecordingConfig::merge`]. Flags and their
//! `NONO_*` variables are applied on top here with the same rule: they can
//! turn recording on, make it required or add a destination, and never turn
//! off what the profile asks for.

use super::{DEFAULT_MAX_BYTES, InputCapture};
use crate::cli::RecordingArgs;
use crate::profile::{SessionRecordingConfig, SessionRecordingInput};
use nono::Result;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Resolved recording settings for one launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordingSettings {
    pub(crate) required: bool,
    /// `None` takes the default for the session's transport: on with a PTY,
    /// off for pipes (§3.2).
    pub(crate) input: Option<InputCapture>,
    pub(crate) max_bytes: u64,
    /// Extra copies of the finished recording (`file` sink), absolute.
    pub(crate) files: Vec<PathBuf>,
    /// Upload to the enrolled platform as chunks close.
    pub(crate) delivery: Option<DeliverySettings>,
}

/// Resolved `delivery` settings. The receiver is always the enrolled
/// platform for now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeliverySettings {
    pub(crate) required: bool,
    pub(crate) flush_timeout: std::time::Duration,
}

/// Default wait at session end for undelivered chunks.
pub(crate) const DEFAULT_FLUSH_TIMEOUT_SECS: u64 = 30;

/// Combine the profile block and the launch flags.
///
/// `launch_dir` anchors relative destination paths; `workdir` expands
/// `$WORKDIR` in a profile path.
pub(crate) fn resolve(
    profile: Option<&SessionRecordingConfig>,
    cli: &RecordingArgs,
    launch_dir: &Path,
    workdir: &Path,
) -> Result<Option<RecordingSettings>> {
    let profile_enabled = profile.is_some_and(SessionRecordingConfig::is_enabled);
    let cli_enabled =
        cli.record || cli.record_required || cli.record_file.is_some() || cli.deliver_to.is_some();
    if let Some(receiver) = cli.deliver_to.as_deref()
        && receiver != crate::profile::RECORDING_RECEIVER_PLATFORM
    {
        return Err(nono::NonoError::ConfigParse(format!(
            "--deliver-to {receiver}: the only supported receiver is `platform`, \
             the platform this host is enrolled with"
        )));
    }
    if !profile_enabled && !cli_enabled {
        return Ok(None);
    }
    let mut files = Vec::new();
    if let Some(file) = profile.and_then(|p| p.file.as_deref()) {
        files.push(absolute(
            &crate::profile::expand_vars(file, workdir)?,
            launch_dir,
        ));
    }
    if let Some(file) = cli.record_file.as_deref() {
        files.push(absolute(file, launch_dir));
    }
    files.dedup();
    let delivery = resolve_delivery(profile.and_then(|p| p.delivery.as_ref()), cli);
    Ok(Some(RecordingSettings {
        // A recording that must be delivered must exist.
        required: cli.record_required
            || profile.is_some_and(|p| p.required == Some(true))
            || delivery.as_ref().is_some_and(|d| d.required),
        input: profile.and_then(|p| p.input).map(|input| match input {
            SessionRecordingInput::On => InputCapture::On,
            SessionRecordingInput::Off => InputCapture::Off,
        }),
        max_bytes: profile
            .and_then(|p| p.max_bytes)
            .unwrap_or(DEFAULT_MAX_BYTES),
        files,
        delivery,
    }))
}

fn resolve_delivery(
    profile: Option<&crate::profile::SessionRecordingDelivery>,
    cli: &RecordingArgs,
) -> Option<DeliverySettings> {
    if profile.is_none() && cli.deliver_to.is_none() {
        return None;
    }
    Some(DeliverySettings {
        required: profile.is_some_and(|d| d.required == Some(true)),
        flush_timeout: std::time::Duration::from_secs(
            profile
                .and_then(|d| d.flush_timeout_secs)
                .unwrap_or(DEFAULT_FLUSH_TIMEOUT_SECS),
        ),
    })
}

fn absolute(path: &Path, launch_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        launch_dir.join(path)
    }
}

/// Drop `file` from a profile that is not user-authored. The `file` sink
/// creates a file outside the sandbox, so pack, registry and built-in
/// profiles cannot choose where; the recording itself stays on.
pub(crate) fn drop_untrusted_file(
    profile_name: &str,
    recording: &mut SessionRecordingConfig,
    silent: bool,
) {
    let is_user_profile = crate::profile::is_user_override(profile_name)
        || crate::profile::is_file_path_ref(profile_name);
    if is_user_profile || recording.file.is_none() {
        return;
    }
    if !silent {
        warn!(
            "Profile '{profile_name}' sets session_recording.file but is not a user profile; \
             recording stays on without the extra file"
        );
    }
    recording.file = None;
    recording.enabled = Some(true);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn block(json: serde_json::Value) -> SessionRecordingConfig {
        serde_json::from_value(json).expect("valid session_recording block")
    }

    fn flags(record: bool, required: bool, file: Option<&str>) -> RecordingArgs {
        RecordingArgs {
            record,
            record_required: required,
            record_file: file.map(PathBuf::from),
            deliver_to: None,
        }
    }

    fn resolve_in(
        profile: Option<&SessionRecordingConfig>,
        cli: &RecordingArgs,
    ) -> Option<RecordingSettings> {
        resolve(profile, cli, Path::new("/launch"), Path::new("/work")).expect("resolves")
    }

    #[test]
    fn recording_is_off_unless_something_turns_it_on() {
        assert_eq!(resolve_in(None, &RecordingArgs::default()), None);
        let off = block(serde_json::json!({ "enabled": false, "input": "on" }));
        assert_eq!(resolve_in(Some(&off), &RecordingArgs::default()), None);
    }

    #[test]
    fn flags_turn_recording_on_with_defaults() {
        let settings = resolve_in(None, &flags(true, false, None)).expect("on");
        assert_eq!(
            settings,
            RecordingSettings {
                required: false,
                input: None,
                max_bytes: DEFAULT_MAX_BYTES,
                files: Vec::new(),
                delivery: None,
            }
        );
        let required = resolve_in(None, &flags(false, true, None)).expect("on");
        assert!(required.required);
        let file = resolve_in(None, &flags(false, false, Some("out/session.cast"))).expect("on");
        assert_eq!(file.files, vec![PathBuf::from("/launch/out/session.cast")]);
    }

    #[test]
    fn flags_cannot_lower_the_profile() {
        let profile = block(serde_json::json!({
            "required": true,
            "input": "off",
            "max_bytes": 1024,
            "file": "/artifacts/profile.cast",
        }));
        let settings = resolve_in(Some(&profile), &flags(false, false, Some("cli.cast")))
            .expect("profile turns recording on");
        assert!(settings.required);
        assert_eq!(settings.input, Some(InputCapture::Off));
        assert_eq!(settings.max_bytes, 1024);
        assert_eq!(
            settings.files,
            vec![
                PathBuf::from("/artifacts/profile.cast"),
                PathBuf::from("/launch/cli.cast"),
            ]
        );
    }

    #[test]
    fn delivery_comes_from_the_flag_or_the_profile() {
        let cli = RecordingArgs {
            deliver_to: Some("platform".to_string()),
            ..RecordingArgs::default()
        };
        let settings = resolve_in(None, &cli).expect("--deliver-to turns recording on");
        assert_eq!(
            settings.delivery,
            Some(DeliverySettings {
                required: false,
                flush_timeout: std::time::Duration::from_secs(DEFAULT_FLUSH_TIMEOUT_SECS),
            })
        );
        let bad = RecordingArgs {
            deliver_to: Some("https://elsewhere.example".to_string()),
            ..RecordingArgs::default()
        };
        assert!(resolve(None, &bad, Path::new("/l"), Path::new("/w")).is_err());

        let profile = block(serde_json::json!({
            "delivery": { "receiver": "platform", "required": true, "flush_timeout_secs": 90 }
        }));
        let settings = resolve_in(Some(&profile), &RecordingArgs::default()).expect("on");
        assert_eq!(
            settings.delivery,
            Some(DeliverySettings {
                required: true,
                flush_timeout: std::time::Duration::from_secs(90),
            })
        );
    }

    #[test]
    fn profile_paths_expand_workdir() {
        let profile = block(serde_json::json!({ "file": "$WORKDIR/session.cast" }));
        let settings =
            resolve_in(Some(&profile), &RecordingArgs::default()).expect("file turns it on");
        assert_eq!(settings.files, vec![PathBuf::from("/work/session.cast")]);
    }

    #[test]
    fn untrusted_profiles_keep_recording_without_the_file() {
        let mut recording = block(serde_json::json!({ "file": "/tmp/x.cast" }));
        drop_untrusted_file("some-pack-profile", &mut recording, true);
        assert_eq!(recording.file, None);
        assert!(recording.is_enabled());

        let mut user = block(serde_json::json!({ "file": "/tmp/x.cast" }));
        drop_untrusted_file("./my-profile.json", &mut user, true);
        assert_eq!(user.file.as_deref(), Some("/tmp/x.cast"));
    }
}
