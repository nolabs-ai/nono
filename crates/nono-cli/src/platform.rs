//! Host platform detection and package/profile `when` predicates.
//!
//! Predicates are intentionally a small closed grammar. Unknown values in
//! known slots evaluate to false; unknown syntax is a parse error.

use nono::{NonoError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformInfo {
    pub os: Os,
    pub linux: Option<LinuxInfo>,
    pub macos: Option<MacosInfo>,
    pub windows: Option<WindowsInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Os {
    Linux,
    Macos,
    Windows,
    Unknown(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxInfo {
    pub distro: Option<String>,
    pub distro_like: Vec<String>,
    pub version_id: Option<String>,
    pub variant_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacosInfo {
    pub product_version: String,
    pub build_version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsInfo {
    pub product_name: String,
    pub version: String,
    pub edition: Option<String>,
}

pub fn current() -> &'static PlatformInfo {
    static CURRENT: OnceLock<PlatformInfo> = OnceLock::new();
    CURRENT.get_or_init(detect)
}

pub fn current_os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

fn detect() -> PlatformInfo {
    if cfg!(target_os = "linux") {
        PlatformInfo {
            os: Os::Linux,
            linux: Some(detect_linux()),
            macos: None,
            windows: None,
        }
    } else if cfg!(target_os = "macos") {
        PlatformInfo {
            os: Os::Macos,
            linux: None,
            macos: Some(detect_macos()),
            windows: None,
        }
    } else if cfg!(target_os = "windows") {
        PlatformInfo {
            os: Os::Windows,
            linux: None,
            macos: None,
            windows: Some(detect_windows()),
        }
    } else {
        PlatformInfo {
            os: Os::Unknown(current_os_name().to_string()),
            linux: None,
            macos: None,
            windows: None,
        }
    }
}

fn detect_linux() -> LinuxInfo {
    match std::fs::read_to_string("/etc/os-release") {
        Ok(content) => parse_os_release(&content),
        Err(_) => LinuxInfo::default(),
    }
}

fn detect_macos() -> MacosInfo {
    MacosInfo {
        product_version: run_sw_vers("-productVersion").unwrap_or_default(),
        build_version: run_sw_vers("-buildVersion").unwrap_or_default(),
    }
}

fn detect_windows() -> WindowsInfo {
    WindowsInfo {
        product_name: query_windows_registry_value("ProductName").unwrap_or_default(),
        version: detect_windows_version(),
        edition: query_windows_registry_value("EditionID"),
    }
}

fn detect_windows_version() -> String {
    let major = query_windows_registry_value("CurrentMajorVersionNumber");
    let minor = query_windows_registry_value("CurrentMinorVersionNumber");
    let build = query_windows_registry_value("CurrentBuildNumber");
    match (major, minor, build) {
        (Some(major), Some(minor), Some(build)) => format!("{major}.{minor}.{build}"),
        (Some(major), None, Some(build)) => format!("{major}.0.{build}"),
        _ => query_windows_registry_value("CurrentVersion").unwrap_or_default(),
    }
}

fn query_windows_registry_value(name: &str) -> Option<String> {
    let output = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "/v",
            name,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_windows_registry_value(&String::from_utf8(output.stdout).ok()?, name)
}

fn parse_windows_registry_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(name) {
            continue;
        }
        let _kind = parts.next()?;
        let value = parts.collect::<Vec<_>>().join(" ");
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn run_sw_vers(arg: &str) -> Option<String> {
    let output = std::process::Command::new("sw_vers")
        .arg(arg)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_os_release(content: &str) -> LinuxInfo {
    let mut info = LinuxInfo::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote_os_release_value(raw_value.trim());
        match key {
            "ID" => info.distro = Some(value),
            "ID_LIKE" => {
                info.distro_like = value
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
            }
            "VERSION_ID" => info.version_id = Some(value),
            "VARIANT_ID" => info.variant_id = Some(value),
            _ => {}
        }
    }
    info
}

fn unquote_os_release_value(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct When {
    predicates: Vec<Predicate>,
}

impl When {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        Ok(Self {
            predicates: vec![Predicate::parse(input)?],
        })
    }

    pub fn matches(&self, platform: &PlatformInfo) -> bool {
        self.predicates
            .iter()
            .any(|predicate| predicate.matches(platform))
    }
}

impl Serialize for When {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let rendered = self
            .predicates
            .iter()
            .map(Predicate::as_str)
            .collect::<Vec<_>>();
        if rendered.len() == 1 {
            rendered[0].serialize(serializer)
        } else {
            rendered.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for When {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawWhen {
            One(String),
            Any(Vec<String>),
        }

        let raw = RawWhen::deserialize(deserializer)?;
        let values = match raw {
            RawWhen::One(value) => vec![value],
            RawWhen::Any(values) => values,
        };
        if values.is_empty() {
            return Err(serde::de::Error::custom(
                "when predicate array must not be empty",
            ));
        }
        if values.len() == 1 {
            return Self::parse(&values[0]).map_err(serde::de::Error::custom);
        }
        let mut predicates = Vec::with_capacity(values.len());
        for value in values {
            predicates.push(Predicate::parse(&value).map_err(serde::de::Error::custom)?);
        }
        Ok(Self { predicates })
    }
}

pub fn when_matches_current(when: Option<&When>) -> Result<bool> {
    Ok(when.map_or(true, |predicate| predicate.matches(current())))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Predicate {
    raw: String,
    negated: bool,
    os: PredicateOs,
    id: Option<String>,
    version: Option<VersionConstraint>,
    build: Option<VersionConstraint>,
    variant: Option<String>,
}

impl Predicate {
    fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(NonoError::ConfigParse(
                "when predicate must not be empty".to_string(),
            ));
        }
        let (negated, body) = match raw.strip_prefix('!') {
            Some(rest) if !rest.is_empty() => (true, rest),
            Some(_) => {
                return Err(NonoError::ConfigParse(format!(
                    "invalid when predicate '{raw}': negation requires a predicate"
                )));
            }
            None => (false, raw),
        };
        if body.contains('!') {
            return Err(NonoError::ConfigParse(format!(
                "invalid when predicate '{raw}': '!' is only allowed at the start"
            )));
        }

        let parts = body.split(':').collect::<Vec<_>>();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(NonoError::ConfigParse(format!(
                "invalid when predicate '{raw}': empty ':' segment"
            )));
        }

        let os = PredicateOs::from_token(parts[0])?;
        let mut id = None;
        let mut version = None;
        let mut build = None;
        let mut variant = None;

        match os {
            PredicateOs::Linux => match parts.len() {
                1 => {}
                2 => id = Some(validate_id(parts[1], raw)?.to_string()),
                3 => {
                    id = Some(validate_id(parts[1], raw)?.to_string());
                    version = Some(VersionConstraint::parse(parts[2], raw)?);
                }
                4 => {
                    id = Some(validate_id(parts[1], raw)?.to_string());
                    version = Some(VersionConstraint::parse(parts[2], raw)?);
                    variant = Some(validate_id(parts[3], raw)?.to_string());
                }
                _ => {
                    return Err(NonoError::ConfigParse(format!(
                        "invalid when predicate '{raw}': too many ':' segments"
                    )));
                }
            },
            PredicateOs::Macos => match parts.len() {
                1 => {}
                2 => version = Some(VersionConstraint::parse(parts[1], raw)?),
                _ => {
                    return Err(NonoError::ConfigParse(format!(
                        "invalid when predicate '{raw}': too many ':' segments"
                    )));
                }
            },
            PredicateOs::Windows => match parts.len() {
                1 => {}
                2 => version = Some(VersionConstraint::parse(parts[1], raw)?),
                3 => {
                    version = Some(VersionConstraint::parse(parts[1], raw)?);
                    build = Some(VersionConstraint::parse(parts[2], raw)?);
                }
                _ => {
                    return Err(NonoError::ConfigParse(format!(
                        "invalid when predicate '{raw}': too many ':' segments"
                    )));
                }
            },
            PredicateOs::Unknown(_) => {
                if parts.len() > 1 {
                    for part in &parts[1..] {
                        validate_id(part, raw)?;
                    }
                }
            }
        }

        Ok(Self {
            raw: raw.to_string(),
            negated,
            os,
            id,
            version,
            build,
            variant,
        })
    }

    fn as_str(&self) -> &str {
        &self.raw
    }

    fn matches(&self, platform: &PlatformInfo) -> bool {
        let matched = match &self.os {
            PredicateOs::Linux => self.matches_linux(platform),
            PredicateOs::Macos => self.matches_macos(platform),
            PredicateOs::Windows => self.matches_windows(platform),
            PredicateOs::Unknown(_) => false,
        };
        if self.negated {
            !matched
        } else {
            matched
        }
    }

    fn matches_linux(&self, platform: &PlatformInfo) -> bool {
        if platform.os != Os::Linux {
            return false;
        }
        let Some(info) = &platform.linux else {
            return false;
        };
        if let Some(id) = &self.id {
            if let Some(base) = id.strip_suffix("-like") {
                if info.distro.as_deref() != Some(base)
                    && !info.distro_like.iter().any(|like| like == base)
                {
                    return false;
                }
            } else if info.distro.as_deref() != Some(id.as_str()) {
                return false;
            }
        }
        if let Some(version) = &self.version {
            let Some(version_id) = info.version_id.as_deref() else {
                return false;
            };
            if !version.matches(version_id) {
                return false;
            }
        }
        if let Some(variant) = &self.variant {
            if info.variant_id.as_deref() != Some(variant.as_str()) {
                return false;
            }
        }
        true
    }

    fn matches_macos(&self, platform: &PlatformInfo) -> bool {
        if platform.os != Os::Macos {
            return false;
        }
        let Some(info) = &platform.macos else {
            return false;
        };
        match &self.version {
            Some(version) => version.matches(&info.product_version),
            None => true,
        }
    }

    fn matches_windows(&self, platform: &PlatformInfo) -> bool {
        if platform.os != Os::Windows {
            return false;
        }
        let Some(info) = &platform.windows else {
            return false;
        };
        if let Some(version) = &self.version {
            if !version.matches(&info.version) {
                return false;
            }
        }
        if let Some(build) = &self.build {
            let build_version = info.version.rsplit('.').next().unwrap_or_default();
            if !build.matches(build_version) {
                return false;
            }
        }
        true
    }
}

fn validate_id<'a>(value: &'a str, raw: &str) -> Result<&'a str> {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        Ok(value)
    } else {
        Err(NonoError::ConfigParse(format!(
            "invalid when predicate '{raw}': invalid identifier segment '{value}'"
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PredicateOs {
    Linux,
    Macos,
    Windows,
    Unknown(String),
}

impl PredicateOs {
    fn from_token(token: &str) -> Result<Self> {
        validate_id(token, token)?;
        Ok(match token {
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            other => Self::Unknown(other.to_string()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionConstraint {
    op: VersionOp,
    version: String,
}

impl VersionConstraint {
    fn parse(value: &str, raw: &str) -> Result<Self> {
        let (op, version) = if let Some(rest) = value.strip_prefix("==") {
            (VersionOp::Eq, rest)
        } else if let Some(rest) = value.strip_prefix(">=") {
            (VersionOp::Gte, rest)
        } else if let Some(rest) = value.strip_prefix("<=") {
            (VersionOp::Lte, rest)
        } else if let Some(rest) = value.strip_prefix('>') {
            (VersionOp::Gt, rest)
        } else if let Some(rest) = value.strip_prefix('<') {
            (VersionOp::Lt, rest)
        } else if value.starts_with(|c: char| !c.is_ascii_alphanumeric()) {
            return Err(NonoError::ConfigParse(format!(
                "invalid when predicate '{raw}': unsupported version comparator in '{value}'"
            )));
        } else {
            (VersionOp::Eq, value)
        };
        if version.is_empty() {
            return Err(NonoError::ConfigParse(format!(
                "invalid when predicate '{raw}': missing version"
            )));
        }
        validate_id(version, raw)?;
        Ok(Self {
            op,
            version: version.to_string(),
        })
    }

    fn matches(&self, actual: &str) -> bool {
        let ordering = compare_versions(actual, &self.version);
        match self.op {
            VersionOp::Eq => ordering == Ordering::Equal,
            VersionOp::Gte => matches!(ordering, Ordering::Greater | Ordering::Equal),
            VersionOp::Gt => ordering == Ordering::Greater,
            VersionOp::Lte => matches!(ordering, Ordering::Less | Ordering::Equal),
            VersionOp::Lt => ordering == Ordering::Less,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionOp {
    Eq,
    Gte,
    Gt,
    Lte,
    Lt,
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let left_parts = left.split('.').collect::<Vec<_>>();
    let right_parts = right.split('.').collect::<Vec<_>>();
    for (left_part, right_part) in left_parts.iter().zip(right_parts.iter()) {
        let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
            (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
            _ if left_part == right_part => Ordering::Equal,
            _ => Ordering::Less,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left_parts.len().cmp(&right_parts.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fedora() -> PlatformInfo {
        PlatformInfo {
            os: Os::Linux,
            linux: Some(LinuxInfo {
                distro: Some("fedora".to_string()),
                distro_like: vec!["rhel".to_string()],
                version_id: Some("43".to_string()),
                variant_id: Some("workstation".to_string()),
            }),
            macos: None,
            windows: None,
        }
    }

    fn macos() -> PlatformInfo {
        PlatformInfo {
            os: Os::Macos,
            linux: None,
            macos: Some(MacosInfo {
                product_version: "15.6.1".to_string(),
                build_version: "24G90".to_string(),
            }),
            windows: None,
        }
    }

    #[test]
    fn parse_os_release_handles_quotes_and_id_like() {
        let info = parse_os_release(
            r#"
ID=fedora
ID_LIKE="rhel centos"
VERSION_ID="43"
VARIANT_ID=workstation
"#,
        );
        assert_eq!(info.distro.as_deref(), Some("fedora"));
        assert_eq!(info.distro_like, vec!["rhel", "centos"]);
        assert_eq!(info.version_id.as_deref(), Some("43"));
        assert_eq!(info.variant_id.as_deref(), Some("workstation"));
    }

    #[test]
    fn linux_predicates_match_distro_like_version_and_variant() {
        let platform = fedora();
        assert!(When::parse("linux").expect("parse").matches(&platform));
        assert!(When::parse("linux:fedora")
            .expect("parse")
            .matches(&platform));
        assert!(When::parse("linux:rhel-like")
            .expect("parse")
            .matches(&platform));
        assert!(When::parse("linux:fedora:>=42")
            .expect("parse")
            .matches(&platform));
        assert!(When::parse("linux:fedora:43:workstation")
            .expect("parse")
            .matches(&platform));
        assert!(!When::parse("linux:ubuntu")
            .expect("parse")
            .matches(&platform));
    }

    #[test]
    fn macos_version_predicates_match() {
        let platform = macos();
        assert!(When::parse("macos").expect("parse").matches(&platform));
        assert!(When::parse("macos:>=15").expect("parse").matches(&platform));
        assert!(!When::parse("macos:<15").expect("parse").matches(&platform));
    }

    #[test]
    fn windows_build_predicate_parses_and_matches() {
        let platform = PlatformInfo {
            os: Os::Windows,
            linux: None,
            macos: None,
            windows: Some(WindowsInfo {
                product_name: "Windows 11 Pro".to_string(),
                version: "10.0.22631".to_string(),
                edition: Some("Professional".to_string()),
            }),
        };
        assert!(When::parse("windows:>=10:>=22000")
            .expect("parse")
            .matches(&platform));
        assert!(When::parse("windows:>=10:22631")
            .expect("parse")
            .matches(&platform));
        assert!(!When::parse("windows:>=10:>30000")
            .expect("parse")
            .matches(&platform));
    }

    #[test]
    fn negation_and_any_of_work() {
        let platform = fedora();
        assert!(When::parse("!macos").expect("parse").matches(&platform));
        let when: When = serde_json::from_str(r#"["macos", "linux:fedora:>=43"]"#).expect("parse");
        assert!(when.matches(&platform));
    }

    #[test]
    fn unknown_os_is_false_not_error() {
        let platform = fedora();
        assert!(!When::parse("freebsd").expect("parse").matches(&platform));
    }

    #[test]
    fn unknown_comparator_is_error() {
        assert!(When::parse("linux:fedora:~=43").is_err());
    }

    #[test]
    fn version_segments_compare_numerically_when_possible() {
        assert_eq!(compare_versions("24.10", "24.4"), Ordering::Greater);
        assert_eq!(compare_versions("24", "24.04"), Ordering::Less);
        assert_eq!(compare_versions("unstable", "25.05"), Ordering::Less);
        assert_eq!(compare_versions("unstable", "unstable"), Ordering::Equal);
    }
}
