//! Self-contained file inventories carried by Sigstore DSSE bundles.
use super::PolicySources;
use crate::platform_policy::protocol::{PolicyTrustRoot, SignedBundle, UnsignedBundle};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nono::{
    NonoError, Result,
    trust::{DsseEnvelope, IN_TOTO_STATEMENT_TYPE, InTotoStatement},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

pub(crate) const PREDICATE: &str = "https://nono.sh/attestation/bundle/v1";
const MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
const MAX_FILES: usize = 1_000;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: u64 = 48 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    name: String,
    publisher: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<i64>,
    entrypoints: BTreeMap<String, String>,
    profiles: BTreeMap<String, String>,
}

fn invalid(message: impl Into<String>) -> NonoError {
    NonoError::ConfigParse(format!("bundle verification failed: {}", message.into()))
}

fn invalid_file(path: &str, reason: impl Into<String>) -> NonoError {
    let reason = reason.into();
    tracing::debug!(file = ?path, reason = ?reason, "Bundle file verification failed");
    invalid(format!("file {path:?}: {reason}"))
}

fn exact_fields(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    })
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path
            .split('/')
            .next()
            .is_some_and(|part| part.eq_ignore_ascii_case("bundle.sig"))
        && path.is_ascii()
        && path.len() <= 1024
        && path.split('/').count() <= 64
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !path
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == ':')
}

pub(super) fn collect_pack(
    package: &crate::package::PackageRef,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let root = crate::package::package_install_dir(&package.namespace, &package.name)?;
    if !std::fs::symlink_metadata(&root)
        .map_err(NonoError::Io)?
        .is_dir()
    {
        return Err(invalid(format!(
            "pack root {root:?} must be a directory, not a symlink"
        )));
    }
    let manifest_path = root.join("package.json");
    let manifest: crate::package::PackageManifest =
        serde_json::from_slice(&read_pack_file(&manifest_path, MAX_BYTES)?).map_err(|error| {
            invalid(format!(
                "pack {:?} has an invalid package.json: {error}",
                package.key()
            ))
        })?;
    if manifest.name != package.name {
        return Err(invalid(format!(
            "pack {:?} package.json names a different pack",
            package.key()
        )));
    }
    let prefix = format!("packs/{}/", package.key());
    let mut original_paths = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let original = format!("{prefix}{}", artifact.path);
        if !valid_path(&original)
            || artifact.path == "package.json"
            || artifact.path == ".nono-trust.bundle"
        {
            return Err(invalid_file(
                &original,
                "invalid or reserved pack artifact path",
            ));
        }
        let installed = crate::package_cmd::installed_artifact_relative_path(artifact)?;
        if original_paths
            .insert(installed, artifact.path.clone())
            .is_some()
        {
            return Err(invalid_file(
                &original,
                "multiple pack artifacts share an installed path",
            ));
        }
    }
    let mut total = files
        .values()
        .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or_else(|| invalid("bundle is too large"))?;
    let mut found = BTreeSet::new();
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .max_depth(64)
    {
        let entry = entry.map_err(|error| {
            invalid(format!("cannot collect pack {:?}: {error}", package.key()))
        })?;
        let relative = entry
            .path()
            .strip_prefix(&root)
            .map_err(|error| invalid(error.to_string()))?;
        if entry.file_type().is_symlink()
            || (!entry.file_type().is_dir() && !entry.file_type().is_file())
        {
            return Err(invalid(format!(
                "pack entry {relative:?} must be a regular file or directory"
            )));
        }
        if entry.file_type().is_dir() {
            if entry.depth() == 64 {
                return Err(invalid(format!(
                    "pack directory {relative:?} exceeds the nesting limit"
                )));
            }
            continue;
        }
        let relative = relative
            .to_str()
            .ok_or_else(|| invalid("pack contains a non-UTF-8 path"))?;
        found.insert(relative.to_owned());
        let original = original_paths
            .get(relative)
            .map(String::as_str)
            .unwrap_or(relative);
        let path = format!("{prefix}{original}");
        if !valid_path(&path) {
            return Err(invalid_file(&path, "invalid pack-relative path"));
        }
        if files.len() >= MAX_FILES {
            return Err(invalid(format!(
                "bundle exceeds the {MAX_FILES}-file limit"
            )));
        }
        let bytes = read_pack_file(entry.path(), MAX_BYTES.saturating_sub(total))?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("bundle is too large"))?;
        if files.insert(path.clone(), bytes).is_some() {
            return Err(invalid_file(
                &path,
                "multiple pack files map to the same original path",
            ));
        }
    }
    for (installed, original) in original_paths {
        if !found.contains(&installed) {
            return Err(invalid_file(
                &format!("{prefix}{original}"),
                "declared pack artifact is missing from the package store",
            ));
        }
    }
    Ok(())
}

fn read_pack_file(path: &std::path::Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("cannot read pack file {path:?}: {error}")))?;
    if !metadata.is_file() {
        return Err(invalid(format!(
            "pack file {path:?} must be a regular file"
        )));
    }
    let mut bytes = Vec::new();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(NonoError::Io)?;
    if !file.metadata().map_err(NonoError::Io)?.is_file() {
        return Err(invalid(format!(
            "pack file {path:?} must be a regular file"
        )));
    }
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(NonoError::Io)?;
    if bytes.len() > limit {
        return Err(invalid(format!(
            "pack file {path:?} exceeds the remaining bundle size limit"
        )));
    }
    Ok(bytes)
}

pub(crate) fn name(bundle: &SignedBundle) -> Option<String> {
    let payload = bundle.signature["dsseEnvelope"]["payload"].as_str()?;
    let bytes = STANDARD.decode(payload).ok()?;
    let statement: Value = serde_json::from_slice(&bytes).ok()?;
    statement["predicate"]["name"].as_str().map(str::to_owned)
}

pub(crate) fn cache_path(
    base: &std::path::Path,
    bundle: &SignedBundle,
    digest: &str,
    revision: i64,
) -> Result<std::path::PathBuf> {
    let hash = digest
        .strip_prefix("sha256:")
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("invalid manifest digest"))?;
    let name: String = name(bundle)
        .unwrap_or_else(|| "policy".into())
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    Ok(base
        .join(if name.is_empty() { "policy" } else { &name })
        .join(format!("r{revision}-{hash}")))
}

pub(crate) fn read_directory(directory: &std::path::Path) -> Result<SignedBundle> {
    tracing::debug!(directory = ?directory, "Reading cached platform bundle");
    let mut files = BTreeMap::new();
    let mut signature = None;
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(directory)
        .follow_links(false)
        .max_depth(64)
    {
        let entry = entry.map_err(|e| invalid(e.to_string()))?;
        if entry.depth() == 64 && entry.file_type().is_dir() {
            return Err(invalid(format!(
                "directory {:?} exceeds the nesting limit",
                entry.path()
            )));
        }
        if entry.file_type().is_symlink() {
            return Err(invalid(format!(
                "symlink {:?} is not allowed in a bundle",
                entry.path()
            )));
        }
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return Err(invalid(format!(
                "entry {:?} is not a regular file",
                entry.path()
            )));
        }
        let path = entry
            .path()
            .strip_prefix(directory)
            .map_err(|e| invalid(e.to_string()))?
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 path"))?
            .to_owned();
        total = total
            .checked_add(entry.metadata().map_err(|e| invalid(e.to_string()))?.len())
            .ok_or_else(|| invalid("bundle is too large"))?;
        if total > (MAX_BYTES * 2) as u64 || files.len() > MAX_FILES {
            return Err(invalid("bundle is too large"));
        }
        let bytes = std::fs::read(entry.path())
            .map_err(|error| invalid_file(&path, format!("cannot read cached file: {error}")))?;
        if path == "bundle.sig" {
            signature = Some(serde_json::from_slice(&bytes).map_err(|error| {
                invalid_file(&path, format!("invalid signature JSON: {error}"))
            })?);
        } else {
            if !valid_path(&path) {
                return Err(invalid_file(&path, "invalid bundle-relative path"));
            }
            files.insert(path, STANDARD.encode(bytes));
        }
    }
    Ok(SignedBundle {
        signature: signature
            .ok_or_else(|| invalid_file("bundle.sig", "missing from cached bundle"))?,
        files,
    })
}

pub(crate) fn write_directory(directory: &std::path::Path, bundle: &SignedBundle) -> Result<()> {
    let parent = directory
        .parent()
        .ok_or_else(|| invalid("missing bundle parent"))?;
    std::fs::create_dir_all(parent).map_err(NonoError::Io)?;
    let staging = tempfile::tempdir_in(parent).map_err(NonoError::Io)?;
    for (path, encoded) in &bundle.files {
        if !valid_path(path) {
            return Err(invalid("invalid file path"));
        }
        let destination = staging.path().join(path);
        let parent = destination
            .parent()
            .ok_or_else(|| invalid("missing file parent"))?;
        std::fs::create_dir_all(parent).map_err(NonoError::Io)?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|e| invalid(e.to_string()))?;
        std::fs::write(destination, bytes).map_err(NonoError::Io)?;
    }
    crate::platform_client::write_json_secure(
        &staging.path().join("bundle.sig"),
        &bundle.signature,
    )?;
    std::fs::rename(staging.path(), directory).map_err(NonoError::Io)?;
    Ok(())
}

pub(crate) fn replace_directory(directory: &std::path::Path, bundle: &SignedBundle) -> Result<()> {
    let parent = directory
        .parent()
        .ok_or_else(|| invalid("missing bundle parent"))?;
    std::fs::create_dir_all(parent).map_err(NonoError::Io)?;
    let staging = tempfile::tempdir_in(parent).map_err(NonoError::Io)?;
    let replacement = staging.path().join("verified");
    let previous = staging.path().join("previous");
    write_directory(&replacement, bundle)?;
    match std::fs::rename(directory, &previous) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(NonoError::Io(error)),
    }
    if let Err(error) = std::fs::rename(&replacement, directory) {
        if !directory.exists() {
            let _ = std::fs::rename(&previous, directory);
        }
        return Err(NonoError::Io(error));
    }
    Ok(())
}

pub(crate) fn export(source: &std::path::Path) -> Result<UnsignedBundle> {
    let (policy, assets) = super::collect_sources(source)?;
    let name = policy
        .root
        .pointer("/meta/name")
        .and_then(Value::as_str)
        .unwrap_or("policy")
        .to_owned();
    let mut files: BTreeMap<_, _> = assets
        .into_iter()
        .map(|(path, bytes)| (path, STANDARD.encode(bytes)))
        .collect();
    let mut insert = |path: &str, document: &Value| -> Result<()> {
        let bytes = serde_json::to_vec(document).map_err(|e| invalid(e.to_string()))?;
        files.insert(path.to_string(), STANDARD.encode(bytes));
        Ok(())
    };
    insert("policy.json", &policy.root)?;
    let mut profiles = BTreeMap::new();
    for (id, document) in policy.profiles {
        let path = format!("profiles/{id}.json");
        insert(&path, &document)?;
        profiles.insert(id, path);
    }
    insert(
        "groups.json",
        &serde_json::to_value(policy.groups).map_err(|e| invalid(e.to_string()))?,
    )?;
    let metadata = Metadata {
        name,
        publisher: "nolabs, Inc.".into(),
        revision: None,
        entrypoints: BTreeMap::from([
            ("policy".into(), "policy.json".into()),
            ("groups".into(), "groups.json".into()),
        ]),
        profiles,
    };
    let mut subjects = Vec::new();
    for (path, content) in &files {
        let bytes = STANDARD
            .decode(content)
            .map_err(|e| invalid(e.to_string()))?;
        subjects.push(json!({"name":path,"digest":{"sha256":crate::platform_client::sha256_hex(&bytes)},"annotations":{"size":bytes.len().to_string()}}));
    }
    let statement = json!({"_type":IN_TOTO_STATEMENT_TYPE,"subject":subjects,"predicateType":PREDICATE,"predicate":metadata});
    if serde_json::to_vec(&statement)
        .map_err(|e| invalid(e.to_string()))?
        .len()
        > MAX_MANIFEST_BYTES
    {
        return Err(invalid("manifest is too large"));
    }
    validate(&statement, &files)?;
    Ok(UnsignedBundle { statement, files })
}

fn validate(statement: &Value, files: &BTreeMap<String, String>) -> Result<PolicySources> {
    let parsed: InTotoStatement =
        serde_json::from_value(statement.clone()).map_err(|e| invalid(e.to_string()))?;
    if parsed.statement_type != IN_TOTO_STATEMENT_TYPE {
        return Err(invalid("bundle.sig must contain an in-toto Statement v1"));
    }
    if parsed.predicate_type != PREDICATE {
        return Err(invalid(format!(
            "bundle.sig must use predicate {PREDICATE}"
        )));
    }
    if parsed.subject.is_empty() {
        return Err(invalid("bundle.sig contains an empty file inventory"));
    }
    if parsed.subject.len() > MAX_FILES || files.len() > MAX_FILES {
        return Err(invalid(format!(
            "bundle exceeds the {MAX_FILES}-file limit"
        )));
    }
    let metadata: Metadata =
        serde_json::from_value(parsed.predicate).map_err(|e| invalid(e.to_string()))?;
    if metadata.name.trim().is_empty()
        || metadata.publisher.trim().is_empty()
        || metadata.entrypoints.len() != 2
    {
        return Err(invalid("invalid metadata or unsupported entrypoints"));
    }
    let mut seen = BTreeSet::new();
    let mut decoded = BTreeMap::new();
    let mut total = 0usize;
    for (index, subject) in parsed.subject.iter().enumerate() {
        if !valid_path(&subject.name) {
            return Err(invalid_file(&subject.name, "invalid bundle-relative path"));
        }
        if !seen.insert(subject.name.to_ascii_lowercase()) {
            return Err(invalid_file(
                &subject.name,
                "duplicate or case-colliding inventory path",
            ));
        }
        let content = files.get(&subject.name).ok_or_else(|| {
            invalid_file(
                &subject.name,
                "listed in the signed inventory but missing from the bundle",
            )
        })?;
        if content.len() > MAX_BYTES * 2 {
            return Err(invalid_file(
                &subject.name,
                "encoded content exceeds the size limit",
            ));
        }
        let bytes = STANDARD
            .decode(content)
            .map_err(|_| invalid_file(&subject.name, "content is not valid standard base64"))?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("bundle is too large"))?;
        if total > MAX_BYTES {
            return Err(invalid("bundle is too large"));
        }
        let size = statement["subject"][index]["annotations"]["size"]
            .as_str()
            .and_then(|s| s.parse::<usize>().ok());
        let size = size.ok_or_else(|| {
            invalid_file(
                &subject.name,
                "signed size must be a decimal byte count encoded as a string",
            )
        })?;
        if size != bytes.len() {
            return Err(invalid_file(
                &subject.name,
                format!(
                    "size differs from the signed inventory (expected {size} bytes, found {})",
                    bytes.len()
                ),
            ));
        }
        if subject.digest.len() != 1 || !subject.digest.contains_key("sha256") {
            return Err(invalid_file(
                &subject.name,
                "signed inventory must specify exactly one SHA-256 digest",
            ));
        }
        if subject.digest.get("sha256") != Some(&crate::platform_client::sha256_hex(&bytes)) {
            return Err(invalid_file(
                &subject.name,
                "SHA-256 digest differs from the signed inventory",
            ));
        }
        decoded.insert(subject.name.clone(), bytes);
    }
    if let Some(path) = files.keys().find(|path| !decoded.contains_key(*path)) {
        return Err(invalid_file(
            path,
            "unexpected file is not listed in the signed inventory",
        ));
    }
    for path in &seen {
        let mut parent = path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if seen.contains(prefix) {
                return Err(invalid_file(
                    path,
                    format!("parent {prefix:?} is also listed as a file"),
                ));
            }
            parent = prefix;
        }
    }
    let document = |path: &str| -> Result<Value> {
        let bytes = decoded.get(path).ok_or_else(|| {
            invalid_file(
                path,
                "policy reference is not listed in the signed inventory",
            )
        })?;
        serde_json::from_slice(bytes)
            .map_err(|error| invalid_file(path, format!("invalid policy JSON: {error}")))
    };
    let entry = |name: &str| {
        metadata
            .entrypoints
            .get(name)
            .ok_or_else(|| invalid(format!("bundle.sig is missing the {name:?} entrypoint")))
    };
    let root = document(entry("policy")?)?;
    let groups =
        serde_json::from_value(document(entry("groups")?)?).map_err(|e| invalid(e.to_string()))?;
    let profiles = metadata
        .profiles
        .iter()
        .map(|(id, path)| Ok((id.clone(), document(path)?)))
        .collect::<Result<_>>()?;
    let policy = PolicySources {
        root,
        profiles,
        groups,
    };
    super::parse_sources(&policy)?;
    Ok(policy)
}

pub(crate) fn verify(
    bundle: &SignedBundle,
    root: &PolicyTrustRoot,
    digest: &str,
    revision: i64,
) -> Result<PolicySources> {
    let signature = &bundle.signature;
    let material = &signature["verificationMaterial"];
    if signature["mediaType"] != MEDIA_TYPE {
        return Err(invalid(
            "bundle.sig uses an unsupported Sigstore bundle version; expected v0.3",
        ));
    }
    if !exact_fields(
        signature,
        &["mediaType", "verificationMaterial", "dsseEnvelope"],
    ) || !exact_fields(material, &["publicKey", "tlogEntries"])
        || !exact_fields(&material["publicKey"], &["hint"])
        || !exact_fields(
            &signature["dsseEnvelope"],
            &["payloadType", "payload", "signatures"],
        )
    {
        return Err(invalid(
            "bundle.sig contains missing, conflicting or unsupported signature fields",
        ));
    }
    if material["publicKey"]["hint"] != root.key_id {
        return Err(invalid(
            "bundle.sig does not identify the pinned platform signing key",
        ));
    }
    if material["tlogEntries"]
        .as_array()
        .is_none_or(|entries| !entries.is_empty())
    {
        return Err(invalid(
            "bundle.sig tlogEntries must be an empty array for nono Bundle v1",
        ));
    }
    let envelope: DsseEnvelope = serde_json::from_value(signature["dsseEnvelope"].clone())
        .map_err(|error| {
            invalid(format!(
                "bundle.sig contains an invalid DSSE envelope: {error}"
            ))
        })?;
    if envelope.payload.len() > MAX_MANIFEST_BYTES * 2 {
        return Err(invalid("manifest is too large"));
    }
    if envelope.signatures.len() != 1 {
        return Err(invalid(
            "bundle.sig must contain exactly one DSSE signature",
        ));
    }
    let signature = &signature["dsseEnvelope"]["signatures"][0];
    if !exact_fields(signature, &["sig"]) && !exact_fields(signature, &["sig", "keyid"]) {
        return Err(invalid(
            "bundle.sig DSSE signature contains unsupported fields",
        ));
    }
    let key = URL_SAFE_NO_PAD
        .decode(&root.public_key)
        .map_err(|e| invalid(e.to_string()))?;
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        key,
    )
    .verify(
        &envelope.pae_bytes()?,
        &envelope.signatures[0].decode_sig()?,
    )
    .map_err(|_| invalid("bundle.sig signature is invalid for the pinned platform key"))?;
    envelope.extract_statement()?;
    let payload = envelope.decode_payload()?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(invalid("manifest is too large"));
    }
    if digest != format!("sha256:{}", crate::platform_client::sha256_hex(&payload)) {
        return Err(invalid(
            "bundle.sig signed inventory does not match the bundle assigned by the platform",
        ));
    }
    let statement: Value = serde_json::from_slice(&payload).map_err(|e| invalid(e.to_string()))?;
    if statement["predicate"]["revision"].as_i64() != Some(revision) {
        return Err(invalid(format!(
            "bundle.sig revision does not match assigned revision {revision}"
        )));
    }
    let sources = validate(&statement, &bundle.files)?;
    tracing::debug!(
        revision,
        bundle_digest = digest,
        files = bundle.files.len(),
        "Verified platform bundle signature and complete file inventory"
    );
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform_policy::protocol::{
        AssignedBundle, AssignmentClaims, PolicyRefreshResponse,
    };

    fn fixture() -> (PolicyTrustRoot, AssignedBundle) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/nono-bundle-v1.json"
        ))
        .expect("fixture");
        let root = serde_json::from_value(fixture["trust_root"].clone()).expect("root");
        let response: PolicyRefreshResponse =
            serde_json::from_value(fixture["response"].clone()).expect("response");
        let mut claims: AssignmentClaims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(response.payload).expect("payload"))
                .expect("claims");
        let mut policy = claims.policy.take().expect("policy");
        policy.bundle = response.bundle;
        (root, policy)
    }

    #[test]
    fn signed_inventory_preserves_policy_and_nested_signature() {
        let (root, policy) = fixture();
        let bundle = policy.bundle.expect("bundle");
        let document =
            verify(&bundle, &root, &policy.content_digest, policy.revision).expect("verified");
        let parsed = super::super::parse_sources(&document).expect("policy sources");
        assert!(
            serde_json::to_string(&parsed.0)
                .expect("profile")
                .contains("$HOME/shared.txt")
        );
        assert!(bundle.files.contains_key("packs/claude/bundle.sig"));
        let sigstore = nono::trust::load_bundle_from_str(
            &bundle.signature.to_string(),
            std::path::Path::new("bundle.sig"),
        )
        .expect("standard Sigstore bundle");
        assert_eq!(
            nono::trust::extract_all_subjects(&sigstore, std::path::Path::new("bundle.sig"))
                .expect("subjects")
                .len(),
            bundle.files.len()
        );
    }

    #[test]
    fn cached_directory_is_self_contained_and_rejects_extra_files_and_symlinks() {
        let (root, policy) = fixture();
        let bundle = policy.bundle.expect("bundle");
        let temp = tempfile::tempdir().expect("cache");
        let directory = cache_path(
            temp.path(),
            &bundle,
            &policy.content_digest,
            policy.revision,
        )
        .expect("path");
        assert!(directory.to_string_lossy().contains("engineering/r7-"));
        write_directory(&directory, &bundle).expect("write cache");
        let read = read_directory(&directory).expect("read cache");
        assert_eq!(read.files, bundle.files);
        verify(&read, &root, &policy.content_digest, policy.revision).expect("verify folder");
        let renamed = temp.path().join("renamed");
        std::fs::rename(&directory, &renamed).expect("rename");
        verify(
            &read_directory(&renamed).expect("read"),
            &root,
            &policy.content_digest,
            policy.revision,
        )
        .expect("renamed folder");
        std::fs::write(renamed.join("extra"), "unlisted").expect("extra");
        assert!(
            verify(
                &read_directory(&renamed).expect("read"),
                &root,
                &policy.content_digest,
                policy.revision
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(temp.path(), renamed.join("symlink")).expect("symlink");
            assert!(read_directory(&renamed).is_err());
        }
    }

    #[test]
    fn missing_extra_modified_files_and_bad_signatures_fail_closed() {
        let (root, policy) = fixture();
        let bundle = policy.bundle.expect("bundle");
        let check =
            |bundle: &SignedBundle| verify(bundle, &root, &policy.content_digest, policy.revision);
        for path in [
            "policy.json",
            "packs/claude/bundle.sig",
            "packs/claude/skills/review/SKILL.md",
            "packs/claude/assets/logo.bin",
        ] {
            let mut modified = bundle.clone();
            modified
                .files
                .insert(path.into(), STANDARD.encode(b"changed"));
            assert!(check(&modified).is_err(), "{path}");
            modified.files.remove(path);
            assert!(check(&modified).is_err(), "missing {path}");
        }
        let mut modified = bundle.clone();
        modified
            .files
            .insert("unexpected".into(), STANDARD.encode(b"extra"));
        assert!(check(&modified).is_err());
        modified = bundle.clone();
        modified.signature["dsseEnvelope"]["signatures"][0]["sig"] =
            json!(STANDARD.encode(b"invalid"));
        assert!(check(&modified).is_err());
        modified = bundle.clone();
        modified.signature["dsseEnvelope"]["payloadType"] = json!("unexpected/type");
        assert!(check(&modified).is_err());
        let mut unknown = root.clone();
        unknown.key_id = "other".into();
        assert!(verify(&bundle, &unknown, &policy.content_digest, policy.revision).is_err());
        assert!(verify(&bundle, &root, "sha256:wrong", policy.revision).is_err());
        assert!(verify(&bundle, &root, &policy.content_digest, policy.revision + 1).is_err());
    }

    #[test]
    fn inventory_errors_identify_the_file_and_specific_failure() {
        let (_, policy) = fixture();
        let bundle = policy.bundle.expect("bundle");
        let statement: Value = serde_json::from_slice(
            &STANDARD
                .decode(
                    bundle.signature["dsseEnvelope"]["payload"]
                        .as_str()
                        .expect("payload"),
                )
                .expect("base64"),
        )
        .expect("statement");
        let check = |files: &BTreeMap<String, String>, path: &str, reason: &str| {
            let error = validate(&statement, files)
                .err()
                .expect("rejected")
                .to_string();
            assert!(error.contains(path), "{error}");
            assert!(error.contains(reason), "{error}");
        };
        let mut files = bundle.files.clone();
        files.remove("policy.json");
        check(&files, "policy.json", "missing from the bundle");
        files = bundle.files.clone();
        files.insert("unsigned-hook.sh".into(), STANDARD.encode(b"unapproved"));
        check(
            &files,
            "unsigned-hook.sh",
            "not listed in the signed inventory",
        );
        files = bundle.files.clone();
        files.insert("policy.json".into(), STANDARD.encode(b"{}"));
        check(
            &files,
            "policy.json",
            "size differs from the signed inventory",
        );
        let mut bytes = STANDARD.decode(&bundle.files["policy.json"]).expect("file");
        bytes[0] ^= 1;
        files.insert("policy.json".into(), STANDARD.encode(bytes));
        check(&files, "policy.json", "SHA-256 digest differs");
        files.insert("policy.json".into(), "not base64!".into());
        check(&files, "policy.json", "not valid standard base64");
    }

    #[test]
    fn signature_envelope_rejects_conflicting_or_unsupported_verification_material() {
        let (root, policy) = fixture();
        let bundle = policy.bundle.expect("bundle");
        for (pointer, value) in [
            ("/messageSignature", json!({"signature":"invalid"})),
            ("/verificationMaterial/tlogEntries", json!("invalid")),
            ("/verificationMaterial/tlogEntries", json!([{}])),
            (
                "/verificationMaterial/certificate",
                json!({"rawBytes":"invalid"}),
            ),
            ("/verificationMaterial/timestampVerificationData", json!({})),
            ("/verificationMaterial/publicKey/extra", json!(true)),
            ("/dsseEnvelope/extra", json!(true)),
            ("/dsseEnvelope/signatures/0/extra", json!(true)),
        ] {
            let mut modified = bundle.clone();
            let (parent, field) = pointer.rsplit_once('/').expect("pointer");
            modified
                .signature
                .pointer_mut(parent)
                .expect("parent")
                .as_object_mut()
                .expect("object")
                .insert(field.into(), value);
            assert!(
                verify(&modified, &root, &policy.content_digest, policy.revision).is_err(),
                "{pointer}"
            );
        }
        let mut modified = bundle.clone();
        modified.signature["verificationMaterial"]
            .as_object_mut()
            .expect("object")
            .remove("tlogEntries");
        assert!(verify(&modified, &root, &policy.content_digest, policy.revision).is_err());
    }

    #[test]
    fn inventories_reject_unsafe_duplicate_and_unresolved_paths() {
        let (_, policy) = fixture();
        let bundle = policy.bundle.expect("bundle");
        let payload = STANDARD
            .decode(
                bundle.signature["dsseEnvelope"]["payload"]
                    .as_str()
                    .expect("payload"),
            )
            .expect("base64");
        let statement: Value = serde_json::from_slice(&payload).expect("statement");
        for path in [
            "../escape",
            "/absolute",
            "a/../b",
            "a//b",
            "a\\b",
            "C:/file",
            "bundle.sig",
        ] {
            let mut modified = statement.clone();
            let original = modified["subject"][0]["name"]
                .as_str()
                .expect("name")
                .to_owned();
            modified["subject"][0]["name"] = json!(path);
            let mut files = bundle.files.clone();
            let bytes = files.remove(&original).expect("file");
            files.insert(path.into(), bytes);
            assert!(validate(&modified, &files).is_err(), "{path}");
        }
        let mut modified = statement.clone();
        modified["subject"][1] = modified["subject"][0].clone();
        assert!(validate(&modified, &bundle.files).is_err());
        modified = statement.clone();
        modified["predicateType"] = json!("https://nono.sh/attestation/bundle/v99");
        assert!(validate(&modified, &bundle.files).is_err());
        modified = statement.clone();
        modified["predicate"]["entrypoints"]["policy"] = json!("unlisted.json");
        assert!(validate(&modified, &bundle.files).is_err());
        modified = statement.clone();
        modified["subject"][0]["annotations"]["size"] = json!("999999999");
        assert!(validate(&modified, &bundle.files).is_err());
        modified = statement.clone();
        let mut files = bundle.files.clone();
        let changed = json!({"extends":["not-in-bundle"]}).to_string();
        files.insert("policy.json".into(), STANDARD.encode(&changed));
        for subject in modified["subject"].as_array_mut().expect("subjects") {
            if subject["name"] == "policy.json" {
                subject["digest"]["sha256"] =
                    json!(crate::platform_client::sha256_hex(changed.as_bytes()));
                subject["annotations"]["size"] = json!(changed.len().to_string());
            }
        }
        assert!(validate(&modified, &files).is_err());
    }
}
