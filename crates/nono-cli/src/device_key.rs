//! Persistent software keys for login-authorized device enrollment.

use aws_lc_rs::signature::EcdsaKeyPair;
use nono::{NonoError, Result};
use std::path::Path;

pub(crate) fn load_or_create(
    issuer: &str,
    tenant: &str,
    user: &str,
) -> Result<(String, EcdsaKeyPair)> {
    let id = crate::platform_client::enrollment_scope_id(issuer, tenant, user)?;
    let dir = crate::state_paths::user_state_dir()?
        .join("platform-device-keys")
        .join(id);
    load_or_create_in(&dir)
}

pub(crate) fn replacement(
    issuer: &str,
    tenant: &str,
    user: &str,
    subject: &str,
) -> Result<(String, EcdsaKeyPair)> {
    let subject = uuid::Uuid::parse_str(subject)
        .map_err(|_| NonoError::ConfigParse("invalid registration to replace".into()))?;
    let scope = crate::platform_client::enrollment_scope_id(issuer, tenant, user)?;
    let dir = crate::state_paths::user_state_dir()?
        .join("platform-device-keys")
        .join(scope)
        .join("replacements")
        .join(subject.to_string());
    load_or_create_in(&dir)
}

fn load_or_create_in(dir: &Path) -> Result<(String, EcdsaKeyPair)> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| NonoError::KeystoreAccess("cannot create device key directory".into()))?;
    let path = dir.join("software.pkcs8");
    let key_ref = crate::trust_keystore::TrustKeyRef::File(path.clone());
    let key = crate::platform_client::load_or_create_signing_key_for_ref(&key_ref)?;
    Ok((format!("file://{}", path.display()), key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn software_keys_persist_and_sign_without_a_keyring() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("device");
        let (reference, key) = load_or_create_in(&path).expect("key");
        let (reloaded_reference, reloaded) = load_or_create_in(&path).expect("reload");
        assert_eq!(reference, reloaded_reference);
        assert_eq!(key.public_key().as_ref(), reloaded.public_key().as_ref());
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(path.join("software.pkcs8"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let signature = reloaded
            .sign(&SystemRandom::new(), b"device proof")
            .expect("signature");
        let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref());
        public
            .verify(b"device proof", signature.as_ref())
            .expect("verification");
        assert!(public.verify(b"changed proof", signature.as_ref()).is_err());
    }

    #[test]
    fn invalid_stored_keys_are_not_replaced() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("software.pkcs8");
        nono::store_secret_file(&path, "invalid").expect("store");
        assert!(load_or_create_in(dir.path()).is_err());
        assert_eq!(std::fs::read_to_string(path).expect("contents"), "invalid");
    }
}
