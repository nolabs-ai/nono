//! CLI commands for aauth agent identity keys.
//!
//! Implements `nono aauth keygen|import|show`. Keys are Ed25519, stored as
//! base64-encoded PKCS#8 DER — the same encoding `nono trust keygen` uses
//! for its own (unrelated) ECDSA signing key — behind the same `file://` /
//! `keyring://` / `env://` URI scheme as `credential_key`, so an
//! `aauth_identity.key_ref` in a profile resolves exactly like any other
//! credential reference.

use crate::cli::{AauthArgs, AauthCommands, AauthImportArgs, AauthKeygenArgs, AauthShowArgs};
use aauth_core::keys::{PrivateKey, generate_jwks, private_key_to_jwk};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use colored::Colorize;
use nono::{NonoError, Result};
use nono_proxy::aauth::jwk_thumbprint;
use zeroize::Zeroizing;

/// Run an aauth subcommand.
pub fn run_aauth(args: AauthArgs) -> Result<()> {
    match args.command {
        AauthCommands::Keygen(keygen_args) => run_keygen(keygen_args),
        AauthCommands::Import(import_args) => run_import(import_args),
        AauthCommands::Show(show_args) => run_show(show_args),
    }
}

/// Only `file://` key refs can be written by this command — `nono::keystore`
/// exposes no generic "store" for `keyring://`/`env://`. Callers who want
/// those backends must place the base64 PKCS#8 there themselves (the same
/// value this command would otherwise write to a file).
fn store_key(key_ref: &str, private_key: &PrivateKey, force: bool) -> Result<()> {
    let Some(path) = key_ref.strip_prefix("file://") else {
        return Err(NonoError::KeystoreAccess(format!(
            "aauth key storage only supports file:// key refs directly; got '{key_ref}'. \
             Store the base64 PKCS#8 value yourself for keyring:// or env:// backends."
        )));
    };
    let path = std::path::Path::new(path);
    if !force && path.exists() {
        return Err(NonoError::KeystoreAccess(format!(
            "key already exists at '{}' (use --force to overwrite)",
            path.display()
        )));
    }
    let der = private_key
        .to_pkcs8_der()
        .map_err(|e| NonoError::KeystoreAccess(format!("PKCS#8 encoding failed: {e}")))?;
    let encoded = Zeroizing::new(BASE64.encode(&*der));
    nono::store_secret_file(path, &encoded)
}

fn print_generated(key_ref: &str, private_key: &PrivateKey) -> Result<()> {
    let thumbprint = jwk_thumbprint(private_key)
        .map_err(|e| NonoError::KeystoreAccess(format!("thumbprint failed: {e}")))?;
    eprintln!("{}", "aauth identity ready.".green());
    eprintln!("  key_ref:    {key_ref}");
    eprintln!("  algorithm:  Ed25519");
    eprintln!("  thumbprint: {thumbprint}");
    eprintln!();
    eprintln!("Add to your profile (hwk — no hosting required):");
    eprintln!("  \"aauth_identity\": {{");
    eprintln!("    \"key_ref\": \"{key_ref}\"");
    eprintln!("  }}");
    eprintln!("  (agent_id is optional here — a local label for your audit log only;");
    eprintln!("  omit it and it defaults to the thumbprint above.)");
    eprintln!();
    eprintln!("Or, to use jwks_uri instead (run `nono aauth show --keyref {key_ref} --jwks`");
    eprintln!("for the JSON to host, then point 'issuer' at where you host it):");
    eprintln!("  \"aauth_identity\": {{");
    eprintln!("    \"key_ref\": \"{key_ref}\",");
    eprintln!("    \"scheme\": {{\"type\": \"jwks_uri\", \"issuer\": \"https://<your-host>\"}}");
    eprintln!("  }}");
    eprintln!("  (don't set agent_id here — under jwks_uri it's always the issuer above,");
    eprintln!("  since that's the only identity a verifying resource ever recovers.)");
    Ok(())
}

fn run_keygen(args: AauthKeygenArgs) -> Result<()> {
    let (private_key, _public_key) = aauth_core::keys::generate_ed25519_keypair();
    store_key(&args.keyref, &private_key, args.force)?;
    print_generated(&args.keyref, &private_key)
}

fn run_import(args: AauthImportArgs) -> Result<()> {
    let pem = Zeroizing::new(std::fs::read_to_string(&args.pem_file).map_err(|e| {
        NonoError::KeystoreAccess(format!("failed to read '{}': {e}", args.pem_file.display()))
    })?);
    let private_key = PrivateKey::from_pkcs8_pem(&pem)
        .map_err(|e| NonoError::KeystoreAccess(format!("invalid Ed25519 PEM key: {e}")))?;
    store_key(&args.keyref, &private_key, args.force)?;
    print_generated(&args.keyref, &private_key)
}

fn run_show(args: AauthShowArgs) -> Result<()> {
    let secret = nono::load_secret_by_ref(nono::keystore::DEFAULT_SERVICE, &args.keyref)?;
    let der = Zeroizing::new(BASE64.decode(secret.trim()).map_err(|e| {
        NonoError::KeystoreAccess(format!("key at '{}' is not valid base64: {e}", args.keyref))
    })?);
    let private_key = PrivateKey::from_pkcs8_der(&der)
        .map_err(|e| NonoError::KeystoreAccess(format!("invalid PKCS#8 Ed25519 key: {e}")))?;
    let thumbprint = jwk_thumbprint(&private_key)
        .map_err(|e| NonoError::KeystoreAccess(format!("thumbprint failed: {e}")))?;
    // `kid` is always the thumbprint — the same value `AauthSigner` sends in
    // a `jwks_uri`-scheme `Signature-Key` header, so whatever's hosted here
    // is guaranteed to have the entry a signed request will ask for.
    let jwk = private_key_to_jwk(&private_key, Some(&thumbprint));

    if args.jwks {
        println!("{}", generate_jwks(&[jwk]));
        return Ok(());
    }

    eprintln!("  key_ref:    {}", args.keyref);
    eprintln!("  algorithm:  Ed25519");
    eprintln!("  thumbprint: {thumbprint}");
    eprintln!("  public jwk: {}", jwk.to_value());
    eprintln!();
    eprintln!(
        "For jwks_uri: `nono aauth show --keyref {} --jwks` prints the",
        args.keyref
    );
    eprintln!("JWKS document to host at your issuer's jwks_uri.");
    Ok(())
}
