//! CLI commands for aauth agent identity keys.
//!
//! Generate Ed25519 PKCS#8 PEM files or inspect existing keys. Existing
//! PEM/DER files can be referenced directly. Runtime
//! references additionally support keyring:// and env:// secrets.

use crate::cli::{AauthArgs, AauthCommands, AauthKeygenArgs, AauthShowArgs};
use aauth_core::keys::{PrivateKey, generate_jwks};
use colored::Colorize;
use nono::{NonoError, Result};
use nono_proxy::aauth::{jwk_thumbprint, key_file_path, load_private_key, public_jwk};
use pkcs8::EncodePrivateKey;

mod key_file;

/// Run an aauth subcommand.
pub fn run_aauth(args: AauthArgs) -> Result<()> {
    match args.command {
        AauthCommands::Keygen(keygen_args) => run_keygen(keygen_args),
        AauthCommands::Show(show_args) => run_show(show_args),
    }
}

/// Only absolute paths and `file://` refs can be written — `nono::keystore`
/// exposes no generic "store" for `keyring://`/`env://`. Callers who want
/// those backends must provision the PEM or base64 DER value themselves.
fn store_key(key_ref: &str, private_key: &PrivateKey, force: bool) -> Result<()> {
    let path = key_file_path(key_ref)
        .map_err(|e| NonoError::KeystoreAccess(e.to_string()))?
        .ok_or_else(|| {
            NonoError::KeystoreAccess(
                "keygen writes only to an absolute path or file:// reference".to_string(),
            )
        })?;
    let PrivateKey::Ed25519(key) = private_key else {
        return Err(NonoError::KeystoreAccess(
            "expected an Ed25519 key".to_string(),
        ));
    };
    // The library returns zeroizing PEM storage; no intermediate base64 copy.
    let pem = key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|_| NonoError::KeystoreAccess("could not encode Ed25519 key".to_string()))?;
    key_file::store(&path, pem.as_bytes(), force)
}

fn print_generated(key_ref: &str, private_key: &PrivateKey) -> Result<()> {
    let json_key_ref = serde_json::json!(key_ref);
    let show_command = show_jwks_command(key_ref);
    let thumbprint = jwk_thumbprint(private_key)
        .map_err(|e| NonoError::KeystoreAccess(format!("thumbprint failed: {e}")))?;
    eprintln!("{}", "aauth identity ready.".green());
    eprintln!("  key_ref:    {key_ref}");
    eprintln!("  algorithm:  Ed25519");
    eprintln!("  thumbprint: {thumbprint}");
    eprintln!();
    eprintln!("For Aauth agent identity, publish the public JWKS:");
    eprintln!("  {show_command}");
    eprintln!("Host /.well-known/aauth-agent.json with issuer and jwks_uri, then configure:");
    eprintln!("  \"aauth_identity\": {{");
    eprintln!("    \"key_ref\": {json_key_ref},");
    eprintln!("    \"agent_id\": \"aauth:agent@agent.example.com\",");
    eprintln!("    \"scheme\": {{\"type\": \"jwt\", \"issuer\": \"https://agent.example.com\"}}");
    eprintln!("  }}");
    eprintln!("  Replace agent.example.com with your HTTPS host in both fields.");
    eprintln!("  nono self-issues a one-hour agent token at startup; restart to renew.");
    eprintln!();
    eprintln!("For generic HTTP signatures without Aauth agent identity (hwk, no hosting):");
    eprintln!("  \"aauth_identity\": {{");
    eprintln!("    \"key_ref\": {json_key_ref}");
    eprintln!("  }}");
    Ok(())
}

fn show_jwks_command(key_ref: &str) -> String {
    crate::command_display::format_command_line(&[
        "nono", "aauth", "show", "--keyref", key_ref, "--jwks",
    ])
}

fn run_keygen(args: AauthKeygenArgs) -> Result<()> {
    let (private_key, _public_key) = aauth_core::keys::generate_ed25519_keypair();
    store_key(&args.keyref, &private_key, args.force)?;
    print_generated(&args.keyref, &private_key)
}

fn run_show(args: AauthShowArgs) -> Result<()> {
    let private_key =
        load_private_key(&args.keyref).map_err(|e| NonoError::KeystoreAccess(e.to_string()))?;
    let thumbprint = jwk_thumbprint(&private_key)
        .map_err(|e| NonoError::KeystoreAccess(format!("thumbprint failed: {e}")))?;
    // `kid` is always the thumbprint — the same value `AauthSigner` sends in
    // a `jwks_uri`-scheme `Signature-Key` header, so whatever's hosted here
    // is guaranteed to have the entry a signed request will ask for.
    let jwk = public_jwk(&private_key, Some(&thumbprint));

    if args.jwks {
        println!("{}", generate_jwks(&[jwk]));
        return Ok(());
    }

    eprintln!("  key_ref:    {}", args.keyref);
    eprintln!("  algorithm:  Ed25519");
    eprintln!("  thumbprint: {thumbprint}");
    eprintln!("  public jwk: {}", jwk.to_value());
    eprintln!();
    eprintln!("Print the public JWKS to host for agent-token verification:");
    eprintln!("  {}", show_jwks_command(&args.keyref));
    Ok(())
}
