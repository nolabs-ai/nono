//! File attestation and integrity verification
//!
//! This module provides types, digest computation, and trust policy primitives
//! for verifying the provenance and integrity of files before they are consumed.
//!
//! # Architecture
//!
//! ```text
//! file --> digest --> blocklist check --> bundle verify --> publisher match --> allow/deny
//! ```
//!
//! The library provides attestation primitives reusable by all language bindings.
//! Signing, CLI commands, and policy file loading live in `nono-cli`.
//!
//! # Components
//!
//! - **Types** ([`types`]): Trust policy, publisher identity, blocklist, verification result
//! - **Digest** ([`digest`]): SHA-256 digest computation for files and byte slices
//! - **Policy** ([`policy`]): Loading, merging, and evaluation of trust policies
//! - **DSSE** ([`dsse`]): Dead Simple Signing Envelope parsing, PAE construction, in-toto statements
//! - **Bundle** ([`bundle`]): Sigstore bundle loading, verification, and identity extraction
//! - **Signing** ([`signing`]): Keyed ECDSA P-256 signing and Sigstore bundle construction
//!
//! # Security
//!
//! - Blocklist checked before any cryptographic verification (fast reject)
//! - Enforcement modes: `Deny` (hard block), `Warn` (log + allow), `Audit` (silent allow + log)
//! - Project-level policy cannot weaken user-level enforcement
//! - No TOFU: files must have valid signatures from trusted publishers on first encounter

pub mod base64;
pub mod bundle;
pub mod digest;
pub mod dsse;
pub mod policy;
pub mod signing;
pub mod types;

pub use bundle::{
    Bundle, CertificateInfo, DerPublicKey, Sha256Hash, SigstoreVerificationResult, TrustedRoot,
    VerificationPolicy, bundle_path_for, extract_all_subjects, extract_bundle_digest,
    extract_predicate_type, extract_signer_identity, load_bundle, load_bundle_from_str,
    load_production_trusted_root, load_trusted_root, load_trusted_root_from_str,
    multi_subject_bundle_path, parse_cert_info, verify_bundle, verify_bundle_keyed,
    verify_bundle_subject_name, verify_bundle_with_digest, verify_keyed_signature,
};
pub use digest::{bytes_digest, file_digest};
pub use dsse::{
    DsseEnvelope, DsseSignature, IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE, InTotoStatement,
    InTotoSubject, NONO_MULTI_SUBJECT_PREDICATE_TYPE, NONO_POLICY_PREDICATE_TYPE,
    NONO_PREDICATE_TYPE, new_envelope, new_instruction_statement, new_multi_subject_statement,
    new_policy_statement, new_statement, pae,
};
pub use policy::{
    evaluate_file, find_included_files, find_included_files_with_skip_dirs, load_policy_from_file,
    load_policy_from_str, merge_policies,
};
pub use signing::{
    KeyPair, MAX_MULTI_SUBJECT_FILES, SigningScheme, export_public_key, generate_signing_key,
    key_id_hex, public_key_id_hex, sign_bytes, sign_files, sign_instruction_file,
    sign_policy_bytes, sign_policy_file, sign_statement_bundle, write_bundle,
};
pub use types::{
    BlockedPublisher, Blocklist, BlocklistEntry, Enforcement, IncludePatterns, Publisher,
    SignerIdentity, TRUST_POLICY_VERSION, TrustPolicy, VerificationOutcome, VerificationResult,
};
