use nono::supervisor::{
    CredentialFrontend, CredentialItemClass, CredentialOperation, CredentialProvider,
    CredentialRequest, CredentialResponse, SecretBytes, SupervisorMessage, SupervisorResponse,
};
use nono::{NonoError, Result};
use std::io::{Read, Write};
use std::path::Path;

pub(crate) const CREDENTIAL_BROKER_ENV: &str = "NONO_CREDENTIAL_BROKER";
pub(crate) const CREDENTIAL_BROKER_VERSION_ENV: &str = "NONO_CREDENTIAL_BROKER_VERSION";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialSecurityCommand {
    pub(crate) operation: CredentialOperation,
    pub(crate) item_class: CredentialItemClass,
    pub(crate) service: Option<String>,
    pub(crate) account: Option<String>,
    pub(crate) label: Option<String>,
    pub(crate) secret: Option<SecretBytes>,
    pub(crate) return_secret: bool,
}

impl CredentialSecurityCommand {
    pub(crate) fn into_request(
        self,
        request_id: String,
        child_pid: u32,
        session_id: String,
    ) -> CredentialRequest {
        CredentialRequest {
            request_id,
            frontend: CredentialFrontend::SecurityCli,
            provider: CredentialProvider::MacosKeychain,
            operation: self.operation,
            item_class: self.item_class,
            service: self.service,
            account: self.account,
            label: self.label,
            server: None,
            protocol: None,
            path: None,
            access_group: None,
            secret: self.secret,
            return_secret: self.return_secret,
            child_pid,
            session_id,
        }
    }
}

pub(crate) fn parse_security_cli_args(
    args: &[String],
) -> std::result::Result<CredentialSecurityCommand, String> {
    if args.first().is_some_and(|arg| arg == "-i") {
        return parse_security_stdin();
    }

    let Some(command) = args.first().map(String::as_str) else {
        return Err("missing security command".to_string());
    };

    match command {
        "find-generic-password" => parse_find_generic_password(&args[1..]),
        "add-generic-password" => parse_add_generic_password(&args[1..]),
        "delete-generic-password" => parse_delete_generic_password(&args[1..]),
        "show-keychain-info" => Ok(CredentialSecurityCommand {
            operation: CredentialOperation::Status,
            item_class: CredentialItemClass::GenericPassword,
            service: None,
            account: None,
            label: None,
            secret: None,
            return_secret: false,
        }),
        other => Err(format!("unsupported security command: {other}")),
    }
}

pub(crate) fn run_credential_helper(args: &[String]) -> Result<()> {
    let socket_path = std::env::var(CREDENTIAL_BROKER_ENV).map_err(|_| {
        NonoError::SandboxInit(format!(
            "{CREDENTIAL_BROKER_ENV} not set. credential helper must be invoked inside a nono supervised sandbox."
        ))
    })?;
    if let Ok(version) = std::env::var(CREDENTIAL_BROKER_VERSION_ENV)
        && version != "1"
    {
        return Err(NonoError::SandboxInit(format!(
            "unsupported credential broker protocol version: {version}"
        )));
    }

    let request_id = format!(
        "credential-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let session_id = std::env::var("NONO_SESSION_ID").unwrap_or_else(|_| "unknown".to_string());
    let request = parse_security_cli_args(args)
        .map_err(|e| NonoError::SandboxInit(format!("unsupported security invocation: {e}")))?
        .into_request(request_id, std::process::id(), session_id);

    let mut socket = nono::supervisor::SupervisorSocket::connect(Path::new(&socket_path))?;
    socket.send_message(&SupervisorMessage::Credential(request))?;

    match socket.recv_response()? {
        SupervisorResponse::Credential(CredentialResponse::Ok { secret, .. }) => {
            if let Some(secret) = secret {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&secret).map_err(|e| {
                    NonoError::SandboxInit(format!("failed to write credential response: {e}"))
                })?;
                stdout.write_all(b"\n").map_err(|e| {
                    NonoError::SandboxInit(format!("failed to write credential response: {e}"))
                })?;
            }
            Ok(())
        }
        SupervisorResponse::Credential(CredentialResponse::Denied { reason, .. })
        | SupervisorResponse::Credential(CredentialResponse::Unsupported { reason, .. })
        | SupervisorResponse::Credential(CredentialResponse::Error { reason, .. }) => {
            Err(NonoError::SandboxInit(reason))
        }
        _ => Err(NonoError::SandboxInit(
            "invalid supervisor response type for credential request".to_string(),
        )),
    }
}

pub(crate) fn handle_credential_request(
    request: CredentialRequest,
    grants: &[crate::profile::CredentialAccessGrant],
) -> CredentialResponse {
    let request_id = request.request_id.clone();
    match authorize_credential_request(&request, grants)
        .and_then(|()| handle_credential_request_inner(request))
    {
        Ok(secret) => CredentialResponse::Ok { request_id, secret },
        Err(CredentialBrokerError::Denied(reason)) => {
            CredentialResponse::Denied { request_id, reason }
        }
        Err(CredentialBrokerError::Unsupported(reason)) => {
            CredentialResponse::Unsupported { request_id, reason }
        }
        Err(CredentialBrokerError::Error(reason)) => {
            CredentialResponse::Error { request_id, reason }
        }
    }
}

fn authorize_credential_request(
    request: &CredentialRequest,
    grants: &[crate::profile::CredentialAccessGrant],
) -> std::result::Result<(), CredentialBrokerError> {
    if grants.is_empty() {
        return Err(CredentialBrokerError::Denied(
            "no credential_access grant configured for this profile".to_string(),
        ));
    }

    for grant in grants {
        if grant.provider != request.provider {
            continue;
        }
        if !grant.classes.contains(&request.item_class) {
            continue;
        }
        if !grant.operations.contains(&request.operation) {
            continue;
        }
        if !service_matches(request.service.as_deref(), grant) {
            continue;
        }
        if !account_matches(request.account.as_deref(), grant) {
            continue;
        }
        return Ok(());
    }

    Err(CredentialBrokerError::Denied(
        "credential request did not match profile credential_access policy".to_string(),
    ))
}

fn service_matches(service: Option<&str>, grant: &crate::profile::CredentialAccessGrant) -> bool {
    let Some(service) = service else {
        return false;
    };
    grant.services.iter().any(|allowed| allowed == service)
        || grant
            .service_prefixes
            .iter()
            .any(|prefix| service.starts_with(prefix))
}

fn account_matches(account: Option<&str>, grant: &crate::profile::CredentialAccessGrant) -> bool {
    grant.accounts.iter().any(|allowed| allowed == "*")
        || account.is_some_and(|account| grant.accounts.iter().any(|allowed| allowed == account))
}

fn parse_security_stdin() -> std::result::Result<CredentialSecurityCommand, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("failed to read security -i input: {e}"))?;
    let line = input
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "security -i input did not contain a command".to_string())?;
    let args = shlex::split(line)
        .ok_or_else(|| "security -i input contains malformed shell quoting".to_string())?;
    parse_security_cli_args(&args)
}

#[derive(Debug)]
enum CredentialBrokerError {
    Denied(String),
    Unsupported(String),
    Error(String),
}

fn handle_credential_request_inner(
    request: CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    if request.provider != CredentialProvider::MacosKeychain {
        return Err(CredentialBrokerError::Unsupported(
            "unsupported credential provider".to_string(),
        ));
    }
    if request.item_class != CredentialItemClass::GenericPassword {
        return Err(CredentialBrokerError::Unsupported(
            "only generic-password items are supported".to_string(),
        ));
    }

    match request.operation {
        CredentialOperation::Read => read_generic_password(&request),
        CredentialOperation::Create | CredentialOperation::Update | CredentialOperation::Upsert => {
            write_generic_password(&request)
        }
        CredentialOperation::Delete => delete_generic_password(&request),
        CredentialOperation::Status => Ok(None),
    }
}

#[cfg(feature = "system-keyring")]
fn keyring_entry(
    request: &CredentialRequest,
) -> std::result::Result<keyring::Entry, CredentialBrokerError> {
    let service = request.service.as_deref().ok_or_else(|| {
        CredentialBrokerError::Denied("credential service is required".to_string())
    })?;
    let account = request.account.as_deref().ok_or_else(|| {
        CredentialBrokerError::Denied("credential account is required".to_string())
    })?;
    keyring::Entry::new(service, account)
        .map_err(|e| CredentialBrokerError::Error(format!("failed to open keychain entry: {e}")))
}

#[cfg(feature = "system-keyring")]
fn read_generic_password(
    request: &CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    let entry = keyring_entry(request)?;
    let password = entry
        .get_password()
        .map_err(|e| CredentialBrokerError::Error(format!("failed to read keychain entry: {e}")))?;
    if request.return_secret {
        Ok(Some(SecretBytes::new(password.into_bytes())))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "system-keyring")]
fn write_generic_password(
    request: &CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    let entry = keyring_entry(request)?;
    let secret = request.secret.as_deref().ok_or_else(|| {
        CredentialBrokerError::Denied("credential secret is required".to_string())
    })?;
    let secret = std::str::from_utf8(secret).map_err(|e| {
        CredentialBrokerError::Denied(format!("credential secret must be UTF-8: {e}"))
    })?;
    entry.set_password(secret).map_err(|e| {
        CredentialBrokerError::Error(format!("failed to write keychain entry: {e}"))
    })?;
    Ok(None)
}

#[cfg(feature = "system-keyring")]
fn delete_generic_password(
    request: &CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    let entry = keyring_entry(request)?;
    entry.delete_credential().map_err(|e| {
        CredentialBrokerError::Error(format!("failed to delete keychain entry: {e}"))
    })?;
    Ok(None)
}

#[cfg(not(feature = "system-keyring"))]
fn read_generic_password(
    _request: &CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    Err(CredentialBrokerError::Unsupported(
        "system keyring support is disabled".to_string(),
    ))
}

#[cfg(not(feature = "system-keyring"))]
fn write_generic_password(
    _request: &CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    Err(CredentialBrokerError::Unsupported(
        "system keyring support is disabled".to_string(),
    ))
}

#[cfg(not(feature = "system-keyring"))]
fn delete_generic_password(
    _request: &CredentialRequest,
) -> std::result::Result<Option<SecretBytes>, CredentialBrokerError> {
    Err(CredentialBrokerError::Unsupported(
        "system keyring support is disabled".to_string(),
    ))
}

fn parse_find_generic_password(
    args: &[String],
) -> std::result::Result<CredentialSecurityCommand, String> {
    let flags = parse_security_flags(args)?;
    let service = require_flag(&flags.service, "-s")?;
    let account = flags.account;

    Ok(CredentialSecurityCommand {
        operation: CredentialOperation::Read,
        item_class: CredentialItemClass::GenericPassword,
        service: Some(service),
        account,
        label: None,
        secret: None,
        return_secret: flags.print_password,
    })
}

fn parse_add_generic_password(
    args: &[String],
) -> std::result::Result<CredentialSecurityCommand, String> {
    let flags = parse_security_flags(args)?;
    let service = require_flag(&flags.service, "-s")?;
    let account = require_flag(&flags.account, "-a")?;
    let secret = flags
        .secret
        .ok_or_else(|| "add-generic-password requires a secret via -w or -X".to_string())?;

    Ok(CredentialSecurityCommand {
        operation: if flags.update_existing {
            CredentialOperation::Upsert
        } else {
            CredentialOperation::Create
        },
        item_class: CredentialItemClass::GenericPassword,
        service: Some(service),
        account: Some(account),
        label: flags.label,
        secret: Some(secret),
        return_secret: false,
    })
}

fn parse_delete_generic_password(
    args: &[String],
) -> std::result::Result<CredentialSecurityCommand, String> {
    let flags = parse_security_flags(args)?;
    let service = require_flag(&flags.service, "-s")?;
    let account = flags.account;

    Ok(CredentialSecurityCommand {
        operation: CredentialOperation::Delete,
        item_class: CredentialItemClass::GenericPassword,
        service: Some(service),
        account,
        label: None,
        secret: None,
        return_secret: false,
    })
}

#[derive(Default)]
struct SecurityFlags {
    account: Option<String>,
    service: Option<String>,
    label: Option<String>,
    secret: Option<SecretBytes>,
    print_password: bool,
    update_existing: bool,
}

fn parse_security_flags(args: &[String]) -> std::result::Result<SecurityFlags, String> {
    let mut flags = SecurityFlags::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-a" => {
                i += 1;
                flags.account = Some(next_value(args, i, "-a")?.to_string());
            }
            "-s" => {
                i += 1;
                flags.service = Some(next_value(args, i, "-s")?.to_string());
            }
            "-l" => {
                i += 1;
                flags.label = Some(next_value(args, i, "-l")?.to_string());
            }
            "-w" => {
                if matches!(args.get(i + 1), Some(value) if !value.starts_with('-')) {
                    i += 1;
                    flags.secret = Some(SecretBytes::new(args[i].as_bytes().to_vec()));
                } else {
                    flags.print_password = true;
                }
            }
            "-X" => {
                i += 1;
                flags.secret = Some(decode_hex(next_value(args, i, "-X")?)?);
            }
            "-U" => {
                flags.update_existing = true;
            }
            "-D" => {
                i += 1;
                let _ = next_value(args, i, "-D")?;
            }
            "-i" => return Err("security -i must be the top-level invocation".to_string()),
            other => return Err(format!("unsupported security flag: {other}")),
        }
        i += 1;
    }
    Ok(flags)
}

fn next_value<'a>(
    args: &'a [String],
    index: usize,
    flag: &str,
) -> std::result::Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn require_flag(value: &Option<String>, flag: &str) -> std::result::Result<String, String> {
    value
        .clone()
        .ok_or_else(|| format!("{flag} is required for this security command"))
}

fn decode_hex(input: &str) -> std::result::Result<SecretBytes, String> {
    if !input.len().is_multiple_of(2) {
        return Err("-X hex value must have an even number of digits".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(SecretBytes::new(out))
}

fn hex_nibble(byte: u8) -> std::result::Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex digit in -X value".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::CredentialAccessGrant;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn grant() -> CredentialAccessGrant {
        CredentialAccessGrant {
            provider: CredentialProvider::MacosKeychain,
            classes: vec![CredentialItemClass::GenericPassword],
            operations: vec![
                CredentialOperation::Read,
                CredentialOperation::Upsert,
                CredentialOperation::Delete,
            ],
            services: vec!["example-service".to_string()],
            service_prefixes: Vec::new(),
            accounts: vec!["alice".to_string()],
        }
    }

    fn request(
        operation: CredentialOperation,
        service: &str,
        account: Option<&str>,
    ) -> CredentialRequest {
        CredentialRequest {
            request_id: "test-request".to_string(),
            frontend: CredentialFrontend::SecurityCli,
            provider: CredentialProvider::MacosKeychain,
            operation,
            item_class: CredentialItemClass::GenericPassword,
            service: Some(service.to_string()),
            account: account.map(str::to_string),
            label: None,
            server: None,
            protocol: None,
            path: None,
            access_group: None,
            secret: None,
            return_secret: matches!(operation, CredentialOperation::Read),
            child_pid: 1,
            session_id: "test-session".to_string(),
        }
    }

    #[test]
    fn parses_find_generic_password() {
        let command = parse_security_cli_args(&strings(&[
            "find-generic-password",
            "-a",
            "alice",
            "-w",
            "-s",
            "example-service",
        ]))
        .expect("parse");

        assert_eq!(command.operation, CredentialOperation::Read);
        assert_eq!(command.item_class, CredentialItemClass::GenericPassword);
        assert_eq!(command.account.as_deref(), Some("alice"));
        assert_eq!(command.service.as_deref(), Some("example-service"));
        assert!(command.return_secret);
        assert!(command.secret.is_none());
    }

    #[test]
    fn parses_add_generic_password_hex_upsert() {
        let command = parse_security_cli_args(&strings(&[
            "add-generic-password",
            "-U",
            "-a",
            "alice",
            "-s",
            "example-service",
            "-X",
            "746f6b656e",
        ]))
        .expect("parse");

        assert_eq!(command.operation, CredentialOperation::Upsert);
        assert_eq!(command.account.as_deref(), Some("alice"));
        assert_eq!(command.service.as_deref(), Some("example-service"));
        assert_eq!(
            command.secret.as_ref().map(|secret| secret.as_slice()),
            Some("token".as_bytes())
        );
    }

    #[test]
    fn parses_delete_generic_password() {
        let command = parse_security_cli_args(&strings(&[
            "delete-generic-password",
            "-a",
            "alice",
            "-s",
            "example-service",
        ]))
        .expect("parse");

        assert_eq!(command.operation, CredentialOperation::Delete);
        assert_eq!(command.account.as_deref(), Some("alice"));
        assert_eq!(command.service.as_deref(), Some("example-service"));
    }

    #[test]
    fn rejects_unsupported_command() {
        let err = parse_security_cli_args(&strings(&["dump-keychain"]))
            .expect_err("unsupported command should fail");
        assert!(err.contains("unsupported security command"));
    }

    #[test]
    fn rejects_malformed_hex_secret() {
        let err = parse_security_cli_args(&strings(&[
            "add-generic-password",
            "-a",
            "alice",
            "-s",
            "example-service",
            "-X",
            "abc",
        ]))
        .expect_err("odd hex should fail");
        assert!(err.contains("even number"));
    }

    #[test]
    fn credential_policy_denies_without_grants() {
        let err = authorize_credential_request(
            &request(CredentialOperation::Read, "example-service", Some("alice")),
            &[],
        )
        .expect_err("empty grants should deny");

        match err {
            CredentialBrokerError::Denied(reason) => {
                assert!(reason.contains("no credential_access grant"));
            }
            CredentialBrokerError::Unsupported(_) | CredentialBrokerError::Error(_) => {
                panic!("expected policy denial")
            }
        }
    }

    #[test]
    fn credential_policy_allows_exact_service_and_account() {
        authorize_credential_request(
            &request(CredentialOperation::Read, "example-service", Some("alice")),
            &[grant()],
        )
        .expect("matching grant should allow");
    }

    #[test]
    fn credential_policy_allows_service_prefix_and_wildcard_account() {
        let mut grant = grant();
        grant.services.clear();
        grant.service_prefixes = vec!["example-".to_string()];
        grant.accounts = vec!["*".to_string()];

        authorize_credential_request(
            &request(CredentialOperation::Upsert, "example-service", Some("bob")),
            &[grant],
        )
        .expect("matching prefix grant should allow");
    }

    #[test]
    fn credential_policy_denies_wrong_service() {
        let err = authorize_credential_request(
            &request(CredentialOperation::Read, "other-service", Some("alice")),
            &[grant()],
        )
        .expect_err("wrong service should deny");

        assert!(matches!(err, CredentialBrokerError::Denied(_)));
    }

    #[test]
    fn credential_policy_denies_wrong_operation() {
        let err = authorize_credential_request(
            &request(
                CredentialOperation::Create,
                "example-service",
                Some("alice"),
            ),
            &[grant()],
        )
        .expect_err("wrong operation should deny");

        assert!(matches!(err, CredentialBrokerError::Denied(_)));
    }
}
