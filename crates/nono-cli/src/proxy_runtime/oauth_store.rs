use super::{
    CaptureCommandResolution, ProxyLaunchOptions, resolve_expanded_capture_command_with_path,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nono::{CapabilitySet, NonoError, Result};
use nono_proxy::capture::CredentialCaptureRequest;
use nono_proxy::config::{EndpointPolicyDecision, OAuthCaptureConfig, ProxyConfig, RouteConfig};
use nono_proxy::error::{ProxyError, Result as ProxyResult};
use nono_proxy::oauth_capture::{
    LoadedOAuthEndpoint, OAuthCapturedField, OAuthRefresh, OAuthTokenStoreBackend,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

// Match the existing provider reply cap. A put may hold an entire bounded
// OAuth response, and JSON escaping can expand its encoded representation.
const MAX_REPLY_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn configure(
    config: &mut ProxyConfig,
    proxy: &ProxyLaunchOptions,
    caps: &CapabilitySet,
) -> Result<()> {
    for provider in &config.oauth_capture {
        let Some(reference) = proxy
            .credential_providers
            .get(&provider.provider)
            .and_then(|def| def.store.as_deref())
        else {
            continue;
        };
        let name = crate::profile::credential_provider::oauth_store_name(reference)?;
        let entry = proxy.credential_capture.get(name).ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "unknown OAuth token store credential_capture.{name}"
            ))
        })?;
        let capture = crate::profile::credential_provider::validate_token_store_entry(name, entry)?;
        let Some(command) = capture.command.first() else {
            return Err(NonoError::ConfigParse(
                "OAuth provider command must not be empty".into(),
            ));
        };
        let command = crate::policy::expand_env_vars(command);
        let CaptureCommandResolution::Resolved(executable) = resolve_store_command(&command, caps)?
        else {
            return Err(NonoError::ConfigParse(format!(
                "OAuth token store credential_capture.{name} command is unavailable"
            )));
        };
        if nono::path_writable_by(&executable, caps) {
            return Err(NonoError::ConfigParse(format!(
                "OAuth token store credential_capture.{name} executable path is sandbox-writable"
            )));
        }
        let args: Vec<_> = capture
            .command
            .iter()
            .skip(1)
            .map(|arg| crate::policy::expand_env_vars(arg))
            .collect();
        let scope = store_scope(
            provider,
            &config.routes,
            proxy,
            name,
            &capture.config,
            (&command, &args),
        )?;

        config.oauth_capture_command_stores.insert(
            provider.provider.clone(),
            Arc::new(CommandStore {
                executable,
                args,
                provider: provider.provider.clone(),
                credential_name: name.to_owned(),
                config: capture.config.clone(),
                session_id: proxy.session_id.clone(),
                scope,
                timeout: Duration::from_secs(entry.timeout_secs.unwrap_or(5)),
                cache_ttl: Duration::from_secs(
                    entry.cache_ttl_secs.or(entry.ttl_secs).unwrap_or(900),
                ),
                home: std::env::var_os("HOME"),
            }),
        );
    }
    Ok(())
}

fn store_scope(
    provider: &OAuthCaptureConfig,
    routes: &[RouteConfig],
    proxy: &ProxyLaunchOptions,
    name: &str,
    provider_config: &serde_json::Value,
    command: (&str, &[String]),
) -> Result<String> {
    let mut routes: Vec<_> = routes
        .iter()
        .filter(|route| {
            let consumer = format!("proxy.{}", route.prefix);
            provider.admitted_consumers.contains(&consumer)
        })
        .collect();
    routes.sort_unstable_by(|left, right| left.prefix.cmp(&right.prefix));
    let approvals = if routes.iter().any(|route| {
        route.endpoint_policy.as_ref().is_some_and(|policy| {
            !policy.approve.is_empty() || policy.default.decision == EndpointPolicyDecision::Approve
        })
    }) {
        crate::approval_runtime::proxy_approval_config(
            proxy.command_policies.as_ref(),
            Some((
                &proxy.network_approval_backends,
                proxy
                    .network_approval_defaults
                    .as_ref()
                    .and_then(|defaults| defaults.backend.as_deref()),
            )),
        )
    } else {
        None
    };

    // Bind saved mappings to the configured helper invocation and effective route policy.
    // Use the expanded command name so the same bare name can resolve on different hosts.
    let mut provider = provider.clone();
    provider.admitted_consumers.sort_unstable();
    let mut provider_config = provider_config.clone();
    provider_config.sort_all_objects();
    let binding = (&provider, routes, name, provider_config, command);
    let encoded = match approvals {
        Some(approvals) => serde_json::to_vec(&(binding, approvals)),
        None => serde_json::to_vec(&binding),
    };
    let identity =
        Zeroizing::new(encoded.map_err(|_| {
            NonoError::ConfigParse("cannot identify OAuth token store scope".into())
        })?);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(identity.as_slice())))
}

fn resolve_store_command(command: &str, caps: &CapabilitySet) -> Result<CaptureCommandResolution> {
    let path = Path::new(command);
    if path.is_absolute() && nono::path_writable_by(path, caps) {
        return Err(NonoError::ConfigParse(
            "OAuth token store executable path is sandbox-writable".into(),
        ));
    }
    resolve_expanded_capture_command_with_path(command, std::env::var_os("PATH").as_deref(), caps)
}

struct CommandStore {
    executable: PathBuf,
    args: Vec<String>,
    provider: String,
    credential_name: String,
    config: serde_json::Value,
    session_id: String,
    scope: String,
    timeout: Duration,
    cache_ttl: Duration,
    home: Option<OsString>,
}

impl std::fmt::Debug for CommandStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandStore")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct OperationRequest<'a> {
    provider: &'a str,
    #[serde(flatten)]
    operation: Operation<'a>,
}

#[derive(Serialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
enum Operation<'a> {
    Put {
        fields: &'a [OAuthCapturedField<'a>],
    },
    Resolve {
        phantom: &'a str,
    },
    Refresh {
        phantom: &'a str,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "operation",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Reply {
    Put { phantoms: Vec<String> },
    Resolve { value: Option<Zeroizing<String>> },
    Refresh(OAuthRefresh),
}

impl OAuthTokenStoreBackend for CommandStore {
    fn credential_name(&self) -> &str {
        &self.credential_name
    }

    fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    fn put(
        &self,
        endpoint: &LoadedOAuthEndpoint,
        fields: &[OAuthCapturedField<'_>],
    ) -> ProxyResult<Vec<String>> {
        match self.run(Some(endpoint), None, Operation::Put { fields })? {
            Reply::Put { phantoms } => Ok(phantoms),
            _ => Err(failed()),
        }
    }

    fn resolve(&self, phantom: &str, consumer: &str) -> ProxyResult<Option<Zeroizing<String>>> {
        // Header substitution uses a synchronous resolver. Both CLI proxy
        // entry points use a multi-thread runtime so the other requests can
        // keep running while this helper waits for subprocess I/O.
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| failed())?;
        if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(failed());
        }
        let reply = tokio::task::block_in_place(|| {
            self.run(None, Some(consumer), Operation::Resolve { phantom })
        })?;
        match reply {
            Reply::Resolve { value } => Ok(value),
            _ => Err(failed()),
        }
    }

    fn refresh(&self, endpoint: &LoadedOAuthEndpoint, phantom: &str) -> ProxyResult<OAuthRefresh> {
        match self.run(Some(endpoint), None, Operation::Refresh { phantom })? {
            Reply::Refresh(reply) => Ok(reply),
            _ => Err(failed()),
        }
    }
}

impl CommandStore {
    // Put and refresh are called on the blocking pool. Resolve uses
    // block_in_place at the synchronous nonce resolver boundary.
    fn run(
        &self,
        endpoint: Option<&LoadedOAuthEndpoint>,
        consumer: Option<&str>,
        operation: Operation<'_>,
    ) -> ProxyResult<Reply> {
        let context = CredentialCaptureRequest {
            credential_name: self.credential_name.clone(),
            route_id: consumer
                .and_then(|id| id.strip_prefix("proxy."))
                .map_or_else(|| format!("oauth.{}", self.provider), str::to_owned),
            request_host: endpoint
                .map_or_else(String::new, |endpoint| endpoint.host_port().to_owned()),
            request_path: endpoint.map_or_else(String::new, |endpoint| endpoint.path().to_owned()),
            request_method: endpoint.map_or_else(String::new, |_| "POST".to_owned()),
            session_id: self.session_id.clone(),
            cache_scope: self.scope.clone(),
        };
        let interaction = serde_json::Map::new();
        let request = context.provider_request(
            &self.config,
            &interaction,
            Some(OperationRequest {
                provider: &self.provider,
                operation,
            }),
        );
        let request = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| failed())?);
        if request.len() > MAX_REQUEST_BYTES {
            return Err(failed());
        }

        let runtime = tokio::runtime::Handle::try_current().map_err(|_| failed())?;
        self.exchange(&runtime, self.spawn_helper()?, request)
    }

    fn spawn_helper(&self) -> ProxyResult<crate::owned_children::OwnedChild> {
        let mut command = Command::new(&self.executable);
        command
            .args(&self.args)
            .env_clear()
            // Helpers must use explicit paths for subprocesses. Unsetting
            // PATH can enable a default search, and an empty PATH can search
            // the working directory.
            .env("PATH", "/dev/null")
            .current_dir(self.executable.parent().ok_or_else(failed)?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(home) = &self.home {
            command.env("HOME", home);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        command.process_group(0);
        crate::owned_children::spawn(&mut command).map_err(|_| failed())
    }

    fn exchange(
        &self,
        runtime: &tokio::runtime::Handle,
        mut child: crate::owned_children::OwnedChild,
        request: Zeroizing<Vec<u8>>,
    ) -> ProxyResult<Reply> {
        let result = runtime.block_on(async {
            let mut input =
                tokio::process::ChildStdin::from_std(child.stdin.take().ok_or_else(failed)?)
                    .map_err(|_| failed())?;
            let mut output =
                tokio::process::ChildStdout::from_std(child.stdout.take().ok_or_else(failed)?)
                    .map_err(|_| failed())?
                    .take((MAX_REPLY_BYTES + 1) as u64);
            let mut reply = Zeroizing::new(Vec::new());
            let send = async move {
                input.write_all(&request).await.map_err(|_| failed())
                // Dropping stdin ends the frame.
            };
            let receive = async {
                output.read_to_end(&mut reply).await.map_err(|_| failed())?;
                if reply.len() > MAX_REPLY_BYTES {
                    return Err(failed());
                }
                Ok(())
            };
            let status = tokio::time::timeout(self.timeout, async {
                tokio::try_join!(send, receive)?;
                // Leave the leader unreaped while subprocesses may still be
                // holding the pipes open. Its PID then anchors the group ID
                // if cleanup is needed.
                loop {
                    if let Some(status) = child.try_wait().map_err(|_| failed())? {
                        return Ok::<_, ProxyError>(status);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| failed())??;
            Ok((status, reply))
        });
        match result {
            Ok((status, reply)) if status.success() => {
                serde_json::from_slice(&reply).map_err(|_| failed())
            }
            Ok(_) => Err(failed()),
            Err(err) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    use nix::sys::signal::{Signal, killpg};
                    use nix::unistd::Pid;

                    let _ = killpg(Pid::from_raw(child.id().cast_signed()), Signal::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                Err(err)
            }
        }
    }
}

fn failed() -> ProxyError {
    ProxyError::Config("OAuth token store command failed".into())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::command_policy::{ApprovalDefaultsConfig, CommandPoliciesConfig};
    use nono_proxy::config::{EndpointPolicyConfig, EndpointPolicyDefault};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn command_store_rejects_absolute_alias_in_writable_directory() {
        let dir = tempfile::tempdir().unwrap();
        let writable = dir.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        let alias = writable.join("store");
        std::os::unix::fs::symlink("/bin/sh", &alias).unwrap();
        let mut caps = CapabilitySet::default();
        caps.add_fs(nono::FsCapability::new_dir(&writable, nono::AccessMode::ReadWrite).unwrap());

        assert!(resolve_store_command(alias.to_str().unwrap(), &caps).is_err());
        assert!(matches!(
            resolve_store_command("/bin/sh", &caps).unwrap(),
            CaptureCommandResolution::Resolved(_)
        ));
    }

    #[test]
    fn scope_binds_helper_invocation_and_effective_approvals() {
        let provider = OAuthCaptureConfig {
            provider: "example".into(),
            token_endpoints: Vec::new(),
            admitted_consumers: vec!["proxy.api".into()],
        };
        let routes = [RouteConfig {
            prefix: "api".into(),
            endpoint_policy: Some(EndpointPolicyConfig {
                default: EndpointPolicyDefault {
                    decision: EndpointPolicyDecision::Approve,
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }];
        let scope_for_command = |proxy: &ProxyLaunchOptions, command| {
            store_scope(
                &provider,
                &routes,
                proxy,
                "store",
                &serde_json::Value::Null,
                command,
            )
            .unwrap()
        };
        let args = ["--vault".to_owned(), "work".to_owned()];
        let scope = |proxy: &ProxyLaunchOptions| scope_for_command(proxy, ("helper", &args));
        let mut proxy = ProxyLaunchOptions {
            network_approval_backends: serde_json::from_value(serde_json::json!({
                "review": {"type": "terminal"},
                "other": {"type": "terminal"}
            }))
            .unwrap(),
            network_approval_defaults: Some(ApprovalDefaultsConfig {
                backend: Some("review".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let initial = scope(&proxy);
        let alternate_args = ["--vault".to_owned(), "personal".to_owned()];
        assert_ne!(
            initial,
            scope_for_command(&proxy, ("helper", &alternate_args))
        );
        assert_ne!(initial, scope_for_command(&proxy, ("other-helper", &args)));
        proxy.network_approval_defaults.as_mut().unwrap().backend = Some("other".into());
        let new_default = scope(&proxy);
        assert_ne!(initial, new_default);
        proxy
            .network_approval_backends
            .get_mut("other")
            .unwrap()
            .timeout_secs = Some(10);
        assert_ne!(new_default, scope(&proxy));

        proxy.command_policies = Some(CommandPoliciesConfig {
            approval_backends: proxy.network_approval_backends.clone(),
            approval_defaults: ApprovalDefaultsConfig {
                backend: Some("review".into()),
                ..Default::default()
            },
            ..Default::default()
        });
        let command_scope = scope(&proxy);
        proxy.network_approval_backends.clear();
        assert_eq!(command_scope, scope(&proxy));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn command_timeout_stops_descendant_after_helper_exits() {
        use std::os::fd::AsFd;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("store");
        std::fs::write(
            &executable,
            r#"#!/bin/sh
/bin/sleep 10 &
: > started
"#,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

        let store = CommandStore {
            executable,
            args: Vec::new(),
            provider: "example".into(),
            credential_name: "store".into(),
            config: serde_json::Value::Null,
            session_id: "test".into(),
            scope: "scope".into(),
            timeout: Duration::from_millis(200),
            cache_ttl: Duration::ZERO,
            home: None,
        };
        let child = store.spawn_helper().unwrap();
        let pipe = child
            .stdout
            .as_ref()
            .unwrap()
            .as_fd()
            .try_clone_to_owned()
            .unwrap();
        let started = dir.path().join("started");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !started.is_file() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let runtime = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            store.exchange(&runtime, child, Zeroizing::new(Vec::new()))
        })
        .await
        .unwrap();
        assert!(result.is_err());

        // The descendant inherits stdout. EOF confirms that cleanup closed its
        // pipe, even though the helper leader exited before the timeout.
        let mut output = tokio::net::unix::pipe::Receiver::from_owned_fd(pipe).unwrap();
        let read = tokio::time::timeout(Duration::from_secs(1), output.read_u8()).await;
        assert!(matches!(read, Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn command_uses_existing_provider_envelope_and_validates_operation() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("store");
        std::fs::write(
            &executable,
            r#"#!/bin/sh
[ "$PATH" = /dev/null ] || exit 1
request=$(/bin/cat)
case "$request" in
  *'"protocol":"nono.credential-provider.v1"'*'"credential_name":"store"'*'"cache_scope":"scope"'*'"provider":"example"'*'"operation":"put"'*'"value":"real-token"'*)
    printf '{"operation":"put","payload":{"phantoms":["phantom"]}}\n' ;;
  *'"operation":"resolve"'*'"phantom":"legacy"'*)
    printf '{"material":{"type":"secret","value":"old-helper"}}\n' ;;
  *'"operation":"resolve"'*)
    printf '{"operation":"resolve","payload":{"value":"resolved-token"}}\n' ;;
  *'"operation":"refresh"'*)
    printf '{"operation":"refresh","payload":{"phantoms":{"access_token":"phantom"},"expires_in":42}}\n' ;;
  *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = CommandStore {
            executable,
            args: Vec::new(),
            provider: "example".into(),
            credential_name: "store".into(),
            config: serde_json::json!({"target": "vault"}),
            session_id: "test".into(),
            scope: "scope".into(),
            timeout: Duration::from_secs(5),
            cache_ttl: Duration::ZERO,
            home: None,
        };

        assert_eq!(
            store
                .resolve("phantom", "proxy.api")
                .unwrap()
                .unwrap()
                .as_str(),
            "resolved-token"
        );
        assert!(store.resolve("legacy", "proxy.api").is_err());
        tokio::task::spawn_blocking(move || {
            let reply = store
                .run(
                    None,
                    None,
                    Operation::Put {
                        fields: &[OAuthCapturedField {
                            path: "access_token",
                            value: "real-token",
                        }],
                    },
                )
                .unwrap();
            assert!(matches!(reply, Reply::Put { phantoms } if phantoms == ["phantom"]));
            let reply = store
                .run(None, None, Operation::Refresh { phantom: "phantom" })
                .unwrap();
            assert!(matches!(reply, Reply::Refresh(reply) if reply.expires_in == Some(42)));
        })
        .await
        .unwrap();
    }
}
