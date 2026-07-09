use crate::config::{
    OAuthTokenEndpointConfig, OAuthTokenRequestBodyFormat, OAuthTokenResponseFieldKind,
};
use crate::error::{ProxyError, Result};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct LoadedOAuthEndpoint {
    pub(super) provider: String,
    pub(super) host_port: String,
    pub(super) path: String,
    pub(super) response_fields: Vec<ResponseField>,
    pub(super) request_body: OAuthTokenRequestBodyFormat,
    pub(super) request_nonce_fields: Vec<String>,
    pub(super) admitted_consumers: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseFieldFormat {
    Opaque,
    Jwt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResponseField {
    pub(super) path: String,
    pub(super) format: ResponseFieldFormat,
}

pub(super) fn load_endpoint(
    provider: &str,
    endpoint: &OAuthTokenEndpointConfig,
    admitted_consumers: HashSet<String>,
) -> Result<LoadedOAuthEndpoint> {
    let url = url::Url::parse(&endpoint.host)
        .map_err(|err| ProxyError::Config(format!("invalid OAuth token host: {err}")))?;
    let scheme = url.scheme();
    if scheme != "https" {
        return Err(ProxyError::Config(
            "OAuth token host must use https".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ProxyError::Config("OAuth token host missing hostname".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ProxyError::Config("OAuth token host missing port".to_string()))?;
    Ok(LoadedOAuthEndpoint {
        provider: provider.to_string(),
        host_port: format!("{}:{}", host.to_lowercase(), port),
        path: endpoint.path.clone(),
        response_fields: endpoint_response_fields(endpoint),
        request_body: endpoint.request_body,
        request_nonce_fields: endpoint.request_nonce_fields.clone(),
        admitted_consumers,
    })
}

fn endpoint_response_fields(endpoint: &OAuthTokenEndpointConfig) -> Vec<ResponseField> {
    let mut fields = Vec::with_capacity(endpoint.response_fields.len());
    for field in &endpoint.response_fields {
        push_response_field(
            &mut fields,
            field.path.clone(),
            match field.kind {
                OAuthTokenResponseFieldKind::Opaque => ResponseFieldFormat::Opaque,
                OAuthTokenResponseFieldKind::Jwt => ResponseFieldFormat::Jwt,
            },
        );
    }
    fields
}

fn push_response_field(fields: &mut Vec<ResponseField>, path: String, format: ResponseFieldFormat) {
    if fields.iter().any(|existing| existing.path == path) {
        return;
    }
    fields.push(ResponseField { path, format });
}

pub(super) fn provider_consumer(provider: &str) -> String {
    format!("oauth.{provider}")
}
