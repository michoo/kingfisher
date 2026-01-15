use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use quick_xml::{events::Event, Reader};
use reqwest::{header::HeaderValue, Client};
use serde_json::Value as JsonValue;
use sha2::Sha256;

use crate::cli::commands::access_map::AccessMapArgs;

use super::{
    build_recommendations, AccessMapResult, AccessSummary, PermissionSummary, ResourceExposure,
    RoleBinding, Severity,
};

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args
        .credential_path
        .as_deref()
        .ok_or_else(|| anyhow!("Azure access-map requires a credential JSON path"))?;
    let data = std::fs::read_to_string(path).context("Failed to read credential file")?;
    map_access_from_json(&data).await
}

pub async fn map_access_from_json(data: &str) -> Result<AccessMapResult> {
    map_access_from_json_with_hints(data, None).await
}

pub async fn map_access_from_json_with_hints(
    data: &str,
    containers_hint: Option<&[String]>,
) -> Result<AccessMapResult> {
    let (storage_account, storage_key) = parse_storage_credentials(data)?;

    let mut risk_notes =
        vec!["Storage account keys grant full control over the storage account".to_string()];

    let containers = match containers_hint {
        Some(list) if !list.is_empty() => list.to_vec(),
        _ => match list_containers(&storage_account, &storage_key).await {
            Ok(list) => list,
            Err(err) => {
                risk_notes.push(format!("Container enumeration failed: {err}"));
                Vec::new()
            }
        },
    };

    let severity = Severity::Critical;
    let permissions =
        PermissionSummary { admin: vec!["storage:*".into()], ..PermissionSummary::default() };

    let roles = vec![RoleBinding {
        name: "storage_account_key".into(),
        source: "shared_key".into(),
        permissions: vec!["storage:*".into()],
    }];

    let mut resources = Vec::new();
    resources.push(ResourceExposure {
        resource_type: "storage_account".into(),
        name: storage_account.clone(),
        permissions: vec!["storage:*".into()],
        risk: "critical".into(),
        reason: "Storage account accessible with shared key".into(),
    });

    if containers.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "storage_container".into(),
            name: String::new(),
            permissions: vec!["storage:*".into()],
            risk: "critical".into(),
            reason: "Container list unavailable; storage account key still grants full access"
                .into(),
        });
    } else {
        for container in containers {
            resources.push(ResourceExposure {
                resource_type: "storage_container".into(),
                name: container,
                permissions: vec!["storage:*".into()],
                risk: "critical".into(),
                reason: "Container accessible with shared key".into(),
            });
        }
    }

    let identity = AccessSummary {
        id: storage_account,
        access_type: "storage_account_key".into(),
        project: None,
        tenant: None,
        account_id: None,
    };

    Ok(AccessMapResult {
        cloud: "azure".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: None,
        provider_metadata: None,
        fingerprint: None,
    })
}

fn parse_storage_credentials(data: &str) -> Result<(String, String)> {
    let token: JsonValue = serde_json::from_str(data)?;
    let storage_account = token["storage_account"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing storage_account in credential JSON"))?
        .to_string();
    let storage_key = token["storage_key"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing storage_key in credential JSON"))?
        .to_string();
    Ok((storage_account, storage_key))
}

async fn list_containers(storage_account: &str, storage_key: &str) -> Result<Vec<String>> {
    let mut containers = std::collections::BTreeSet::new();
    let mut marker: Option<String> = None;

    loop {
        let now_rfc = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mut url = reqwest::Url::parse(&format!(
            "https://{account}.blob.core.windows.net/",
            account = storage_account
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("comp", "list");
            if let Some(marker_value) = marker.as_deref() {
                query.append_pair("marker", marker_value);
            }
        }

        let canon_headers = format!("x-ms-date:{now_rfc}\nx-ms-version:2023-11-03\n");
        let mut canon_resource = format!("/{account}/\ncomp:list", account = storage_account);
        if let Some(marker_value) = marker.as_deref() {
            canon_resource.push_str(&format!("\nmarker:{marker_value}"));
        }
        let string_to_sign = format!(
            "GET\n\n\n\n\n\n\n\n\n\n\n\n{headers}{resource}",
            headers = canon_headers,
            resource = canon_resource
        );

        let key_bytes = b64.decode(storage_key)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
            .map_err(|_| anyhow!("invalid key length"))?;
        mac.update(string_to_sign.as_bytes());
        let signature = b64.encode(mac.finalize().into_bytes());

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ms-date", HeaderValue::from_str(&now_rfc)?);
        headers.insert("x-ms-version", HeaderValue::from_static("2023-11-03"));
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!(
                "SharedKey {account}:{sig}",
                account = storage_account,
                sig = signature
            ))?,
        );

        let client = Client::builder().build()?;
        let resp = client.get(url).headers(headers).send().await?;
        let status = resp.status();
        let body_txt = resp.text().await?;

        if !status.is_success() {
            return Err(anyhow!(
                "Azure Storage list containers failed (HTTP {}): {}",
                status,
                body_txt
            ));
        }

        let mut reader = Reader::from_str(&body_txt);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) if e.name().as_ref().eq_ignore_ascii_case(b"name") => {
                    let text = reader.read_text(e.name())?;
                    let name = text.into_owned();
                    if !name.is_empty() {
                        containers.insert(name);
                    }
                }
                Ok(Event::Start(e)) if e.name().as_ref().eq_ignore_ascii_case(b"nextmarker") => {
                    let text = reader.read_text(e.name())?;
                    let value = text.into_owned();
                    if !value.trim().is_empty() {
                        next_marker = Some(value);
                    }
                }
                Err(e) => return Err(anyhow!("XML parse error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        if next_marker.is_none() {
            break;
        }
        marker = next_marker;
    }

    Ok(containers.into_iter().collect())
}
