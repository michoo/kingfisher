use std::path::Path;

use anyhow::{Context, Result};
use gcloud_storage::{
    client::{Client, ClientConfig},
    http::objects::{
        download::Range,
        get::GetObjectRequest,
        list::{ListObjectsRequest, ListObjectsResponse},
    },
};
use tracing::debug;

/// Visit every object in the given GCS bucket, optionally filtered by prefix.
///
/// Authentication is attempted via Application Default Credentials. When that
/// fails and no explicit service account path was provided, the client falls
/// back to anonymous access so public buckets can still be scanned.
pub async fn visit_bucket_objects<F>(
    bucket: &str,
    prefix: Option<&str>,
    service_account_path: Option<&Path>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    if let Some(path) = service_account_path {
        std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", path);
    }

    let config = match ClientConfig::default().with_auth().await {
        Ok(config) => config,
        Err(err) => {
            if service_account_path.is_some()
                || std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok()
            {
                return Err(err)
                    .context("Failed to authenticate with GCS using provided credentials");
            }
            debug!("Falling back to anonymous GCS access: {err}");
            ClientConfig::default().anonymous()
        }
    };

    let client = Client::new(config);
    let mut page_token: Option<String> = None;

    loop {
        let request = ListObjectsRequest {
            bucket: bucket.to_string(),
            prefix: prefix.map(|p| p.to_string()),
            page_token: page_token.clone(),
            ..ListObjectsRequest::default()
        };

        let mut response: ListObjectsResponse = client
            .list_objects(&request)
            .await
            .with_context(|| format!("Failed to list objects in bucket {bucket}"))?;

        if let Some(items) = response.items.take() {
            for object in items.into_iter().filter(|o| !o.name.is_empty()) {
                let data = client
                    .download_object(
                        &GetObjectRequest {
                            bucket: bucket.to_string(),
                            object: object.name.clone(),
                            ..GetObjectRequest::default()
                        },
                        &Range::default(),
                    )
                    .await
                    .with_context(|| format!("Failed to fetch object {}", object.name))?;

                visitor(object.name, data)?;
            }
        }

        match response.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token),
            _ => break,
        }
    }

    Ok(())
}
