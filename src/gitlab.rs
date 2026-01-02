use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use gitlab::{
    api::{
        groups::projects::GroupProjects,
        paged,
        users::{UserProjects, Users},
        Pagination, Query,
    },
    Gitlab, GitlabBuilder,
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use tokio::task;
use tracing::{info, warn};
use url::{form_urlencoded, Url};

use crate::{findings_store, git_url::GitUrl};
use std::str::FromStr;

#[derive(Deserialize)]
struct SimpleUser {
    id: u64,
}

#[derive(Deserialize)]
struct SimpleProject {
    http_url_to_repo: String,
}

#[derive(Deserialize)]
struct SimpleGroup {
    id: u64,
}

#[derive(Deserialize)]
struct GitLabProjectId {
    id: u64,
}

#[derive(Deserialize)]
struct GitLabContributor {
    name: String,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GitLabUser {
    id: u64,
    _username: String,
    name: String,
    email: Option<String>,
}

/// Repository filter types for GitLab
#[derive(Debug, Clone)]
pub enum RepoType {
    All,
    Owner,
    Member,
}

/// A struct to hold GitLab repository query specifications
#[derive(Debug, Clone)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub group: Vec<String>,
    pub all_groups: bool,
    pub include_subgroups: bool,
    pub repo_filter: RepoType,
    pub exclude_repos: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.group.is_empty() && !self.all_groups
    }
}

fn normalize_project_path(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let segments: Vec<&str> = without_git.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return None;
    }
    Some(segments.join("/").to_lowercase())
}

fn parse_project_path_from_url(repo_url: &str) -> Option<String> {
    let url = Url::parse(repo_url).ok()?;
    normalize_project_path(url.path())
}

fn parse_project_path(raw: &str) -> Option<String> {
    normalize_project_path(raw)
}

fn parse_excluded_project(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(name) = parse_project_path_from_url(trimmed) {
        return Some(name);
    }

    if let Some(idx) = trimmed.rfind(':') {
        if let Some(name) = parse_project_path(&trimmed[idx + 1..]) {
            return Some(name);
        }
    }

    parse_project_path(trimmed)
}

struct ExcludeMatcher {
    exact: HashSet<String>,
    globs: Option<GlobSet>,
}

impl ExcludeMatcher {
    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.globs.is_none()
    }

    fn matches(&self, name: &str) -> bool {
        if self.exact.contains(name) {
            return true;
        }
        if let Some(globs) = &self.globs {
            return globs.is_match(name);
        }
        false
    }
}

fn looks_like_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

fn build_exclude_matcher(exclude_repos: &[String]) -> ExcludeMatcher {
    let mut exact = HashSet::new();
    let mut glob_builder = GlobSetBuilder::new();
    let mut has_glob = false;

    for raw in exclude_repos {
        match parse_excluded_project(raw) {
            Some(name) => {
                if looks_like_glob(&name) {
                    match Glob::new(&name) {
                        Ok(glob) => {
                            glob_builder.add(glob);
                            has_glob = true;
                        }
                        Err(err) => {
                            warn!("Ignoring invalid GitLab exclusion pattern '{raw}': {err}");
                            exact.insert(name);
                        }
                    }
                } else {
                    exact.insert(name);
                }
            }
            None => {
                warn!("Ignoring invalid GitLab exclusion '{raw}' (expected group/project)");
            }
        }
    }

    let globs = if has_glob {
        match glob_builder.build() {
            Ok(set) => Some(set),
            Err(err) => {
                warn!("Failed to build GitLab exclusion patterns: {err}");
                None
            }
        }
    } else {
        None
    };

    ExcludeMatcher { exact, globs }
}

fn should_exclude_repo(clone_url: &str, excludes: &ExcludeMatcher) -> bool {
    if excludes.is_empty() {
        return false;
    }
    if let Some(name) = parse_project_path_from_url(clone_url) {
        return excludes.matches(&name);
    }
    false
}

fn create_gitlab_client(gitlab_url: &Url, ignore_certs: bool) -> Result<Gitlab> {
    let host = gitlab_url.host_str().context("GitLab URL must contain a host")?;

    if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
        return if ignore_certs {
            Gitlab::new_insecure(host, token).map_err(Into::into)
        } else {
            Gitlab::new(host, token).map_err(Into::into)
        };
    }

    // public-only client no PRIVATE-TOKEN header
    let mut builder = GitlabBuilder::new_unauthenticated(host);
    if ignore_certs {
        builder.insecure();
    }
    Ok(builder.build()?)
}

fn normalize_api_base(api_url: &Url) -> Url {
    let mut base = api_url.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base
}

pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    gitlab_url: Url,
    ignore_certs: bool,
    progress: Option<ProgressBar>,
) -> Result<Vec<String>> {
    let specifiers = repo_specifiers.clone();
    let repo_urls = task::spawn_blocking(move || {
        let progress_ref = progress.as_ref();
        enumerate_repo_urls_blocking(&specifiers, gitlab_url, ignore_certs, progress_ref)
    })
    .await??;

    Ok(repo_urls)
}

pub async fn enumerate_contributor_repo_urls(
    repo_url: &GitUrl,
    gitlab_url: &Url,
    ignore_certs: bool,
    exclude_repos: &[String],
    repo_clone_limit: Option<usize>,
    progress_enabled: bool,
) -> Result<Vec<String>> {
    let (_, path) = parse_repo(repo_url).context("invalid GitLab repo URL")?;
    let encoded = form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>();
    let exclude_set = build_exclude_matcher(exclude_repos);
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;
    let token = env::var("KF_GITLAB_TOKEN").ok().filter(|t| !t.is_empty());
    let api_base = normalize_api_base(gitlab_url);

    let project_url = api_base
        .join(&format!("api/v4/projects/{encoded}"))
        .context("Failed to build GitLab project URL")?;
    let mut project_req = client.get(project_url);
    if let Some(token) = token.as_ref() {
        project_req = project_req.header("PRIVATE-TOKEN", token);
    }
    let project_resp = project_req.send().await?;
    if !project_resp.status().is_success() {
        warn_on_rate_limit("GitLab", project_resp.status(), "fetching project metadata");
        return Ok(Vec::new());
    }
    let project: GitLabProjectId = project_resp.json().await?;
    let project_id = project.id;

    let mut contributors = Vec::new();
    let mut page = 1;
    loop {
        let mut url = api_base
            .join(&format!("api/v4/projects/{project_id}/repository/contributors"))
            .context("Failed to build GitLab contributors URL")?;
        url.query_pairs_mut().append_pair("per_page", "100").append_pair("page", &page.to_string());
        let mut req = client.get(url);
        if let Some(token) = token.as_ref() {
            req = req.header("PRIVATE-TOKEN", token);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            warn_on_rate_limit("GitLab", resp.status(), "listing contributors");
            break;
        }
        let page_contributors: Vec<GitLabContributor> = resp.json().await?;
        if page_contributors.is_empty() {
            break;
        }
        contributors.extend(page_contributors);
        page += 1;
    }

    let mut seen_users = HashSet::new();
    let mut users = Vec::new();
    for contributor in contributors {
        let query = contributor.email.as_deref().unwrap_or(&contributor.name);
        let mut url = api_base.join("api/v4/users").context("Failed to build GitLab users URL")?;
        url.query_pairs_mut().append_pair("search", query);
        let mut req = client.get(url);
        if let Some(token) = token.as_ref() {
            req = req.header("PRIVATE-TOKEN", token);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            warn_on_rate_limit("GitLab", resp.status(), "searching for contributor users");
            continue;
        }
        let users_resp: Vec<GitLabUser> = resp.json().await?;
        let matching = users_resp.into_iter().find(|user| {
            contributor
                .email
                .as_ref()
                .and_then(|email| user.email.as_ref().map(|u| (email, u)))
                .map(|(email, user_email)| email.eq_ignore_ascii_case(user_email))
                .unwrap_or_else(|| user.name.eq_ignore_ascii_case(&contributor.name))
        });
        let Some(user) = matching else {
            continue;
        };
        if !seen_users.insert(user.id) {
            continue;
        }
        users.push(user);
    }

    let (per_user_limit, total_limit) =
        determine_contributor_repo_limits(repo_clone_limit, users.len(), "GitLab");
    let progress = build_contributor_progress_bar(
        progress_enabled,
        users.len() as u64,
        "Enumerating GitLab contributor repositories...",
    );

    let mut repo_urls = Vec::new();
    let mut total_repo_count = 0usize;
    for user in users {
        if let Some(total_limit) = total_limit {
            if total_repo_count >= total_limit {
                break;
            }
        }
        let mut user_repo_count = 0usize;
        page = 1;
        loop {
            if let Some(per_user_limit) = per_user_limit {
                if user_repo_count >= per_user_limit {
                    break;
                }
            }
            if let Some(total_limit) = total_limit {
                if total_repo_count >= total_limit {
                    break;
                }
            }
            let mut url = api_base
                .join(&format!("api/v4/users/{}/projects", user.id))
                .context("Failed to build GitLab user projects URL")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string())
                .append_pair("order_by", "updated_at")
                .append_pair("sort", "desc");
            let mut req = client.get(url);
            if let Some(token) = token.as_ref() {
                req = req.header("PRIVATE-TOKEN", token);
            }
            let resp = req.send().await?;
            if !resp.status().is_success() {
                warn_on_rate_limit("GitLab", resp.status(), "listing user projects");
                break;
            }
            let projects: Vec<SimpleProject> = resp.json().await?;
            if projects.is_empty() {
                break;
            }
            for proj in projects {
                if let Some(per_user_limit) = per_user_limit {
                    if user_repo_count >= per_user_limit {
                        break;
                    }
                }
                if let Some(total_limit) = total_limit {
                    if total_repo_count >= total_limit {
                        break;
                    }
                }
                if should_exclude_repo(&proj.http_url_to_repo, &exclude_set) {
                    continue;
                }
                repo_urls.push(proj.http_url_to_repo);
                user_repo_count += 1;
                total_repo_count += 1;
            }
            page += 1;
        }
        progress.inc(1);
    }

    repo_urls.sort();
    repo_urls.dedup();
    progress.finish_and_clear();
    Ok(repo_urls)
}

fn warn_on_rate_limit(service: &str, status: StatusCode, action: &str) {
    if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
        warn!("{service} API rate limit or access restriction while {action}: HTTP {status}");
    }
}

fn determine_contributor_repo_limits(
    repo_clone_limit: Option<usize>,
    user_count: usize,
    service: &str,
) -> (Option<usize>, Option<usize>) {
    let Some(limit) = repo_clone_limit else {
        return (None, None);
    };
    if user_count == 0 {
        return (Some(0), Some(limit));
    }
    if user_count > limit {
        let per_user_limit = std::cmp::max(1, limit / 100);
        info!(
            "Found {user_count} {service} contributors which exceeds repo-clone-limit {limit}. \
Consider increasing repo-clone-limit; sampling {per_user_limit} repos per user until the limit is reached."
        );
        return (Some(per_user_limit), Some(limit));
    }
    let per_user_limit = std::cmp::max(1, limit / user_count);
    (Some(per_user_limit), Some(limit))
}

fn build_contributor_progress_bar(
    progress_enabled: bool,
    length: u64,
    message: &str,
) -> ProgressBar {
    if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new(length).with_style(style).with_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    }
}

fn enumerate_repo_urls_blocking(
    repo_specifiers: &RepoSpecifiers,
    gitlab_url: Url,
    ignore_certs: bool,
    progress: Option<&ProgressBar>,
) -> Result<Vec<String>> {
    let client = create_gitlab_client(&gitlab_url, ignore_certs)?;
    let mut repo_urls = Vec::new();
    let exclude_set = build_exclude_matcher(&repo_specifiers.exclude_repos);

    // 1) Process each GitLab username
    for username in &repo_specifiers.user {
        // a) Look up the user by username, deserializing only `id`
        let users_ep = Users::builder().username(username).build()?;
        let hits: Vec<SimpleUser> = users_ep.query(&client)?;
        let user =
            hits.into_iter().next().context(format!("GitLab user `{}` not found", username))?;
        let user_id = user.id;

        // b) List that user's projects applying the requested filter
        let mut builder = UserProjects::builder();
        builder.user(user_id);

        match repo_specifiers.repo_filter {
            RepoType::Owner => {
                builder.owned(true);
            }
            RepoType::Member => {
                builder.membership(true);
            }
            RepoType::All => {
                // default: list all visible repositories
            }
        }

        let projects_ep = builder.build()?;
        let projects: Vec<SimpleProject> = paged(projects_ep, Pagination::All).query(&client)?;
        for proj in projects {
            if should_exclude_repo(&proj.http_url_to_repo, &exclude_set) {
                continue;
            }
            repo_urls.push(proj.http_url_to_repo);
        }

        if let Some(pb) = progress {
            pb.inc(1);
        }
    }

    // all groups
    let groups: Vec<SimpleGroup> = if repo_specifiers.all_groups {
        let groups_ep = gitlab::api::groups::Groups::builder().all_available(true).build()?;
        paged(groups_ep, Pagination::All).query(&client.clone())?
    } else {
        let mut found: Vec<SimpleGroup> = Vec::new();
        for grp in &repo_specifiers.group {
            let ep = gitlab::api::groups::Group::builder().group(grp).build()?;
            let group: SimpleGroup = ep.query(&client.clone())?;
            found.push(group);
        }
        found
    };

    for group in groups {
        let mut gp_builder = GroupProjects::builder();
        gp_builder.group(group.id);
        if matches!(repo_specifiers.repo_filter, RepoType::Owner) {
            gp_builder.owned(true);
        }
        if repo_specifiers.include_subgroups {
            gp_builder.include_subgroups(true);
        }

        let gp_ep = gp_builder.build()?;
        let projects: Vec<SimpleProject> = paged(gp_ep, Pagination::All).query(&client)?;
        for proj in projects {
            if should_exclude_repo(&proj.http_url_to_repo, &exclude_set) {
                continue;
            }
            repo_urls.push(proj.http_url_to_repo);
        }
        if let Some(pb) = progress {
            pb.inc(1);
        }
    }

    // 3) Sort & dedupe
    repo_urls.sort_unstable();
    repo_urls.dedup();

    Ok(repo_urls)
}

pub async fn list_repositories(
    api_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    groups: &[String],
    all_groups: bool,
    include_subgroups: bool,
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        group: groups.to_vec(),
        all_groups,
        include_subgroups,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
    };

    // Create a progress bar for displaying status
    let progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let repo_urls =
        enumerate_repo_urls(&repo_specifiers, api_url, ignore_certs, Some(progress.clone()))
            .await?;

    // Print repositories
    for url in repo_urls {
        println!("{}", url);
    }

    Ok(())
}

fn parse_repo(repo_url: &GitUrl) -> Option<(String, String)> {
    let url = Url::parse(repo_url.as_str()).ok()?;
    let host = url.host_str()?.to_string();
    let mut path = url.path().trim_start_matches('/').to_string();
    if let Some(stripped) = path.strip_suffix(".git") {
        path = stripped.to_string();
    }
    Some((host, path))
}

pub fn wiki_url(repo_url: &GitUrl) -> Option<GitUrl> {
    let (host, path) = parse_repo(repo_url)?;
    let wiki = format!("https://{host}/{path}.wiki.git");
    GitUrl::from_str(&wiki).ok()
}

pub async fn fetch_repo_items(
    repo_url: &GitUrl,
    ignore_certs: bool,
    output_root: &Path,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let (host, path) = parse_repo(repo_url).context("invalid GitLab repo URL")?;
    let encoded = form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>();
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;

    let mut dirs = Vec::new();

    // Issues
    let issues_dir = output_root.join("gitlab_issues").join(path.replace('/', "_"));
    fs::create_dir_all(&issues_dir)?;
    let mut page = 1;
    loop {
        let url = format!(
            "https://{host}/api/v4/projects/{encoded}/issues?scope=all&state=all&per_page=100&page={page}"
        );
        let mut req = client.get(&url);
        if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
            if !token.is_empty() {
                req = req.header("PRIVATE-TOKEN", token);
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            break;
        }
        let issues: Vec<Value> = resp.json().await?;
        if issues.is_empty() {
            break;
        }
        for issue in issues {
            let number = issue.get("iid").and_then(|v| v.as_u64()).unwrap_or(0);
            let title = issue.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = issue.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let content = format!("# {title}\n\n{body}");
            let file_path = issues_dir.join(format!("issue_{number}.md"));
            fs::write(&file_path, content)?;
            let url = format!("https://{host}/{path}/-/issues/{number}");
            let mut ds = datastore.lock().unwrap();
            ds.register_repo_link(file_path, url);
        }
        page += 1;
    }
    if issues_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(issues_dir);
    }

    // Snippets
    let snippets_dir = output_root.join("gitlab_snippets").join(path.replace('/', "_"));
    fs::create_dir_all(&snippets_dir)?;
    page = 1;
    loop {
        let url =
            format!("https://{host}/api/v4/projects/{encoded}/snippets?per_page=100&page={page}");
        let mut req = client.get(&url);
        if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
            if !token.is_empty() {
                req = req.header("PRIVATE-TOKEN", token);
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            break;
        }
        let snippets: Vec<Value> = resp.json().await?;
        if snippets.is_empty() {
            break;
        }
        for snip in snippets {
            if let Some(id) = snip.get("id").and_then(|v| v.as_u64()) {
                let raw_url = format!("https://{host}/api/v4/projects/{encoded}/snippets/{id}/raw");
                let mut req_s = client.get(&raw_url);
                if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
                    if !token.is_empty() {
                        req_s = req_s.header("PRIVATE-TOKEN", token);
                    }
                }
                let raw = req_s.send().await?.text().await?;
                let file_path = snippets_dir.join(format!("snippet_{id}"));
                fs::write(&file_path, raw)?;
                let url = format!("https://{host}/{path}/-/snippets/{id}");
                let mut ds = datastore.lock().unwrap();
                ds.register_repo_link(file_path, url);
            }
        }
        page += 1;
    }
    if snippets_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(snippets_dir);
    }

    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_excluded_project_variants() {
        assert_eq!(parse_excluded_project("Group/Project").as_deref(), Some("group/project"));
        assert_eq!(parse_excluded_project("group/project.git").as_deref(), Some("group/project"));
        assert_eq!(
            parse_excluded_project("https://gitlab.com/Group/Project.git").as_deref(),
            Some("group/project")
        );
        assert_eq!(
            parse_excluded_project("git@gitlab.com:Group/Sub/Project.git").as_deref(),
            Some("group/sub/project")
        );
        assert_eq!(
            parse_excluded_project("ssh://git@gitlab.example.com/Group/Sub/Project.git").as_deref(),
            Some("group/sub/project")
        );
        assert_eq!(
            parse_excluded_project("  group/sub/project  ").as_deref(),
            Some("group/sub/project")
        );
        assert_eq!(parse_excluded_project("not-a-project"), None);
    }

    #[test]
    fn should_exclude_repo_matches_normalized_paths() {
        let excludes = build_exclude_matcher(&vec!["Group/Sub/Project".to_string()]);
        assert!(should_exclude_repo("https://gitlab.com/group/sub/project.git", &excludes));
        assert!(!should_exclude_repo("https://gitlab.com/group/other/project.git", &excludes));
    }

    #[test]
    fn should_exclude_repo_matches_ssh_urls() {
        let excludes = build_exclude_matcher(&vec!["group/sub/project".to_string()]);
        assert!(should_exclude_repo(
            "ssh://git@gitlab.example.com/group/sub/project.git",
            &excludes
        ));
    }

    #[test]
    fn should_exclude_repo_matches_globs() {
        let excludes = build_exclude_matcher(&vec!["group/**/archive-*".to_string()]);
        assert!(should_exclude_repo("https://gitlab.com/group/sub/archive-2023.git", &excludes));
        assert!(!should_exclude_repo("https://gitlab.com/group/sub/project.git", &excludes));
    }
}
