use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result};
use bstr::ByteSlice;
use gix::{
    date::{parse as parse_time, Time},
    hashtable::HashMap,
    prelude::FindExt,
    ObjectId, Repository,
};
use smallvec::SmallVec;
use tracing::{debug, debug_span};

use crate::{
    blob::{BlobAppearance, BlobAppearanceSet},
    git_commit_metadata::CommitMetadata,
    git_metadata_graph::{GitMetadataGraph, RepositoryIndex},
};

// Convert "<seconds> <offset>" -- Time; fallback to the Unix-epoch on parse error
#[inline]
fn parse_sig_time<T: AsRef<[u8]>>(raw: T) -> Time {
    match std::str::from_utf8(raw.as_ref()) {
        Ok(s) => parse_time(s, None).unwrap_or_else(|_| Time::new(0, 0)),
        Err(_) => Time::new(0, 0),
    }
}

pub struct GitRepoResult {
    pub path: PathBuf,
    pub repository: Repository,
    pub blobs: Vec<GitBlobMetadata>,
}

#[derive(Clone)]
pub struct GitBlobMetadata {
    pub blob_oid: ObjectId,
    pub first_seen: BlobAppearanceSet,
}

pub struct GitRepoWithMetadataEnumerator<'a> {
    path: &'a Path,
    repo: Repository,
    exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
}

impl<'a> GitRepoWithMetadataEnumerator<'a> {
    pub fn new(
        path: &'a Path,
        repo: Repository,
        exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
    ) -> Self {
        Self { path, repo, exclude_globset }
    }

    pub fn run(self) -> Result<GitRepoResult> {
        let started = Instant::now();
        // let _span = debug_span!("enumerate_git_with_metadata", path = ?self.path).entered();
        let odb = &self.repo.objects;
        let object_index = RepositoryIndex::new(odb)?;

        debug!(
            "Indexed {} objects in {:.6}s; {} blobs; {} commits",
            object_index.num_objects(),
            started.elapsed().as_secs_f64(),
            object_index.num_blobs(),
            object_index.num_commits(),
        );

        let mut metadata_graph = GitMetadataGraph::with_capacity(object_index.num_commits());
        let mut scratch = Vec::with_capacity(4 * 1024 * 1024);
        let mut commit_metadata =
            HashMap::with_capacity_and_hasher(object_index.num_commits(), Default::default());

        // Collect commit metadata and build commit graph
        for commit_oid in object_index.commits() {
            let commit = match odb.find_commit(commit_oid, &mut scratch) {
                Ok(commit) => commit,
                Err(e) => {
                    debug!("Failed to find commit {commit_oid}: {e}");
                    continue;
                }
            };
            let tree_oid = commit.tree();
            let tree_idx = match object_index.get_tree_index(&tree_oid) {
                Some(idx) => idx,
                None => {
                    debug!("Failed to find tree {tree_oid} for commit {commit_oid}");
                    continue;
                }
            };
            let commit_idx = metadata_graph.get_commit_idx(*commit_oid, Some(tree_idx));

            for parent_oid in commit.parents() {
                let parent_idx = metadata_graph.get_commit_idx(parent_oid, None);
                metadata_graph.add_commit_edge(parent_idx, commit_idx);
            }

            let committer = &commit.committer;
            // let author = &commit.author;

            commit_metadata.insert(
                *commit_oid,
                Arc::new(CommitMetadata {
                    commit_id: *commit_oid,
                    committer_name: String::from_utf8_lossy(&committer.name).into_owned(),
                    committer_email: String::from_utf8_lossy(&committer.email).into_owned(),
                    committer_timestamp: parse_sig_time(committer.time),
                }),
            );
        }

        debug!("Built metadata graph in {:.6}s", started.elapsed().as_secs_f64());

        // Compute metadata once, then get all blob IDs
        let meta_result = metadata_graph.get_repo_metadata(&object_index, &self.repo);
        let all_blobs = object_index.into_blobs();

        // Assemble final blob list
        let blobs = match meta_result {
            Err(e) => {
                debug!("Failed to compute reachable blobs; ignoring metadata: {e}");
                all_blobs
                    .into_iter()
                    .map(|blob_oid| GitBlobMetadata { blob_oid, first_seen: Default::default() })
                    .collect()
            }
            Ok(metadata) => {
                // Build map of blob -> appearances
                let mut blob_map: HashMap<_, SmallVec<_>> =
                    all_blobs.into_iter().map(|b| (b, SmallVec::new())).collect();

                for e in metadata {
                    let cm = match commit_metadata.get(&e.commit_oid) {
                        Some(cm) => cm,
                        None => {
                            debug!("Missing commit metadata for {}", e.commit_oid);
                            continue;
                        }
                    };
                    for (blob_oid, path) in e.introduced_blobs {
                        blob_map
                            .entry(blob_oid)
                            .or_default()
                            .push(BlobAppearance { commit_metadata: cm.clone(), path });
                    }
                }

                // Filter out empty or ignored paths
                blob_map
                    .into_iter()
                    .filter_map(|(blob_oid, appearances)| {
                        if appearances.is_empty() {
                            return Some(GitBlobMetadata { blob_oid, first_seen: appearances });
                        }
                        let filtered = appearances
                            .into_iter()
                            .filter(|entry| match entry.path.to_path() {
                                Ok(p) => {
                                    if let Some(gs) = &self.exclude_globset {
                                        let m = gs.is_match(p);
                                        if m {
                                            debug!("Skipping {} due to --exclude", p.display());
                                        }
                                        !m
                                    } else {
                                        true
                                    }
                                }
                                Err(_) => true,
                            })
                            .collect::<SmallVec<_>>();
                        if filtered.is_empty() {
                            None
                        } else {
                            Some(GitBlobMetadata { blob_oid, first_seen: filtered })
                        }
                    })
                    .collect()
            }
        };

        Ok(GitRepoResult { repository: self.repo, path: self.path.to_owned(), blobs })
    }
}

pub struct GitRepoEnumerator<'a> {
    path: &'a Path,
    repo: Repository,
}

impl<'a> GitRepoEnumerator<'a> {
    pub fn new(path: &'a Path, repo: Repository) -> Self {
        Self { path, repo }
    }

    pub fn run(self) -> Result<GitRepoResult> {
        use gix::{object::Kind, odb::store::iter::Ordering, prelude::*};
        let _span = debug_span!("enumerate_git", path = ?self.path).entered();
        let odb = &self.repo.objects;
        let mut blobs = Vec::with_capacity(64 * 1024);

        for oid_result in odb
            .iter()
            .context("Failed to iterate object database")?
            .with_ordering(Ordering::PackAscendingOffsetThenLooseLexicographical)
        {
            let oid = match oid_result {
                Ok(oid) => oid,
                Err(e) => {
                    debug!("Failed to read object id: {e}");
                    continue;
                }
            };
            let hdr = match odb.header(oid) {
                Ok(hdr) => hdr,
                Err(e) => {
                    debug!("Failed to read object header for {oid}: {e}");
                    continue;
                }
            };

            if hdr.kind() == Kind::Blob {
                blobs.push(oid);
            }
        }

        let blobs = blobs
            .into_iter()
            .map(|blob_oid| GitBlobMetadata { blob_oid, first_seen: Default::default() })
            .collect();

        Ok(GitRepoResult { repository: self.repo, path: self.path.to_owned(), blobs })
    }
}
