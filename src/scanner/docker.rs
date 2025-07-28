use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use oci_distribution::client::{linux_amd64_resolver, Client, ClientConfig};
use oci_distribution::{secrets::RegistryAuth, Reference};
use sha2::{Digest, Sha256};
use tracing::debug;
use walkdir::WalkDir;

use crate::decompress::decompress_file;

pub struct Docker;

impl Docker {
    pub fn new() -> Self {
        Docker
    }

    fn try_save_local_image(&self, image: &str, out_dir: &Path, use_progress: bool) -> Result<()> {
        let docker = Command::new("docker")
            .args(["image", "inspect", image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        if !matches!(docker, Ok(s) if s.success()) {
            return Err(anyhow!("image not local"));
        }

        let pb = if use_progress {
            let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len}")
                .expect("progress template");
            let pb = ProgressBar::new(0).with_style(style);
            pb.enable_steady_tick(Duration::from_millis(100));
            pb
        } else {
            ProgressBar::hidden()
        };
        pb.set_message(format!("saving local {image}"));

        std::fs::create_dir_all(out_dir)?;
        let tar_path = out_dir.join("local_image.tar");
        let status = Command::new("docker")
            .args(["image", "save", image, "-o", tar_path.to_str().unwrap()])
            .status()
            .with_context(|| "running docker save")?;
        if !status.success() {
            pb.finish_with_message("docker save failed");
            return Err(anyhow!("failed to save local image"));
        }

        pb.set_message("extracting layers");
        decompress_file(&tar_path, Some(out_dir))?;

        let mut layer_paths = Vec::new();
        for entry in WalkDir::new(out_dir) {
            let entry = entry?;
            if entry.file_name() == "layer.tar" {
                layer_paths.push(entry.path().to_path_buf());
            }
        }

        pb.set_length(layer_paths.len() as u64);
        for p in layer_paths {
            let mut data = Vec::new();
            File::open(&p)?.read_to_end(&mut data)?;
            let digest = format!("{:x}", Sha256::digest(&data));
            let new_path = out_dir.join(format!("layer_{digest}.tar"));
            std::fs::rename(&p, &new_path)?;
            // extract layer contents so inner filenames appear in scan results
            decompress_file(&new_path, Some(out_dir))?;
            std::fs::remove_file(&new_path)?;
            pb.inc(1);
        }

        pb.finish_with_message(format!("saved {image}"));
        Ok(())
    }

    pub async fn save_image_to_dir(
        &self,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        if self.try_save_local_image(image, out_dir, use_progress).is_ok() {
            return Ok(());
        }
        let reference: Reference =
            image.parse().with_context(|| format!("invalid image reference {image}"))?;
        debug!("Pulling {image}");
        let pb = if use_progress {
            let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len}")
                .expect("progress template");
            let pb = ProgressBar::new(0).with_style(style);
            pb.enable_steady_tick(Duration::from_millis(100));
            pb.set_message(format!("pulling {image}"));
            pb
        } else {
            ProgressBar::hidden()
        };
        let client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });
        let mut client = client;
        let auth = RegistryAuth::Anonymous;
        let accepted = vec![
            oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        ];
        let pulled = client.pull(&reference, &auth, accepted).await?;
        pb.set_length(pulled.layers.len() as u64);
        pb.set_message("extracting layers");

        std::fs::create_dir_all(out_dir)?;
        for layer in pulled.layers.into_iter() {
            let ext = match layer.media_type.as_str() {
                oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE
                | oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => "tar.gz",
                oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE
                | oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => "tar",
                _ => "bin",
            };
            let digest = layer.sha256_digest();
            let file_name = format!("layer_{digest}.{ext}");
            let tmp_path = out_dir.join(file_name);
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(&layer.data)?;
            decompress_file(&tmp_path, Some(out_dir))?;
            std::fs::remove_file(&tmp_path)?;
            pb.inc(1);
        }
        pb.finish_with_message(format!("saved {image}"));
        Ok(())
    }
}

pub async fn save_docker_images(
    images: &[String],
    clone_root: &Path,
    use_progress: bool,
) -> Result<Vec<(PathBuf, String)>> {
    let docker = Docker::new();
    let mut dirs = Vec::new();
    for image in images {
        let dir_name = image.replace(['/', ':'], "_");
        let out_dir = clone_root.join(format!("docker_{dir_name}"));
        docker
            .save_image_to_dir(image, &out_dir, use_progress)
            .await
            .with_context(|| format!("saving image {image}"))?;
        dirs.push((out_dir, image.clone()));
    }
    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_struct_new() {
        let _ = Docker::new();
    }
}