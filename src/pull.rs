use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

#[derive(Debug)]
pub struct SafeExtractResult {
    pub extracted_files_count: usize,
    pub preserved_items: Vec<String>,
}

/// Download an archive from a URL with integrity checking
pub fn download_archive(url: &str) -> Result<Vec<u8>, String> {
    let clean_url = url.trim().trim_matches('\'').trim_matches('"');
    let mut response = ureq::get(clean_url)
        .call()
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("missing scheme") || err_str.contains("relative URL") {
                format!(
                    "Invalid URL format. Please make sure the URL begins with https:// and is enclosed in quotes: \"{}\"",
                    clean_url
                )
            } else if err_str.contains("400") || err_str.contains("403") {
                format!(
                    "Download request rejected (HTTP {}). The shipping URL may have expired, or was corrupted (e.g. unquoted '&' in bash).",
                    err_str
                )
            } else {
                format!("Failed to download archive: {}", err_str)
            }
        })?;

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        if status == 403 || status == 400 {
            return Err(format!(
                "Download failed (HTTP status {}). The presigned URL has expired or is invalid.",
                status
            ));
        }
        return Err(format!("Download failed with HTTP status {}", status));
    }

    let data = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| format!("Failed reading download body: {}", e))?;

    Ok(data)
}

/// Verify SHA-256 of the archive bytes against an expected hex checksum
pub fn verify_archive_checksum(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual_hex = hex::encode(hasher.finalize());

    if !actual_hex.eq_ignore_ascii_case(expected_hex.trim()) {
        return Err(format!(
            "Checksum mismatch! Expected: {}, Computed: {}",
            expected_hex.trim(),
            actual_hex
        ));
    }

    Ok(())
}

/// Safely unpack archive, checking each path against traversal and verifying internal manifest
pub fn safe_unpack_and_install(
    archive_bytes: &[u8],
    destination_dir: &Path,
    expected_archive_checksum: Option<&str>,
) -> Result<SafeExtractResult, String> {
    // 1. Verify archive checksum if supplied
    if let Some(exp) = expected_archive_checksum {
        verify_archive_checksum(archive_bytes, exp)?;
    }

    // 2. Prepare staging directory
    let parent_dir = destination_dir
        .parent()
        .ok_or_else(|| "Destination has no parent directory".to_string())?;

    fs::create_dir_all(parent_dir)
        .map_err(|e| format!("Failed to create parent directory {}: {}", parent_dir.display(), e))?;

    let staging_dir = tempfile_staging_dir(parent_dir, destination_dir)?;
    if staging_dir.exists() {
        let _ = fs::remove_dir_all(&staging_dir);
    }
    fs::create_dir_all(&staging_dir)
        .map_err(|e| format!("Failed to create staging dir {}: {}", staging_dir.display(), e))?;

    // 3. Extract and check paths
    let gz = GzDecoder::new(archive_bytes);
    let mut tar = Archive::new(gz);

    let mut manifest_content: Option<String> = None;
    let mut extracted_count = 0;

    for entry_res in tar.entries().map_err(|e| format!("Failed reading tar entries: {}", e))? {
        let mut entry = entry_res.map_err(|e| format!("Invalid tar entry: {}", e))?;
        let entry_path = entry.path().map_err(|e| format!("Invalid path in tar: {}", e))?.into_owned();

        // Path traversal validation:
        // Must be relative, cannot contain '..', cannot start with '/'
        let path_str = entry_path.to_string_lossy();
        if entry_path.is_absolute() || path_str.starts_with('/') || path_str.starts_with('\\') {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(format!("SECURITY ERROR: Absolute path in archive: {}", path_str));
        }

        for component in entry_path.components() {
            match component {
                std::path::Component::ParentDir => {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(format!("SECURITY ERROR: Path traversal ('..') detected in archive: {}", path_str));
                }
                std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(format!("SECURITY ERROR: Root or prefix path detected in archive: {}", path_str));
                }
                _ => {}
            }
        }

        // Special handling for manifest
        if path_str == ".xhip-manifest.sha256" {
            let mut s = String::new();
            entry.read_to_string(&mut s).map_err(|e| format!("Failed to read manifest: {}", e))?;
            manifest_content = Some(s);
            continue;
        }

        // Safe extraction target
        let target_path = staging_dir.join(&entry_path);
        if let Some(p) = target_path.parent() {
            fs::create_dir_all(p)
                .map_err(|e| format!("Failed to create directory {}: {}", p.display(), e))?;
        }

        entry.unpack(&target_path)
            .map_err(|e| format!("Failed to extract file {}: {}", target_path.display(), e))?;

        extracted_count += 1;
    }

    // 4. Verify manifest if present
    if let Some(manifest) = manifest_content {
        let manifest_map = parse_manifest(&manifest);
        for (rel_path, expected_hash) in manifest_map {
            let full_p = staging_dir.join(&rel_path);
            if !full_p.exists() {
                let _ = fs::remove_dir_all(&staging_dir);
                return Err(format!("Manifest check error: file {} listed in manifest not found", rel_path));
            }
            if full_p.is_file() {
                let bytes = fs::read(&full_p)
                    .map_err(|e| format!("Failed to read file {} for checksum: {}", full_p.display(), e))?;
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let actual_hash = hex::encode(hasher.finalize());
                if !actual_hash.eq_ignore_ascii_case(&expected_hash) {
                    let _ = fs::remove_dir_all(&staging_dir);
                    return Err(format!(
                        "File integrity failure on {}: expected checksum {}, got {}",
                        rel_path, expected_hash, actual_hash
                    ));
                }
            }
        }
    }

    // 5. Preserve persistent runtime data (.env, uploads, sqlite db, etc.) if destination already exists
    let mut preserved_items = Vec::new();
    if destination_dir.exists() {
        preserved_items = preserve_runtime_data(destination_dir, &staging_dir)?;
    }

    // 6. Safe atomic or near-atomic rotation
    // Backup existing destination if it exists
    let backup_dir = if destination_dir.exists() {
        let b = destination_dir.with_extension(format!("xhip-backup-{}", chrono::Utc::now().timestamp()));
        fs::rename(destination_dir, &b)
            .map_err(|e| format!("Failed to rename live directory to backup {}: {}", b.display(), e))?;
        Some(b)
    } else {
        None
    };

    // Move staging into destination
    if let Err(e) = fs::rename(&staging_dir, destination_dir) {
        // Rollback
        if let Some(ref b) = backup_dir {
            let _ = fs::rename(b, destination_dir);
        }
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(format!("Failed to activate staged release to {}: {}", destination_dir.display(), e));
    }

    // Clean up backup if successful
    if let Some(b) = backup_dir {
        let _ = fs::remove_dir_all(b);
    }

    Ok(SafeExtractResult {
        extracted_files_count: extracted_count,
        preserved_items,
    })
}

fn tempfile_staging_dir(parent: &Path, dest: &Path) -> Result<PathBuf, String> {
    let name = dest.file_name().unwrap_or_default().to_string_lossy();
    let staging_name = format!(".{}-staging-{}", name, chrono::Utc::now().timestamp_nanos_opt().unwrap_or(12345));
    Ok(parent.join(staging_name))
}

fn parse_manifest(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let hash = parts[0].to_string();
            let path = parts[1..].join(" ");
            map.insert(path, hash);
        }
    }
    map
}

/// Preserve runtime files like .env, databases, uploads from destination into staging before replacing
fn preserve_runtime_data(dest: &Path, staging: &Path) -> Result<Vec<String>, String> {
    let mut preserved = Vec::new();
    let preserve_patterns = [
        ".env",
        ".env.local",
        ".env.production",
        "storage",
        "uploads",
        "data",
        "db.sqlite",
        "db.sqlite3",
        "production.sqlite3",
    ];

    for pattern in &preserve_patterns {
        let src_path = dest.join(pattern);
        let dst_path = staging.join(pattern);

        if src_path.exists() && !dst_path.exists() {
            if src_path.is_dir() {
                copy_dir_recursive(&src_path, &dst_path)?;
                preserved.push(format!("{}/ (directory)", pattern));
            } else if src_path.is_file() {
                if let Some(parent) = dst_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create parent dir for {}: {}", dst_path.display(), e))?;
                }
                fs::copy(&src_path, &dst_path)
                    .map_err(|e| format!("Failed to preserve {}: {}", src_path.display(), e))?;
                preserved.push(pattern.to_string());
            }
        }
    }

    Ok(preserved)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst)
        .map_err(|e| format!("Failed to create dir {}: {}", dst.display(), e))?;
    for entry in fs::read_dir(src).map_err(|e| format!("Failed to read dir {}: {}", src.display(), e))? {
        let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
        let entry_path = entry.path();
        let target_path = dst.join(entry.file_name());
        if entry_path.is_dir() {
            copy_dir_recursive(&entry_path, &target_path)?;
        } else {
            fs::copy(&entry_path, &target_path)
                .map_err(|e| format!("Failed to copy file: {}", e))?;
        }
    }
    Ok(())
}
