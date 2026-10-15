use flate2::write::GzEncoder;
use flate2::Compression;
use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Cloudflare R2 / AWS S3 single PUT object size limit (5 GB)
pub const MAX_ARCHIVE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Threshold to warn users of unusually large individual files (50 MB)
pub const LARGE_FILE_WARN_THRESHOLD: u64 = 50 * 1024 * 1024;

pub struct PackageResult {
    pub tar_gz_bytes: Vec<u8>,
    pub checksum_hex: String,
    pub uncompressed_size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct LargeFileInfo {
    pub relative_path: String,
    pub size_bytes: u64,
}

/// Automatically ensures .xhipignore exists in the project root.
/// If .gitignore exists, .xhipignore copies its contents.
/// If no .gitignore exists, an empty .xhipignore is created.
/// Returns Ok((created, description)).
pub fn ensure_xhipignore(root: &Path) -> Result<(bool, &'static str), String> {
    let xhipignore_path = root.join(".xhipignore");
    if !xhipignore_path.exists() {
        let gitignore_path = root.join(".gitignore");
        if gitignore_path.exists() {
            let gitignore_content = fs::read_to_string(&gitignore_path).unwrap_or_default();
            fs::write(&xhipignore_path, gitignore_content)
                .map_err(|e| format!("Failed to create .xhipignore at {}: {}", xhipignore_path.display(), e))?;
            Ok((true, "copied from .gitignore"))
        } else {
            fs::write(&xhipignore_path, "")
                .map_err(|e| format!("Failed to create .xhipignore at {}: {}", xhipignore_path.display(), e))?;
            Ok((true, "created empty"))
        }
    } else {
        Ok((false, "already exists"))
    }
}

/// Force sync/update .xhipignore from .gitignore (or empty if no .gitignore)
pub fn sync_xhipignore(root: &Path) -> Result<&'static str, String> {
    let xhipignore_path = root.join(".xhipignore");
    let gitignore_path = root.join(".gitignore");
    if gitignore_path.exists() {
        let gitignore_content = fs::read_to_string(&gitignore_path).unwrap_or_default();
        fs::write(&xhipignore_path, gitignore_content)
            .map_err(|e| format!("Failed to write .xhipignore at {}: {}", xhipignore_path.display(), e))?;
        Ok("synced from .gitignore")
    } else {
        fs::write(&xhipignore_path, "")
            .map_err(|e| format!("Failed to write .xhipignore at {}: {}", xhipignore_path.display(), e))?;
        Ok("reset to empty")
    }
}

pub fn scan_large_files(root: &Path, files: &[PathBuf]) -> Vec<LargeFileInfo> {
    let mut large_files = Vec::new();
    for file in files {
        if let Ok(meta) = fs::metadata(file) {
            let size = meta.len();
            if size >= LARGE_FILE_WARN_THRESHOLD {
                if let Ok(rel) = file.strip_prefix(root) {
                    large_files.push(LargeFileInfo {
                        relative_path: rel.to_string_lossy().to_string(),
                        size_bytes: size,
                    });
                }
            }
        }
    }
    large_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    large_files
}

pub fn collect_files(
    root: &Path,
    additional_ignores: &[String],
    custom_include_env: bool,
) -> Result<Vec<PathBuf>, String> {
    // Automatically create .xhipignore if not present
    let _ = ensure_xhipignore(root);

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(true)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false);

    // Add .xhipignore custom ignore rules
    let xhipignore_path = root.join(".xhipignore");
    if xhipignore_path.exists() {
        builder.add_custom_ignore_filename(".xhipignore");
    }

    // Additional overrides or custom options
    let mut overrides = ignore::overrides::OverrideBuilder::new(root);
    for pattern in additional_ignores {
        let rule = format!("!{}", pattern);
        let _ = overrides.add(&rule);
    }

    if let Ok(ov) = overrides.build() {
        builder.overrides(ov);
    }

    let mut files = Vec::new();
    for result in builder.build() {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path == root {
                    continue;
                }
                if let Ok(rel) = path.strip_prefix(root) {
                    // Always exclude git internal repository files and directories
                    if rel.components().any(|c| c.as_os_str() == ".git") {
                        continue;
                    }
                    // Exclude VCS & xhip metadata files from shipped archive
                    if let Some(name) = rel.file_name().and_then(|n| n.to_str()) {
                        if name == ".gitignore" || name == ".gitattributes" || name == ".xhipignore" || name == ".xhip" {
                            continue;
                        }
                    }
                    // Exclude .env files unless explicitly included
                    if !custom_include_env {
                        if let Some(name) = rel.file_name().and_then(|n| n.to_str()) {
                            if name == ".env" || name.starts_with(".env.") {
                                continue;
                            }
                        }
                    }
                }
                // Do not pack directory entries directly, only regular files or symlinks
                if path.is_file() || path.is_symlink() {
                    files.push(path.to_path_buf());
                }
            }
            Err(e) => return Err(format!("Error scanning project directory: {}", e)),
        }
    }

    files.sort();
    Ok(files)
}

/// Compute SHA-256 using a streaming 64 KB buffer to avoid reading large files into RAM
pub fn hash_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn create_archive(
    root: &Path,
    files: &[PathBuf],
) -> Result<PackageResult, String> {
    let mut buffer = Vec::new();
    let mut uncompressed_size: u64 = 0;
    {
        let enc = GzEncoder::new(&mut buffer, Compression::best());
        let mut tar_builder = tar::Builder::new(enc);

        let mut included_rel_paths = Vec::new();
        for file in files {
            let rel_path = file
                .strip_prefix(root)
                .map_err(|e| format!("Failed to strip prefix: {}", e))?;

            let rel_str = rel_path.to_string_lossy().to_string();

            // Sanity check against absolute paths or parent directory traversals
            if rel_str.starts_with('/') || rel_str.starts_with('\\') || rel_str.contains("..") {
                return Err(format!("Unsafe file path detected during packaging: {}", rel_str));
            }

            if let Ok(meta) = fs::metadata(file) {
                uncompressed_size += meta.len();
            }

            let mut f = File::open(file)
                .map_err(|e| format!("Failed to open file {}: {}", file.display(), e))?;

            tar_builder
                .append_file(rel_path, &mut f)
                .map_err(|e| format!("Failed to append {} to tar archive: {}", rel_str, e))?;

            included_rel_paths.push(rel_str);
        }

        // Calculate and embed a checksum manifest using streaming hash
        let mut manifest_bytes = Vec::new();
        for path_str in &included_rel_paths {
            let full_p = root.join(path_str);
            if let Ok(hex_hash) = hash_file_sha256(&full_p) {
                let _ = writeln!(manifest_bytes, "{}  {}", hex_hash, path_str);
            }
        }

        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, ".xhip-manifest.sha256", manifest_bytes.as_slice())
            .map_err(|e| format!("Failed to write archive manifest: {}", e))?;

        let enc = tar_builder
            .into_inner()
            .map_err(|e| format!("Failed to finish tar archive: {}", e))?;
        enc.finish()
            .map_err(|e| format!("Failed to finish gzip compression: {}", e))?;
    }

    let archive_len = buffer.len() as u64;
    if archive_len > MAX_ARCHIVE_BYTES {
        return Err(format!(
            "Archive size ({}) exceeds Cloudflare R2 single upload limit of 5 GB.\n\
             Please exclude large files (e.g. build artifacts, databases, media) via .xhipignore.",
            format_bytes(archive_len)
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let checksum_hex = hex::encode(hasher.finalize());

    Ok(PackageResult {
        tar_gz_bytes: buffer,
        checksum_hex,
        uncompressed_size_bytes: uncompressed_size,
    })
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Node representing a file or directory in the tree preview
#[derive(Default)]
pub struct TreeNode {
    pub is_file: bool,
    pub children: BTreeMap<String, TreeNode>,
}

impl TreeNode {
    pub fn insert(&mut self, parts: &[&str]) {
        if parts.is_empty() {
            return;
        }
        let first = parts[0].to_string();
        if parts.len() == 1 {
            let node = self.children.entry(first).or_default();
            node.is_file = true;
        } else {
            let node = self.children.entry(first).or_default();
            node.insert(&parts[1..]);
        }
    }

    pub fn render(&self, prefix: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let total = self.children.len();
        for (i, (name, child)) in self.children.iter().enumerate() {
            let is_last = i + 1 == total;
            let branch = if is_last { "└── " } else { "├── " };
            let next_prefix = if is_last {
                format!("{}    ", prefix)
            } else {
                format!("{}│   ", prefix)
            };

            if child.is_file {
                lines.push(format!("{}{}{}", prefix, branch, name));
            } else {
                lines.push(format!("{}{}{}/", prefix, branch, name));
                lines.extend(child.render(&next_prefix));
            }
        }
        lines
    }
}

pub fn render_file_tree(root_name: &str, rel_paths: &[PathBuf]) -> String {
    let mut root_node = TreeNode::default();
    for path in rel_paths {
        let components: Vec<&str> = path.iter().filter_map(|c| c.to_str()).collect();
        root_node.insert(&components);
    }

    let mut out = format!("{}/\n", root_name);
    for line in root_node.render("") {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

pub fn detect_project_name(dir: &Path) -> String {
    // 0. Check for local .xhip configuration
    let xhip_file = dir.join(".xhip");
    if let Ok(content) = fs::read_to_string(&xhip_file) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return sanitize_project_name(trimmed);
        }
    }

    // 1. Check Cargo.toml
    let cargo_toml = dir.join("Cargo.toml");
    if let Ok(content) = fs::read_to_string(&cargo_toml) {
        if let Ok(val) = toml::from_str::<toml::Value>(&content) {
            if let Some(pkg) = val.get("package") {
                if let Some(name) = pkg.get("name").and_then(|n| n.as_str()) {
                    if !name.is_empty() {
                        return sanitize_project_name(name);
                    }
                }
            }
        }
    }

    // 2. Check package.json
    let package_json = dir.join("package.json");
    if let Ok(content) = fs::read_to_string(&package_json) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
                if !name.is_empty() {
                    return sanitize_project_name(name);
                }
            }
        }
    }

    // 3. Check pyproject.toml
    let pyproject = dir.join("pyproject.toml");
    if let Ok(content) = fs::read_to_string(&pyproject) {
        if let Ok(val) = toml::from_str::<toml::Value>(&content) {
            if let Some(proj) = val.get("project") {
                if let Some(name) = proj.get("name").and_then(|n| n.as_str()) {
                    if !name.is_empty() {
                        return sanitize_project_name(name);
                    }
                }
            }
        }
    }

    // 4. Git repository root name
    if let Ok(repo_root) = find_git_root(dir) {
        if let Some(name) = repo_root.file_name() {
            let s = name.to_string_lossy().to_string();
            if !s.is_empty() {
                return sanitize_project_name(&s);
            }
        }
    }

    // 5. Current directory name
    if let Ok(abs) = dir.canonicalize() {
        if let Some(name) = abs.file_name() {
            let s = name.to_string_lossy().to_string();
            if !s.is_empty() {
                return sanitize_project_name(&s);
            }
        }
    }

    if let Some(name) = dir.file_name() {
        let s = name.to_string_lossy().to_string();
        if !s.is_empty() {
            return sanitize_project_name(&s);
        }
    }

    "app".to_string()
}

pub fn save_project_name_if_needed(dir: &Path, name: &str) {
    let xhip_file = dir.join(".xhip");
    if !xhip_file.exists() {
        let _ = fs::write(&xhip_file, format!("{}\n", name));
    }
}

fn find_git_root(start: &Path) -> Result<PathBuf, ()> {
    let mut cur = start.canonicalize().map_err(|_| ())?;
    loop {
        if cur.join(".git").exists() {
            return Ok(cur);
        }
        if !cur.pop() {
            break;
        }
    }
    Err(())
}

pub fn sanitize_project_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    clean.trim_matches('-').to_lowercase()
}
