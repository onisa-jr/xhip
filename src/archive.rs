use flate2::write::GzEncoder;
use flate2::Compression;
use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

// Default template content for auto-generated .xhipignore
pub const DEFAULT_XHIPIGNORE_TEMPLATE: &str = r#"# .xhipignore - Patterns to exclude when packaging with Xhip
# Syntax is the same as .gitignore:
#   - '#' starts a comment
#   - Prepend '!' to re-include a file or pattern
#   - Trailing '/' matches directories only

# Sensitive files and secrets (NEVER upload to untrusted targets)
.env
.env.*
*.pem
*.key
*.id_rsa
*.id_ed25519
id_rsa
id_ed25519
*.pfx
*.p12
*.pkcs12

# Version control systems
.git/
.gitignore
.gitattributes
.hg/
.svn/

# Dependencies and virtual environments
node_modules/
vendor/
.venv/
venv/
env/
__pycache__/
*.pyc
.pytest_cache/
.mypy_cache/
.tox/

# Build outputs and compilation artifacts
target/
dist/
build/
.next/
.nuxt/
.turbo/
.cache/
*.log
.DS_Store
Thumbs.db
"#;

pub struct PackageResult {
    pub tar_gz_bytes: Vec<u8>,
    pub checksum_hex: String,
}

/// Automatically ensures .xhipignore exists in the project root.
/// Returns true if a new file was created.
pub fn ensure_xhipignore(root: &Path) -> Result<bool, String> {
    let xhipignore_path = root.join(".xhipignore");
    if !xhipignore_path.exists() {
        fs::write(&xhipignore_path, DEFAULT_XHIPIGNORE_TEMPLATE)
            .map_err(|e| format!("Failed to create .xhipignore at {}: {}", xhipignore_path.display(), e))?;
        Ok(true)
    } else {
        Ok(false)
    }
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

    // If custom_include_env is requested, add an override rule to include .env
    if custom_include_env {
        let _ = overrides.add("!.env");
        let _ = overrides.add("!.env.*");
    }

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

pub fn create_archive(
    root: &Path,
    files: &[PathBuf],
) -> Result<PackageResult, String> {
    let mut buffer = Vec::new();
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

            let mut f = File::open(file)
                .map_err(|e| format!("Failed to open file {}: {}", file.display(), e))?;

            tar_builder
                .append_file(rel_path, &mut f)
                .map_err(|e| format!("Failed to append {} to tar archive: {}", rel_str, e))?;

            included_rel_paths.push(rel_str);
        }

        // Calculate and embed a checksum manifest
        let mut manifest_bytes = Vec::new();
        for path_str in &included_rel_paths {
            let full_p = root.join(path_str);
            if let Ok(content) = fs::read(&full_p) {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                let hex_hash = hex::encode(hasher.finalize());
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

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let checksum_hex = hex::encode(hasher.finalize());

    Ok(PackageResult {
        tar_gz_bytes: buffer,
        checksum_hex,
    })
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
    // 1. If in a git repository, try to read git root name
    if let Ok(repo_root) = find_git_root(dir) {
        if let Some(name) = repo_root.file_name() {
            let s = name.to_string_lossy().to_string();
            if !s.is_empty() {
                return sanitize_project_name(&s);
            }
        }
    }

    // 2. Fall back to current directory name
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
